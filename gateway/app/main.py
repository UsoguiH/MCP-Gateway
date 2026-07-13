"""FastAPI application — HTTP surface for the gateway and UI (spec §11 Phase 3-4)."""
import base64
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse, Response)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import (apikeys, audit, auth, devclient, insights, mcp_server, notifications,
               oauth, selfinfo, settings as gwsettings)
from .auth import USERS, verify
from .config import CONFIG, POLICY, ROOT
from .controls import RateLimiter, kill_switch
from .gateway import Gateway

gw = Gateway()

_ALLOWED_ORIGINS = CONFIG["auth"].get("allowed_origins", ["*"])
_DEV_LOGIN = CONFIG["auth"].get("dev_login_enabled", False)
_MAX_BODY = int(CONFIG["auth"].get("max_request_bytes", 65536))
# Trusted-proxy enforcement: when enabled, every request MUST arrive through the
# mTLS-terminating sidecar, proven by a shared secret header the proxy injects and
# that the network prevents clients from reaching the gateway to forge. This closes
# the "reach the gateway directly, bypass mTLS" hole. The proxy also strips any
# client-supplied X-Client-Cert-Thumbprint and re-injects the TLS-verified one.
from .config import secret as _secret                                    # noqa: E402
_PROXY_CFG = CONFIG["auth"].get("trusted_proxy", {}) or {}
# Enable via config OR the MCP_TRUSTED_PROXY env, so one config.yaml serves both
# dev (proxy off, direct loopback) and prod (proxy on behind the mTLS terminator).
_PROXY_REQUIRED = bool(_PROXY_CFG.get("enabled", False)) or \
    os.environ.get("MCP_TRUSTED_PROXY", "").lower() in ("1", "true", "yes")
_PROXY_SECRET = _secret("MCP_PROXY_SHARED_SECRET", _PROXY_CFG.get("shared_secret") or "")
_PROXY_HEADER = _PROXY_CFG.get("header", "x-proxy-auth").lower()
# Per-IP throttle on auth endpoints (finding M1/M5: raises the cost of lockout-DoS
# and online guessing so a single source can't cheaply spam login attempts).
_login_limiter = RateLimiter(int(CONFIG["auth"].get("login_rate_per_minute", 20)))


async def _approval_sweeper(interval_s: int = 300):
    """Expire overdue approvals + prune resolved ones on a timer, so a stale
    destructive action is contained even when no approver ever opens the queue."""
    import asyncio
    while True:
        try:
            await asyncio.sleep(interval_s)
            _audit_expired_approvals()          # expire + audit; _save() also prunes
        except asyncio.CancelledError:
            break
        except Exception:
            pass                                # a sweep must never crash the gateway


async def _state_sweeper(interval_s: int = 30):
    """Phase-3 housekeeping (DB mode only): converge this instance's MCP servers
    with the shared inventory (a server added on another instance starts here
    within one sweep) and reap idle shared sessions."""
    import asyncio
    from . import statestore
    tick = 0
    while True:
        try:
            await asyncio.sleep(interval_s)
            if not statestore.enabled():
                continue
            changed = await gw.mcp.sync_with_inventory()
            if changed["started"] or changed["removed"]:
                gw.registry.reconcile(gw.mcp.all_tools())
                audit.record("server_inventory_synced",
                             instance=statestore.instance_id(), **changed)
            tick += 1
            if tick % 10 == 0:                  # every ~5 min
                reaped = mcp_server.reap_idle_sessions()
                if reaped:
                    audit.record("mcp_sessions_reaped", count=reaped,
                                 instance=statestore.instance_id())
        except asyncio.CancelledError:
            break
        except Exception:
            pass                                # a sweep must never crash the gateway


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    import anyio.to_thread
    # The control pipeline is synchronous and DB-bound, so it runs in worker threads
    # (Gateway._execute_call) to keep the event loop free. AnyIO's default limiter is 40
    # threads for the WHOLE process — with the pipeline threaded, that ceiling becomes the
    # next queue behind the connection pool. Size it with the pool, not against it.
    limiter = anyio.to_thread.current_default_thread_limiter()
    limiter.total_tokens = int(os.environ.get("MCP_WORKER_THREADS", "64"))

    await gw.startup()
    # Verify the ENTIRE audit chain once, at boot: it seeds the incremental verifier's
    # state and is the pass that would catch an edit to a historical record (something an
    # incremental check, by construction, cannot). Every later check is incremental and
    # effectively free — see audit.chain_status.
    chain_ok, chain_msg = audit.chain_status(full=True)
    if not chain_ok:
        print(f"AUDIT CHAIN INTEGRITY FAILURE: {chain_msg}", file=os.sys.stderr)
    audit.record("gateway_startup", servers=list(gw.mcp.servers.keys()),
                 chain_ok=chain_ok, chain_status=chain_msg)
    sweeper = asyncio.create_task(_approval_sweeper())
    state_sweeper = asyncio.create_task(_state_sweeper())
    yield
    sweeper.cancel()
    state_sweeper.cancel()
    await gw.shutdown()


app = FastAPI(title="Secure MCP Gateway", version="1.0", lifespan=lifespan)


# ---------- edge guard: body-size cap + origin check + login rate-limit ----------
@app.middleware("http")
async def edge_guard(request: Request, call_next):
    # Trusted-proxy gate: reject anything that didn't come through the mTLS
    # terminator (constant-time compare of the injected shared secret). UI static
    # assets and health are exempt so a liveness probe still works.
    if _PROXY_REQUIRED and request.url.path.startswith(("/api/", "/mcp")) \
            and request.url.path != "/api/health":
        import hmac as _hmac
        got = request.headers.get(_PROXY_HEADER, "")
        if not _PROXY_SECRET or not _hmac.compare_digest(got, _PROXY_SECRET):
            return JSONResponse({"detail": "direct access denied — requests must "
                                 "traverse the mTLS gateway proxy"}, status_code=403)
    # M3: reject oversized request bodies before they are parsed
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_BODY:
        return JSONResponse({"detail": "request too large"}, status_code=413)
    # L1: Origin validation (MCP spec MUST — DNS-rebinding defense). Scoped to the
    # API/MCP surface: the OAuth browser flow (/oauth/*), the connect page and the
    # public metadata are browser-facing and legitimately carry varied Origins; they
    # are protected instead by PKCE + the login itself, so exempt them here.
    _origin_exempt = request.url.path.startswith(("/oauth/", "/connect", "/.well-known/"))
    origin = request.headers.get("origin")
    if origin and not _origin_exempt and "*" not in _ALLOWED_ORIGINS \
            and origin not in _ALLOWED_ORIGINS:
        return JSONResponse({"detail": "invalid origin"}, status_code=403)
    # M1/M5: per-IP rate limit on authentication endpoints
    if request.url.path.startswith(("/api/login", "/api/dev/login")):
        ip = request.client.host if request.client else "unknown"
        if not _login_limiter.allow(ip):
            return JSONResponse({"detail": "too many login attempts"}, status_code=429)
    response = await call_next(request)
    # Security headers (defense-in-depth): clickjacking, MIME-sniff, referrer leak,
    # feature access, cross-origin isolation, transport security, and a strict CSP
    # that blocks any external script/style/connect/frame.
    response.headers["MCP-Protocol-Version"] = "2025-11-25"   # A10: advertise spec revision
    # Which instance served this request (Phase 3). Behind a load balancer, "the
    # gateway was slow / returned that" is unanswerable without it — an operator
    # correlating an audit record with a node's logs needs the node's name.
    from . import statestore as _ss
    response.headers["X-Gateway-Instance"] = _ss.instance_id()
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'; object-src 'none'")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.url.path.startswith(("/api/", "/mcp")):
        response.headers["Cache-Control"] = "no-store"      # never cache sensitive API data
    return response


# ---------- auth dependency ----------
# The token is bound (RFC 8705 cnf.x5t#S256) to the client certificate. The
# verified thumbprint arrives in X-Client-Cert-Thumbprint.
# PRODUCTION SWAP POINT: that header is set by the mTLS-terminating sidecar from
# the TLS-verified peer cert, and any client-supplied copy is stripped at the edge.
def current_user(authorization: str = Header(default=""),
                 x_client_cert_thumbprint: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    claims = verify(authorization[7:], x_client_cert_thumbprint or None)
    if not claims:
        raise HTTPException(401, "invalid token, expired, revoked, or cert-binding mismatch")
    return claims


def require_admin(claims: dict = Depends(current_user)) -> dict:
    if not POLICY["roles"].get(claims["role"], {}).get("admin"):
        raise HTTPException(403, "admin role required")
    return claims


def fresh_password(claims: dict = Depends(current_user)) -> dict:
    """Gate: block privileged/tool actions while the operator owes a password change
    (forced first-login rotation or expiry). They can still hit /api/auth/password,
    /api/me, and logout to resolve it."""
    if auth.password_change_required(claims["sub"]):
        raise HTTPException(403, "password change required — rotate via /api/auth/password")
    return claims


def _base_url(request: Request) -> str:
    """External base URL as the client sees it (honors the mTLS terminator's
    X-Forwarded-* so OAuth metadata advertises https://gateway:8443, not loopback)."""
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}"


def mcp_principal(request: Request, authorization: str = Header(default=""),
                  x_client_cert_thumbprint: str = Header(default="")) -> dict:
    """Auth for /mcp — accepts EITHER a cert-bound console session token OR an OAuth
    2.1 access token (local-AI clients). On failure, advertise the OAuth resource
    metadata per the MCP authorization spec so a compliant client self-onboards."""
    challenge = (f'Bearer resource_metadata='
                 f'"{_base_url(request)}/.well-known/oauth-protected-resource"')
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "authorization required",
                            headers={"WWW-Authenticate": challenge})
    token = authorization[7:]
    if token.startswith("mcpk_"):
        claims = apikeys.verify(token)                           # scoped API key
    else:
        claims = verify(token, x_client_cert_thumbprint or None)  # cert-bound session
        if not claims:
            claims = auth.verify_oauth_access(token)             # OAuth bearer
    if not claims:
        raise HTTPException(401, "invalid, expired, or revoked token",
                            headers={"WWW-Authenticate": challenge})
    if auth.password_change_required(claims["sub"]):
        raise HTTPException(403, "password change required — rotate via /api/auth/password")
    return claims


def claims_for(username: str) -> dict:
    u = USERS[username]
    return {"sub": username, "name": u["name"], "role": u["role"], "clearance": u["clearance"]}


# ---------- models ----------
class ChallengeReq(BaseModel):
    cert_pem: str


class LoginReq(BaseModel):
    cert_pem: str
    nonce: str
    signature: str          # base64-encoded signature over the nonce


class DevLoginReq(BaseModel):
    username: str
    pin: str
    otp: str = ""            # third factor: TOTP authenticator code (MFA)


class AuthLoginReq(BaseModel):
    username: str
    password: str            # layer 1 — verified before MFA is ever offered


class MfaReq(BaseModel):
    mfa_ticket: str          # proof that layer 1 (password) passed
    otp: str                 # layer 2 — TOTP authenticator code


class KillReq(BaseModel):
    scope: str
    reason: str = ""              # required on engage — containment must say why
    ttl_minutes: int | None = None   # auto-release, so a kill can't be forgotten


class TierReq(BaseModel):
    tier: int                # 0 read | 1 reversible write | 2 human | 3 two-person


class ReasonReq(BaseModel):
    reason: str = ""


class SettingsReq(BaseModel):
    section: str
    patch: dict


class MaintenanceReq(BaseModel):
    enabled: bool
    message: str = ""


class EditServerReq(BaseModel):
    command: str | None = None
    args: list[str] = []
    transport: str = "stdio"
    url: str | None = None
    env: dict[str, str] = {}


class ChangePwReq(BaseModel):
    old_password: str
    new_password: str


class RevokeReq(BaseModel):
    sub: str


class ConnectTokenReq(BaseModel):
    # optional label so a user can name the client they're pasting the token into
    label: str = ""


class ApiKeyReq(BaseModel):
    name: str
    sub: str                 # operator the key acts as (capped by their role)
    scope: str = "read"      # read | standard | full (extra tier cap on top of role)
    ttl_days: int | None = None


class OperatorCreateReq(BaseModel):
    sub: str
    name: str = ""
    role: str = "employee"
    clearance: str = "restricted"


class OperatorRoleReq(BaseModel):
    role: str | None = None
    clearance: str | None = None
    name: str | None = None


class ServerAddReq(BaseModel):
    name: str
    command: str = ""
    args: list[str] = []
    transport: str = "stdio"     # stdio | http
    url: str = ""
    env: dict[str, str] = {}


class NotifReadReq(BaseModel):
    ids: list[str] = []
    all: bool = False


def _user_view(claims: dict) -> dict:
    return {"sub": claims["sub"], "name": claims["name"],
            "role": claims["role"], "clearance": claims["clearance"],
            "amr": claims.get("amr", []),
            "password_change_required": bool(claims.get("pwd_change_required"))
            or auth.password_change_required(claims["sub"])}


# ---------- auth: TPM-bound certificate login ----------
@app.post("/api/login/challenge")
def login_challenge(req: ChallengeReq):
    """Step 1-2: present the client cert, receive a signing challenge."""
    ch = auth.make_challenge(req.cert_pem)
    if not ch:
        raise HTTPException(401, "unknown, untrusted, expired, or revoked certificate")
    return ch


@app.post("/api/login")
def login(req: LoginReq):
    """Step 3-4: prove possession of the TPM key; receive a bound session token."""
    try:
        sig = base64.b64decode(req.signature)
    except Exception:
        raise HTTPException(400, "signature must be base64")
    token = auth.authenticate(req.cert_pem, req.nonce, sig)
    if not token:
        audit.record("login_failed")
        raise HTTPException(401, "authentication failed (bad proof-of-possession or challenge)")
    claims = verify(token, auth.pki.cert_thumbprint(auth.pki.load_cert_from_pem(req.cert_pem)))
    audit.record("login", user=claims["sub"], role=claims["role"])
    return {"token": token, "thumbprint": claims["cnf"]["x5t#S256"], "user": _user_view(claims)}


@app.post("/api/auth/login")
def auth_login(req: AuthLoginReq):
    """Layer 1 — username + strong password (salted PBKDF2, constant-time, anti-
    hammering). A wrong username/password is rejected HERE and never advances to MFA.
    On success, if MFA is required, returns a short-lived mfa_ticket for layer 2
    (no session token yet); otherwise mints the session directly."""
    if auth.locked(req.username):
        audit.record("login_locked_out", user=req.username)
        raise HTTPException(429, "Too many failed attempts. This account is temporarily locked — try again shortly.")
    if not auth.verify_password_layer(req.username, req.password):
        audit.record("login_failed", user=req.username, stage="password",
                     locked=auth.locked(req.username))
        raise HTTPException(401, "Incorrect username or password.")
    # password ok
    if CONFIG["auth"].get("require_mfa", False):
        audit.record("login_password_ok", user=req.username)
        return {"mfa_required": True, "mfa_ticket": auth.issue_mfa_ticket(req.username),
                "username": req.username}
    got = auth.finish_password_only(req.username)
    token, binding = got
    claims = verify(token, binding)
    audit.record("login", user=claims["sub"], role=claims["role"], amr=claims["amr"], acr=claims["acr"])
    return {"token": token, "thumbprint": binding, "user": _user_view(claims)}


@app.post("/api/auth/mfa")
def auth_mfa(req: MfaReq):
    """Layer 2 — TOTP. Requires a valid mfa_ticket from layer 1 (so the password step
    cannot be skipped). A wrong code feeds the same anti-hammering lockout."""
    username = auth.verify_mfa_ticket(req.mfa_ticket)
    if not username:
        raise HTTPException(401, "Your sign-in step expired. Enter your username and password again.")
    if auth.locked(username):
        audit.record("login_locked_out", user=username)
        raise HTTPException(429, "Too many failed attempts. This account is temporarily locked — try again shortly.")
    got = auth.complete_mfa(username, req.otp)
    if not got:
        audit.record("login_mfa_failed", user=username, locked=auth.locked(username))
        raise HTTPException(401, "Incorrect authenticator code.")
    token, binding = got
    claims = verify(token, binding)
    audit.record("login", user=claims["sub"], role=claims["role"], amr=claims["amr"], acr=claims["acr"],
                 pwd_change_required=bool(claims.get("pwd_change_required")))
    return {"token": token, "thumbprint": binding, "user": _user_view(claims)}


@app.post("/api/auth/password")
def change_password(req: ChangePwReq, claims: dict = Depends(current_user)):
    """Self-service password change (also how a forced first-login/expiry rotation is
    resolved). Verifies the current password, enforces strength, clears must-change."""
    ok, msg = auth.change_password(claims["sub"], req.old_password, req.new_password)
    if not ok:
        audit.record("password_change_failed", user=claims["sub"])
        raise HTTPException(400, msg)
    audit.record("password_changed", user=claims["sub"])
    return {"status": "password changed", "password_status": auth.password_status(claims["sub"])}


@app.get("/api/auth/password/status")
def password_status(claims: dict = Depends(current_user)):
    return auth.password_status(claims["sub"])


@app.post("/api/dev/quicklogin")
def dev_quicklogin():
    """DEV ONLY: open the dashboard immediately as admin, skipping password + MFA.
    Gated by auth.dev_quick_login; 404 when off (production). The tripwire flags it."""
    got = auth.dev_quick_session("admin")
    if not got:
        raise HTTPException(404, "not found")
    token, binding = got
    claims = verify(token, binding)
    audit.record("dev_quicklogin", user=claims["sub"], role=claims["role"])
    return {"token": token, "thumbprint": binding, "user": _user_view(claims)}


@app.post("/api/dev/login")
def dev_login(req: DevLoginReq):
    """DEV ONLY convenience: run the full multi-factor challenge/response for a demo
    user. THREE factors: cert possession + PIN (unlocks the key) + a TOTP
    authenticator code (MFA). Disabled in production (dev_login_enabled)."""
    if not _DEV_LOGIN:
        raise HTTPException(404, "not found")
    if req.username not in USERS:
        raise HTTPException(401, "authentication failed")
    if auth.locked(req.username):
        audit.record("login_locked_out", user=req.username)
        raise HTTPException(429, "too many failed attempts; identity temporarily locked")
    # Factor 3 (MFA): verify the TOTP authenticator code before anything else.
    if not auth.verify_totp(req.username, req.otp):
        auth.note_failure(req.username)
        audit.record("login_mfa_failed", user=req.username, locked=auth.locked(req.username))
        raise HTTPException(401, "invalid or missing authenticator code (MFA)")
    got = devclient.obtain_token(req.username, req.pin, amr_extra=["otp"])
    if not got:
        auth.note_failure(req.username)          # wrong PIN fails locally -> count it here
        audit.record("login_failed", user=req.username, locked=auth.locked(req.username))
        raise HTTPException(401, "authentication failed (wrong PIN or certificate)")
    token, thumb = got
    claims = verify(token, thumb)
    audit.record("login", user=claims["sub"], role=claims["role"],
                 amr=claims["amr"], acr=claims["acr"], dev=True)
    return {"token": token, "thumbprint": thumb, "user": _user_view(claims)}


@app.get("/api/dev/otp")
def dev_otp(username: str):
    """DEV ONLY soft-token: the current TOTP code for a demo operator, so the login
    screen can show a working authenticator. In production dev_login is disabled and
    operators use their own enrolled authenticator app — this endpoint 404s."""
    if not _DEV_LOGIN:
        raise HTTPException(404, "not found")
    if username not in USERS:
        raise HTTPException(404, "unknown operator")
    return {"code": auth.totp_code(username), "seconds_remaining": auth.totp_remaining()}


@app.get("/api/auth/info")
def auth_info():
    """Public: which sign-in methods this deployment offers (drives the login screen).
    Reveals no secrets — just the configured modes so the UI renders the right buttons."""
    a = CONFIG.get("auth", {})
    oidc = a.get("oidc", {}) or {}
    return {
        "org": "Government Entity",
        "mode": a.get("mode", "builtin"),
        "password_login": True,                                 # username + strong password
        "sso_enabled": a.get("mode") == "oidc" and bool(oidc.get("issuer")),
        "certificate_login": False,                             # cert/mTLS path (not surfaced in this build)
        "mfa_required": bool(a.get("require_mfa", False)),      # drives the authenticator step
        "dev_login": _DEV_LOGIN,                                # developer path (off in production)
        "dev_quick_login": bool(a.get("dev_quick_login", False)),  # DEV "Enter now" bypass button
        "assurance": a.get("aal", "aal2"),
    }


@app.get("/api/dev/userlist")
def dev_userlist():
    """DEV ONLY: demo usernames for the login screen. Does NOT return PINs
    (finding C1) — PINs are documented, never served by an API."""
    if not _DEV_LOGIN:
        raise HTTPException(404, "not found")
    return {"users": [{"username": u, "name": USERS[u]["name"], "role": USERS[u]["role"],
                       "clearance": USERS[u]["clearance"]} for u in USERS]}


@app.get("/api/me")
def me(claims: dict = Depends(current_user)):
    now = int(time.time())
    return {"sub": claims["sub"], "name": claims["name"],
            "role": claims["role"], "clearance": claims["clearance"],
            "expires_in": max(0, int(claims["exp"]) - now),
            "session_age": now - int(claims.get("auth_time") or claims["iat"]),
            "absolute_max": auth.session_absolute_max(),
            "warn_seconds": gwsettings.get("session", "warn_seconds")}


@app.post("/api/auth/refresh")
def refresh_session(claims: dict = Depends(current_user)):
    """Renew a live console session (A12).

    The console held one fixed-lifetime token and simply died when it expired — mid-approval,
    with no warning and no way to stay signed in. The UI now renews silently while the
    operator is working (so the TTL behaves as an idle timeout) and warns before expiry when
    they are not. The absolute cap still forces a real re-authentication.
    """
    try:
        token, binding, expires_in = auth.refresh_session(claims)
    except auth.SessionExpired as e:
        raise HTTPException(401, str(e))
    audit.record("session_refreshed", user=claims["sub"],
                 session_age=int(time.time()) - int(claims.get("auth_time") or claims["iat"]))
    return {"token": token, "thumbprint": binding, "expires_in": expires_in,
            "warn_seconds": gwsettings.get("session", "warn_seconds")}


# ---------- tools (REST view for the ops console) ----------
@app.get("/api/tools")
def tools(claims: dict = Depends(current_user)):
    return {"tools": gw.visible_tools(claims)}


# ---------- inbound MCP endpoint (Streamable HTTP) ----------
# This replaces /api/chat: the gateway runs no model. Each colleague's own local
# LLM connects here as an MCP client and drives tool calls through the pipeline.
# Auth is the same TPM-bound, cert-constrained token used everywhere else.
@app.post("/mcp")
async def mcp_post(request: Request, claims: dict = Depends(mcp_principal),
                   mcp_session_id: str = Header(default="")):
    try:
        message = await request.json()
    except Exception:
        return JSONResponse(mcp_server.parse_error(), status_code=200)
    if isinstance(message, list):
        return JSONResponse(mcp_server.batch_unsupported(), status_code=200)
    status, body, extra = await mcp_server.dispatch(gw, claims, message, mcp_session_id or None)
    if body is None:                                   # 202 ack to a notification
        return Response(status_code=status, headers=extra)
    return JSONResponse(body, status_code=status, headers=extra)


@app.get("/mcp")
def mcp_get():
    # We do not offer a server-initiated SSE stream, so GET is not allowed (spec).
    return JSONResponse({"detail": "method not allowed"}, status_code=405)


@app.delete("/mcp")
def mcp_delete(claims: dict = Depends(current_user), mcp_session_id: str = Header(default="")):
    if mcp_session_id:
        mcp_server.end_session(mcp_session_id)
    return Response(status_code=204)


# ---------- OAuth 2.1 authorization server (MCP client onboarding) ----------
# Fronts the existing password+MFA login with the standard auth-code + PKCE flow,
# so a spec-compliant local-AI client (Claude Code, etc.) self-onboards: it reads
# the metadata below, registers, opens /oauth/authorize in a browser where the
# colleague logs in, then exchanges the code for a bearer token at /oauth/token.
def _oauth_error(err: oauth.OAuthError) -> JSONResponse:
    return JSONResponse({"error": err.error, "error_description": err.description},
                        status_code=err.status)


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
def oauth_protected_resource(request: Request):
    return oauth.protected_resource_metadata(_base_url(request))


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/mcp")
def oauth_authorization_server(request: Request):
    return oauth.authorization_server_metadata(_base_url(request))


@app.post("/oauth/register")
async def oauth_register(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata",
                             "error_description": "body must be JSON"}, status_code=400)
    try:
        rec = oauth.register_client(payload)
        audit.record("oauth_client_registered", client_id=rec["client_id"],
                     client_name=rec.get("client_name", ""))
        return JSONResponse(rec, status_code=201)
    except oauth.OAuthError as e:
        return _oauth_error(e)


def _authorize_page(params: dict, error: str = "") -> HTMLResponse:
    """Self-contained login + consent page served for GET/failed POST of /authorize.
    The page IS the gateway's password+MFA login; on success it 302s back with a code."""
    import html as _html
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{_html.escape(v)}">'
        for k, v in params.items() if v)
    client = oauth.get_client(params.get("client_id", ""))
    client_name = _html.escape(client.get("client_name") or "عميل ذكاء اصطناعي") if client else "عميل ذكاء اصطناعي"
    err_html = f'<p class="animate-element err" style="animation-delay:.25s">{_html.escape(error)}</p>' if error else ""
    mfa_field = ("""
<div class="animate-element field" style="animation-delay:.5s">
  <label>رمز المصادقة</label>
  <div class="glass"><input name="otp" inputmode="numeric" autocomplete="one-time-code"
    pattern="[0-9]*" maxlength="6" placeholder="000000" class="otp"></div>
</div>""" if CONFIG["auth"].get("require_mfa", False) else "")
    # Exact visual clone of the dashboard login (Login.tsx): white RTL page,
    # glass inputs, green CTA, staggered entrance animation — different backend.
    return HTMLResponse(f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>تفويض وصول الذكاء الاصطناعي</title>
<style>
*{{box-sizing:border-box;margin:0}}
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fff;
 color:#111827;text-align:right;font-family:Inter,"Segoe UI",system-ui,sans-serif}}
@keyframes elementIn{{from{{opacity:0;transform:translateY(24px)}}to{{opacity:1;transform:translateY(0)}}}}
.animate-element{{animation:elementIn .9s cubic-bezier(0.16,1,0.3,1) both}}
section{{width:100%;max-width:28rem;padding:2rem;display:flex;flex-direction:column;gap:1.5rem}}
h1{{font-size:2.75rem;font-weight:300;color:#111827;letter-spacing:-.05em;line-height:1.15}}
.sub{{color:#6b7280;line-height:1.6;font-size:.95rem}}
.sub b{{color:#111827;font-weight:600}}
form{{display:flex;flex-direction:column;gap:1.25rem}}
label{{display:block;font-size:.875rem;font-weight:500;color:#6b7280}}
.glass{{margin-top:.25rem;border-radius:1rem;border:1px solid #e5e7eb;background:rgba(17,24,39,.05);
 backdrop-filter:blur(4px);transition:border-color .15s,background .15s;position:relative}}
.glass:focus-within{{border-color:rgba(74,222,128,.7);background:rgba(34,197,94,.1)}}
input{{width:100%;background:transparent;font-size:.875rem;padding:1rem;border:0;border-radius:1rem;
 outline:none;text-align:right;color:#111827;font-family:inherit}}
input.pw{{padding-left:3rem}}
input.otp{{font-size:1.125rem;text-align:center;letter-spacing:.4em}}
.eye{{position:absolute;top:0;bottom:0;left:.75rem;display:flex;align-items:center;border:0;
 background:none;cursor:pointer;color:#6b7280;padding:0}}
.eye:hover{{color:#111827}}
.eye svg{{width:1.25rem;height:1.25rem}}
.err{{font-size:.875rem;color:#ef4444}}
button.cta{{width:100%;border:0;border-radius:1rem;background:#16a34a;padding:1rem;font-size:1rem;
 font-weight:500;color:#fff;cursor:pointer;transition:background .15s;font-family:inherit}}
button.cta:hover{{background:#15803d}}
.foot{{text-align:center;font-size:.75rem;color:#9ca3af;line-height:1.6}}
</style></head><body>
<section>
  <h1 class="animate-element" style="animation-delay:.1s">مرحباً</h1>
  <p class="animate-element sub" style="animation-delay:.2s"><b>{client_name}</b> يطلب الوصول إلى
  الأنظمة الداخلية <b>بحسابك أنت</b> عبر البوابة الآمنة. سجّل الدخول للموافقة — كل استدعاء يقوم به
  سيبقى مُدقَّقاً ومُسجَّلاً باسمك.</p>
  {err_html}
  <form method="post" action="/oauth/authorize">
    {hidden}
    <div class="animate-element field" style="animation-delay:.3s">
      <label>اسم المستخدم</label>
      <div class="glass"><input name="username" autocomplete="username" autofocus required
        placeholder="أدخل اسم المستخدم"></div>
    </div>
    <div class="animate-element field" style="animation-delay:.4s">
      <label>كلمة المرور</label>
      <div class="glass">
        <input name="password" id="pw" type="password" autocomplete="current-password" required
          placeholder="أدخل كلمة المرور" class="pw">
        <button type="button" class="eye" id="eyeBtn" aria-label="إظهار كلمة المرور">
          <svg id="eyeIcon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"
            stroke-linecap="round" stroke-linejoin="round">
            <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
      </div>
    </div>
    {mfa_field}
    <button type="submit" class="animate-element cta" style="animation-delay:.6s">تسجيل الدخول والموافقة</button>
  </form>
  <p class="animate-element foot" style="animation-delay:.7s">أنت توافق على الوصول لحسابك فقط. أغلق هذه الصفحة للإلغاء.</p>
</section>
<script>
document.getElementById("eyeBtn").addEventListener("click",function(){{
  var pw=document.getElementById("pw");
  pw.type=pw.type==="password"?"text":"password";
  this.style.color=pw.type==="text"?"#111827":"#6b7280";
}});
</script>
</body></html>""")


_AUTHZ_PARAM_KEYS = ("response_type", "client_id", "redirect_uri", "code_challenge",
                     "code_challenge_method", "state", "scope")


def _validate_authorize(p: dict) -> tuple[dict, str]:
    """Shared validation for GET render + POST submit. Returns (client, redirect_uri)
    or raises OAuthError for problems we must NOT redirect (bad client/redirect)."""
    client = oauth.get_client(p.get("client_id", ""))
    if not client:
        raise oauth.OAuthError("invalid_client", "unknown client_id; register first", status=400)
    redirect_uri = p.get("redirect_uri", "")
    if not redirect_uri or not oauth.redirect_uri_allowed(client, redirect_uri):
        raise oauth.OAuthError("invalid_request", "redirect_uri not registered for this client",
                               status=400)
    return client, redirect_uri


@app.get("/oauth/authorize")
def oauth_authorize_get(request: Request):
    p = {k: request.query_params.get(k, "") for k in _AUTHZ_PARAM_KEYS}
    try:
        _validate_authorize(p)
    except oauth.OAuthError as e:
        return _oauth_error(e)                 # safe: don't redirect to an unvetted URI
    if p.get("response_type") != "code":
        return _redirect_error(p, "unsupported_response_type", "only response_type=code")
    if p.get("code_challenge_method", "S256") != "S256" or not p.get("code_challenge"):
        return _redirect_error(p, "invalid_request", "PKCE S256 code_challenge required")
    return _authorize_page(p)


def _redirect_error(p: dict, error: str, desc: str) -> Response:
    from urllib.parse import urlencode
    q = {"error": error, "error_description": desc}
    if p.get("state"):
        q["state"] = p["state"]
    return RedirectResponse(f"{p['redirect_uri']}?{urlencode(q)}", status_code=302)


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request):
    form = await request.form()
    p = {k: str(form.get(k, "")) for k in _AUTHZ_PARAM_KEYS}
    try:
        _validate_authorize(p)
    except oauth.OAuthError as e:
        return _oauth_error(e)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    otp = str(form.get("otp", "")).strip()
    # Layer 1: password. Layer 2: TOTP when MFA is enforced. Reuses the same
    # verification + lockout machinery as the console login.
    ok = False
    if not auth.locked(username) and auth.verify_password_layer(username, password):
        if CONFIG["auth"].get("require_mfa", False):
            ok = auth.verify_totp(username, otp)
        else:
            ok = True
    if not ok:
        auth.note_failure(username)
        audit.record("oauth_authorize_failed", user=username or "unknown")
        return _authorize_page(p, error="Sign-in failed. Check your username, password"
                               + (" and authenticator code." if CONFIG["auth"].get("require_mfa") else "."))
    auth.clear_failures(username)
    code = oauth.create_authorization_code(
        p["client_id"], p["redirect_uri"], p["code_challenge"], username,
        p.get("scope") or "mcp")
    audit.record("oauth_authorized", user=username, client_id=p["client_id"])
    from urllib.parse import urlencode
    q = {"code": code}
    if p.get("state"):
        q["state"] = p["state"]
    return RedirectResponse(f"{p['redirect_uri']}?{urlencode(q)}", status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await request.form()
    grant = str(form.get("grant_type", ""))
    try:
        if grant == "authorization_code":
            body = oauth.exchange_code(
                str(form.get("code", "")), str(form.get("client_id", "")),
                str(form.get("redirect_uri", "")), str(form.get("code_verifier", "")))
            audit.record("oauth_token_issued", client_id=str(form.get("client_id", "")),
                         grant="authorization_code")
        elif grant == "refresh_token":
            body = oauth.refresh_access(
                str(form.get("refresh_token", "")), str(form.get("client_id", "")))
            audit.record("oauth_token_refreshed", client_id=str(form.get("client_id", "")))
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    except oauth.OAuthError as e:
        return _oauth_error(e)
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


# ---------- "Connect your AI" self-service page ----------
@app.get("/connect")
def connect_page():
    return FileResponse(str(UI_DIR / "connect.html"),
                        headers={"Cache-Control": "no-cache, must-revalidate"})


@app.post("/api/connect/token")
def connect_token(req: ConnectTokenReq, request: Request, claims: dict = Depends(fresh_password)):
    """Mint a paste-in connection token for MCP clients that take a static bearer
    (no OAuth support). Longer-lived than a console session but bounded, revocable,
    and attributed to this user. OAuth (auto-refresh) is preferred where supported."""
    ttl = int(CONFIG["auth"].get("oauth", {}).get("manual_token_ttl_seconds", 28800))
    token, expires_in, jti = auth.mint_oauth_access(claims["sub"], scope="mcp", ttl=ttl)
    audit.record("connect_token_issued", user=claims["sub"], jti=jti,
                 label=req.label[:60], expires_in=expires_in)
    return {
        "access_token": token,
        "expires_in": expires_in,
        "mcp_url": f"{_base_url(request)}/mcp",
        "config": {
            "mcpServers": {
                "company-gateway": {
                    "type": "http",
                    "url": f"{_base_url(request)}/mcp",
                    "headers": {"Authorization": f"Bearer {token}"},
                }
            }
        },
    }


@app.get("/api/connect/status")
def connect_status(claims: dict = Depends(current_user)):
    """Whether this user currently has a live MCP client session connected."""
    live = [s for s in mcp_server.sessions_list() if s["sub"] == claims["sub"]]
    return {"connected": bool(live), "sessions": len(live),
            "mcp_url_path": "/mcp", "user": claims["sub"]}


# ---------- approvals (HITL) ----------
def _audit_expired_approvals():
    """Expire overdue requests and put each on the audit chain (which also lands
    them in the notification panel)."""
    for e in gw.approvals.expire_stale():
        audit.record("approval_expired", approval_id=e["id"], requester=e["requester"],
                     server=e["server"], tool=e["tool"], tier=e["tier"],
                     waited_hours=round((time.time() - e.get("created", 0)) / 3600, 1))


@app.get("/api/approvals")
def list_approvals(claims: dict = Depends(current_user)):
    if not POLICY["roles"].get(claims["role"], {}).get("can_approve"):
        raise HTTPException(403, "approver role required")
    _audit_expired_approvals()
    return {"pending": gw.approvals.list_pending()}


@app.post("/api/approvals/{aid}/approve")
async def approve(aid: str, claims: dict = Depends(current_user)):
    if not POLICY["roles"].get(claims["role"], {}).get("can_approve"):
        raise HTTPException(403, "approver role required")
    # Step-up (RFC 9470): approving a Tier-3 destructive action requires a FRESH
    # authentication — a stale session cannot rubber-stamp a two-person delete.
    pending = gw.approvals.get(aid)
    if pending and pending.get("tier", 0) >= 3 and not auth.step_up_satisfied(claims):
        audit.record("step_up_required", approval_id=aid, approver=claims["sub"], tier=pending["tier"])
        raise HTTPException(401, "step-up required: re-authenticate to approve a Tier-3 action",
                            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'})
    result = gw.approvals.approve(aid, claims["sub"])
    if "error" in result:
        raise HTTPException(400, result["error"])
    audit.record("approval_vote", approval_id=aid, approver=claims["sub"],
                 action="approve", status=result["status"])
    if result["status"] == "approved":
        exec_result = await gw.execute_approved(result, claims_for)
        return {"status": "approved_and_executed", "approval": result, "result": exec_result}
    return {"status": "recorded", "approval": result,
            "remaining": result["approvals_required"] - len(result["approvals"])}


@app.post("/api/approvals/{aid}/reject")
def reject(aid: str, claims: dict = Depends(current_user)):
    if not POLICY["roles"].get(claims["role"], {}).get("can_approve"):
        raise HTTPException(403, "approver role required")
    result = gw.approvals.reject(aid, claims["sub"])
    if "error" in result:
        raise HTTPException(400, result["error"])
    audit.record("approval_vote", approval_id=aid, approver=claims["sub"], action="reject")
    return {"status": "rejected", "approval": result}


@app.get("/api/approvals/history")
def approvals_history(limit: int = 200, claims: dict = Depends(current_user)):
    """Resolved approvals (approved / rejected / expired) — who decided what, when,
    both signers — for the approver console and compliance."""
    if not POLICY["roles"].get(claims["role"], {}).get("can_approve"):
        raise HTTPException(403, "approver role required")
    _audit_expired_approvals()
    return {"history": gw.approvals.history(limit)}


# ---------- admin: kill switch, audit, registry ----------
@app.get("/api/admin/killswitch")
def killswitch_status(claims: dict = Depends(require_admin)):
    return {"active": kill_switch.active(), "details": kill_switch.details(),
            "scopes": _killswitch_scope_options()}


def _killswitch_scope_options() -> dict:
    """The scopes an admin can contain, so the console offers pickers instead of a
    free-text box where a typo silently protects nothing (A7)."""
    servers = sorted(gw.mcp.servers)
    tools = sorted({f"{t['server']}:{t['name']}" for t in gw.mcp.all_tools()})
    return {"servers": servers, "tools": tools, "users": sorted(USERS)}


@app.post("/api/admin/killswitch/engage")
def killswitch_engage(req: KillReq, claims: dict = Depends(require_admin)):
    """Engage containment. A reason is REQUIRED (the most powerful button in the product
    must leave a trail), and an optional TTL auto-releases it so a forgotten global kill
    cannot strand the organization indefinitely."""
    scope = (req.scope or "").strip()
    if not _valid_kill_scope(scope):
        raise HTTPException(400, "scope must be 'global', 'server:<name>', "
                                 "'tool:<server>:<tool>' or 'user:<sub>'")
    reason = (req.reason or "").strip()
    if len(reason) < 3:
        raise HTTPException(400, "a reason is required (min 3 characters)")
    ttl = req.ttl_minutes
    if ttl is not None and not (1 <= int(ttl) <= 10080):
        raise HTTPException(400, "ttl_minutes must be between 1 and 10080 (7 days)")
    kill_switch.engage(scope, by=claims["sub"], reason=reason,
                       ttl_minutes=int(ttl) if ttl else None)
    audit.record("killswitch_engage", scope=scope, by=claims["sub"], reason=reason,
                 ttl_minutes=ttl)
    return {"active": kill_switch.active(), "details": kill_switch.details()}


def _valid_kill_scope(scope: str) -> bool:
    if scope == "global":
        return True
    if scope.startswith("server:") and len(scope) > 7:
        return True
    if scope.startswith("user:") and len(scope) > 5:
        return True
    if scope.startswith("tool:") and scope.count(":") >= 2:
        return True
    return False


@app.post("/api/admin/killswitch/release")
def killswitch_release(req: KillReq, claims: dict = Depends(require_admin)):
    kill_switch.release(req.scope)
    audit.record("killswitch_release", scope=req.scope, by=claims["sub"])
    return {"active": kill_switch.active(), "details": kill_switch.details()}


@app.get("/api/admin/revocations")
def revocations(claims: dict = Depends(require_admin)):
    return {"revoked": auth.revoked(), "lockouts": auth.lockout_status()}


@app.post("/api/admin/revoke")
def revoke_identity(req: RevokeReq, claims: dict = Depends(require_admin)):
    """Identity kill-switch: block a subject within one request (<1s), independent
    of token lifetime. Rejects new logins and in-flight tokens for that subject."""
    auth.revoke_subject(req.sub)
    cancelled = gw.approvals.reject_all_for(req.sub, by=claims["sub"])
    for a in cancelled:
        audit.record("approval_cancelled", approval_id=a["id"], requester=req.sub,
                     reason="requester revoked", by=claims["sub"])
    audit.record("identity_revoked", sub=req.sub, by=claims["sub"],
                 approvals_cancelled=len(cancelled))
    return {"revoked": auth.revoked()}


@app.post("/api/admin/unrevoke")
def unrevoke_identity(req: RevokeReq, claims: dict = Depends(require_admin)):
    auth.unrevoke_subject(req.sub)
    audit.record("identity_unrevoked", sub=req.sub, by=claims["sub"])
    return {"revoked": auth.revoked()}


@app.post("/api/admin/unlock")
def unlock_identity(req: RevokeReq, claims: dict = Depends(require_admin)):
    """Clear an identity's anti-hammering lockout (after out-of-band verification)."""
    auth.clear_failures(req.sub)
    audit.record("identity_unlocked", sub=req.sub, by=claims["sub"])
    return {"lockouts": auth.lockout_status()}


@app.get("/api/admin/audit")
def audit_tail(event: str = "", user: str = "", server: str = "", tool: str = "",
               text: str = "", since: float | None = None, until: float | None = None,
               limit: int = 200, offset: int = 0,
               claims: dict = Depends(require_admin)):
    """Filtered, paginated audit search (A2). With no filters this is the old tail, so
    existing callers are unaffected; with filters it answers 'what did khalid touch last
    Tuesday' without SSH-ing in to grep a 2 MB JSONL file."""
    ok, msg = audit.chain_status()      # the "Re-verify" button forces a fresh full pass
    page = insights.query(event=event, user=user, server=server, tool=tool, text=text,
                          since=since, until=until, limit=limit, offset=offset)
    return {"chain_ok": ok, "chain_status": msg, **page}


@app.get("/api/admin/audit/verify")
def audit_verify(claims: dict = Depends(require_admin)):
    """Force a FULL re-verification of the hash chain (the console's Re-verify button).
    Deliberately not cached: this is the tamper-evidence check, and an operator asking for
    it must get a fresh answer, however long the log is."""
    ok, msg = audit.chain_status(full=True)      # every record, from genesis
    audit.record("audit_chain_verified", by=claims["sub"], ok=ok, detail=msg)
    return {"chain_ok": ok, "chain_status": msg}


@app.get("/api/admin/audit/facets")
def audit_facets(claims: dict = Depends(require_admin)):
    """Distinct events/users/servers/tools — the filter dropdowns."""
    return insights.facets()


@app.get("/api/admin/audit/export")
def audit_export(fmt: str = "csv", event: str = "", user: str = "", server: str = "",
                 tool: str = "", text: str = "", since: float | None = None,
                 until: float | None = None, limit: int = 10000,
                 claims: dict = Depends(require_admin)):
    """Export the current audit view (CSV or JSON) for an investigation or an auditor."""
    page = insights.query(event=event, user=user, server=server, tool=tool, text=text,
                          since=since, until=until, limit=min(int(limit), 10000), offset=0)
    audit.record("audit_exported", by=claims["sub"], count=len(page["records"]), format=fmt,
                 filters={k: v for k, v in
                          {"event": event, "user": user, "server": server, "tool": tool,
                           "text": text}.items() if v})
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        return JSONResponse(
            page["records"],
            headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.json"'})
    return PlainTextResponse(
        insights.export_csv(page["records"]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'})


@app.get("/api/admin/registry")
def registry(claims: dict = Depends(require_admin)):
    """Registry entries, each carrying the live tool schema so an admin can READ a tool
    before approving it — approving a hash you cannot inspect is not governance (A8)."""
    entries = []
    for e in gw.registry.entries.values():
        live = gw.mcp.find_tool(e["server"], e["tool"])
        definition = e.get("definition") or {}
        entries.append({
            **e,
            "description": (live or {}).get("description") or definition.get("description", ""),
            "schema": (live or {}).get("schema") or definition.get("schema", {}),
            "has_drift": bool(e.get("pending_fingerprint")),
        })
    return {"entries": entries}


@app.get("/api/admin/registry/{server}/{tool}/diff")
def registry_diff(server: str, tool: str, claims: dict = Depends(require_admin)):
    """What actually CHANGED in a drift-quarantined tool — pinned vs pending definition.
    Re-pinning a hash without seeing the diff is rubber-stamping (A24)."""
    diff = gw.registry.drift_diff(server, tool)
    if not diff:
        raise HTTPException(404, "no pending drift for this tool")
    return diff


@app.post("/api/admin/registry/{server}/{tool}/reject")
def reject_tool(server: str, tool: str, req: ReasonReq,
                claims: dict = Depends(require_admin)):
    """Risk-Board REJECTION: the tool stays known, permanently inactive, and discovery
    will not resurrect it. Until now an admin could only ever say yes (A8)."""
    if not gw.registry.reject(server, tool, req.reason):
        raise HTTPException(404, "unknown tool")
    audit.record("tool_rejected", server=server, tool=tool, by=claims["sub"],
                 reason=req.reason)
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/reinstate")
def reinstate_tool(server: str, tool: str, claims: dict = Depends(require_admin)):
    """Undo a rejection — the tool returns to `pending` for a fresh decision."""
    if not gw.registry.reinstate(server, tool):
        raise HTTPException(400, "tool is not rejected")
    audit.record("tool_reinstated", server=server, tool=tool, by=claims["sub"])
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/quarantine")
def quarantine_tool(server: str, tool: str, req: ReasonReq,
                    claims: dict = Depends(require_admin)):
    """Manually contain ONE tool on suspicion — narrower than a kill switch, and durable.
    Previously an admin could only wait for hash drift to quarantine something (A8)."""
    reason = (req.reason or "").strip()
    if len(reason) < 3:
        raise HTTPException(400, "a reason is required (min 3 characters)")
    if not gw.registry.quarantine(server, tool, reason):
        raise HTTPException(404, "unknown tool")
    audit.record("tool_quarantined", server=server, tool=tool, by=claims["sub"], reason=reason)
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/unquarantine")
def unquarantine_tool(server: str, tool: str, claims: dict = Depends(require_admin)):
    """Release a MANUAL quarantine. A drift quarantine must go through approve_drift
    (re-pin the hash) so a definition change can never be waved through by accident."""
    if not gw.registry.unquarantine(server, tool):
        raise HTTPException(400, "tool is not manually quarantined "
                                 "(drift quarantines are released by re-pinning)")
    audit.record("tool_unquarantined", server=server, tool=tool, by=claims["sub"])
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/approve_drift")
def approve_drift(server: str, tool: str, claims: dict = Depends(require_admin)):
    gw.registry.approve_drift(server, tool)
    audit.record("registry_drift_approved", server=server, tool=tool, by=claims["sub"])
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/approve")
def approve_tool(server: str, tool: str, claims: dict = Depends(require_admin)):
    """Risk-Board activation of a newly-onboarded (pending) tool."""
    ok = gw.registry.approve_tool(server, tool)
    audit.record("tool_onboarded", server=server, tool=tool, by=claims["sub"], activated=ok)
    return {"approved": ok, "entry": gw.registry.get(server, tool)}


@app.post("/api/admin/registry/{server}/{tool}/tier")
def set_tool_tier(server: str, tool: str, req: TierReq,
                  claims: dict = Depends(require_admin)):
    """Risk-Board tier override: replace the discovery heuristic's tier for one tool
    (0 read / 1 reversible write / 2 human approval / 3 two-person)."""
    if req.tier not in (0, 1, 2, 3):
        raise HTTPException(400, "tier must be 0, 1, 2 or 3")
    entry = gw.registry.get(server, tool)
    if not entry:
        raise HTTPException(404, "unknown tool")
    old = entry["tier"]
    gw.registry.set_tier(server, tool, req.tier)
    audit.record("tool_retiered", server=server, tool=tool, by=claims["sub"],
                 old_tier=old, new_tier=req.tier)
    return {"entry": gw.registry.get(server, tool)}


@app.post("/api/admin/mfa/{username}/enroll")
def admin_enroll_mfa(username: str, claims: dict = Depends(require_admin)):
    """Enroll (or re-enroll) an operator's TOTP authenticator. Returns the base32
    secret + otpauth:// URI ONCE for out-of-band handover; the gateway stores only
    the KEK-encrypted secret. Re-enrollment invalidates the previous authenticator."""
    if username not in USERS:
        raise HTTPException(404, "unknown operator")
    secret, uri = auth.enroll_totp(username)
    audit.record("mfa_enrolled", user=username, by=claims["sub"])
    return {"username": username, "secret": secret, "otpauth_uri": uri,
            "note": "displayed once — hand over out-of-band and verify first login"}


@app.get("/api/admin/mfa")
def mfa_status(claims: dict = Depends(require_admin)):
    """Which operators have an enrolled authenticator (required to log in when
    auth.require_mfa is on)."""
    return {"require_mfa": bool(CONFIG["auth"].get("require_mfa", False)),
            "operators": {u: auth.mfa_enrolled(u) for u in USERS}}


# ---------- admin: API keys (real issue/revoke — keys work on /mcp) ----------
@app.get("/api/admin/apikeys")
def apikeys_list(claims: dict = Depends(require_admin)):
    return {"keys": apikeys.list_keys(), "scopes": sorted(apikeys.SCOPES)}


@app.post("/api/admin/apikeys")
def apikeys_create(req: ApiKeyReq, claims: dict = Depends(require_admin)):
    """Issue a scoped API key bound to an operator. The full token is returned ONCE
    and stored only as a hash."""
    if req.sub not in USERS:
        raise HTTPException(404, "unknown operator")
    try:
        rec, token = apikeys.issue(req.name, req.sub, req.scope, req.ttl_days, claims["sub"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.record("apikey_created", kid=rec["kid"], name=rec["name"], sub=req.sub,
                 scope=req.scope, ttl_days=req.ttl_days, by=claims["sub"])
    return {"key": {k: v for k, v in rec.items() if k != "hash"}, "token": token,
            "note": "displayed once — store it in your CI secret manager now"}


@app.post("/api/admin/apikeys/{kid}/revoke")
def apikeys_revoke(kid: str, claims: dict = Depends(require_admin)):
    rec = apikeys.revoke(kid)
    if not rec:
        raise HTTPException(404, "unknown key")
    audit.record("apikey_revoked", kid=kid, name=rec["name"], by=claims["sub"])
    return {"revoked": kid}


# ---------- admin: OAuth clients (list + revoke registered MCP clients) ----------
@app.get("/api/admin/oauth/clients")
def oauth_clients(claims: dict = Depends(require_admin)):
    return {"clients": oauth.list_clients()}


@app.post("/api/admin/oauth/clients/{client_id}/revoke")
def oauth_client_revoke(client_id: str, claims: dict = Depends(require_admin)):
    """Delete a client registration and kill all its refresh tokens. Outstanding
    access tokens (<=1h TTL) expire on their own and cannot be renewed."""
    rec = oauth.revoke_client(client_id)
    if rec is None:
        raise HTTPException(404, "unknown client")
    audit.record("oauth_client_revoked", client_id=client_id,
                 client_name=rec.get("client_name", ""),
                 refresh_tokens_revoked=rec.get("refresh_tokens_revoked", 0), by=claims["sub"])
    return {"revoked": client_id, "refresh_tokens_revoked": rec.get("refresh_tokens_revoked", 0)}


# ---------- admin: operator lifecycle ----------
def _admin_count() -> int:
    return sum(1 for u in USERS.values() if POLICY["roles"].get(u["role"], {}).get("admin"))


@app.post("/api/admin/operators")
def operator_create(req: OperatorCreateReq, claims: dict = Depends(require_admin)):
    """Full onboarding in one step: create the operator, seed a temporary password
    (returned ONCE, rotation forced at first login) and enroll their authenticator
    (otpauth URI returned ONCE for out-of-band handover)."""
    ok, msg = auth.create_operator(req.sub, req.name, req.role, req.clearance)
    if not ok:
        raise HTTPException(400, msg)
    sub = req.sub.strip().lower()
    temp_pw, err = auth.reset_password(sub)
    if err:
        raise HTTPException(500, f"operator created but password seeding failed: {err}")
    secret, uri = auth.enroll_totp(sub)
    audit.record("operator_created", sub=sub, role=req.role, clearance=req.clearance,
                 by=claims["sub"])
    return {"sub": sub, "temp_password": temp_pw, "totp_secret": secret,
            "otpauth_uri": uri,
            "note": "hand the password + authenticator over out-of-band; shown once"}


@app.post("/api/admin/operators/{sub}/offboard")
def operator_offboard(sub: str, claims: dict = Depends(require_admin)):
    if sub == claims["sub"]:
        raise HTTPException(400, "you cannot offboard yourself")
    u = USERS.get(sub)
    if not u:
        raise HTTPException(404, "unknown operator")
    if POLICY["roles"].get(u["role"], {}).get("admin") and _admin_count() <= 1:
        raise HTTPException(400, "cannot offboard the last admin")
    ok, msg = auth.remove_operator(sub)
    if not ok:
        raise HTTPException(400, msg)
    cancelled = gw.approvals.reject_all_for(sub, by=claims["sub"])
    for a in cancelled:
        audit.record("approval_cancelled", approval_id=a["id"], requester=sub,
                     reason="requester offboarded", by=claims["sub"])
    audit.record("operator_offboarded", sub=sub, by=claims["sub"],
                 approvals_cancelled=len(cancelled))
    return {"offboarded": sub, "approvals_cancelled": len(cancelled)}


@app.post("/api/admin/operators/{sub}/role")
def operator_role(sub: str, req: OperatorRoleReq, claims: dict = Depends(require_admin)):
    u = USERS.get(sub)
    if not u:
        raise HTTPException(404, "unknown operator")
    old_role, old_clearance = u["role"], u["clearance"]
    demoting = POLICY["roles"].get(old_role, {}).get("admin") and \
        req.role is not None and not POLICY["roles"].get(req.role, {}).get("admin")
    if demoting and sub == claims["sub"]:
        raise HTTPException(400, "you cannot remove your own admin role")
    if demoting and _admin_count() <= 1:
        raise HTTPException(400, "cannot demote the last admin")
    ok, msg = auth.update_operator(sub, role=req.role, clearance=req.clearance, name=req.name)
    if not ok:
        raise HTTPException(400, msg)
    audit.record("operator_role_changed", sub=sub, old_role=old_role,
                 old_clearance=old_clearance, role=USERS[sub]["role"],
                 clearance=USERS[sub]["clearance"], by=claims["sub"])
    # a role change must not ride on old tokens minted with the old role
    auth.terminate_sessions(sub)
    return {"sub": sub, "role": USERS[sub]["role"], "clearance": USERS[sub]["clearance"]}


@app.post("/api/admin/operators/{sub}/reset_password")
def operator_reset_password(sub: str, claims: dict = Depends(require_admin)):
    """Issue a temporary password (returned ONCE); rotation forced at next login."""
    temp_pw, err = auth.reset_password(sub)
    if err:
        raise HTTPException(404 if "unknown" in err else 400, err)
    audit.record("password_reset_forced", sub=sub, by=claims["sub"])
    return {"sub": sub, "temp_password": temp_pw,
            "note": "hand over out-of-band; shown once, must be rotated at first login"}


@app.post("/api/admin/operators/{sub}/signout")
def operator_signout(sub: str, claims: dict = Depends(require_admin)):
    """Sign a subject out everywhere: console sessions, OAuth access + refresh
    tokens, API keys issued before now, and live MCP sessions."""
    if sub not in USERS:
        raise HTTPException(404, "unknown operator")
    auth.terminate_sessions(sub)
    audit.record("sessions_terminated", sub=sub, by=claims["sub"])
    return {"signed_out": sub}


@app.post("/api/admin/sessions/{sid}/terminate")
def session_terminate(sid: str, claims: dict = Depends(require_admin)):
    """Kill one live inbound MCP session (by the 12-char id shown in the console)."""
    got = mcp_server.terminate(sid)
    if not got:
        raise HTTPException(404, "unknown session")
    audit.record("mcp_session_terminated", sid=got["id"], sub=got["sub"], by=claims["sub"])
    return {"terminated": got}


# ---------- admin: server lifecycle & containment ----------
def _server_or_404(name: str):
    srv = gw.mcp.servers.get(name)
    if not srv:
        raise HTTPException(404, "unknown server")
    return srv


@app.post("/api/admin/servers/{name}/restart")
async def server_restart(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    try:
        await gw.mcp.restart_server(name)
    except Exception as e:
        audit.record("server_restart_failed", server=name, by=claims["sub"], error=str(e)[:200])
        raise HTTPException(502, f"restart failed: {e}")
    gw.reset_breaker(name)
    gw.registry.reconcile(gw.mcp.all_tools())
    audit.record("server_restarted", server=name, by=claims["sub"])
    return {"server": name, "state": "running"}


@app.post("/api/admin/servers/{name}/stop")
async def server_stop(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    await gw.mcp.stop_server(name)
    audit.record("server_stopped", server=name, by=claims["sub"])
    return {"server": name, "state": "stopped"}


@app.post("/api/admin/servers/{name}/start")
async def server_start(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    try:
        await gw.mcp.start_server(name)
    except Exception as e:
        audit.record("server_start_failed", server=name, by=claims["sub"], error=str(e)[:200])
        raise HTTPException(502, f"start failed: {e}")
    gw.reset_breaker(name)
    gw.registry.reconcile(gw.mcp.all_tools())
    audit.record("server_started", server=name, by=claims["sub"])
    return {"server": name, "state": "running"}


@app.post("/api/admin/servers/{name}/drain")
def server_drain(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    gw.drain(name)
    audit.record("server_drained", server=name, by=claims["sub"])
    return {"server": name, "drained": True}


@app.post("/api/admin/servers/{name}/undrain")
def server_undrain(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    gw.undrain(name)
    audit.record("server_undrained", server=name, by=claims["sub"])
    return {"server": name, "drained": False}


@app.post("/api/admin/servers/{name}/breaker_reset")
def server_breaker_reset(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    gw.reset_breaker(name)
    audit.record("breaker_reset", server=name, by=claims["sub"])
    return {"server": name, "breaker_open": False}


@app.post("/api/admin/servers/add")
async def server_add(req: ServerAddReq, claims: dict = Depends(require_admin)):
    """Connect a new MCP server at runtime and persist it (no config.yaml edit, no
    gateway restart). Its tools enter the registry through the normal onboarding
    gate (pending until approved, when the gate is on)."""
    if req.transport == "stdio" and not req.command:
        raise HTTPException(400, "stdio servers need a command")
    if req.transport == "http" and not req.url:
        raise HTTPException(400, "http servers need a url")
    if req.transport not in ("stdio", "http"):
        raise HTTPException(400, "transport must be stdio or http")
    spec = {"name": req.name.strip(), "command": req.command, "args": req.args,
            "transport": req.transport, "env": req.env}
    if req.url:
        spec["url"] = req.url
    try:
        srv = await gw.mcp.add_server(spec)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"server failed to start: {e}")
    events = gw.registry.reconcile(gw.mcp.all_tools())
    for e in events:
        audit.record("registry_event", **e)
    audit.record("server_added", server=srv.name, transport=req.transport,
                 tools=len(srv.tools), by=claims["sub"])
    return {"server": srv.name, "state": srv.state, "tools": len(srv.tools),
            "pending_tools": len([e for e in events if e.get("status") == "pending"])}


@app.post("/api/admin/servers/{name}/remove")
async def server_remove(name: str, claims: dict = Depends(require_admin)):
    _server_or_404(name)
    await gw.mcp.remove_server(name)
    gw.undrain(name)
    gw.reset_breaker(name)
    audit.record("server_removed", server=name, by=claims["sub"])
    return {"removed": name}


@app.get("/api/admin/servers/{name}/spec")
def server_spec(name: str, claims: dict = Depends(require_admin)):
    """The spec a server is running with — what the edit form loads (env values redacted)."""
    _server_or_404(name)
    return gw.mcp.server_spec(name)


@app.post("/api/admin/servers/{name}/edit")
async def server_edit(name: str, req: EditServerReq, claims: dict = Depends(require_admin)):
    """Change a server's command/args/env/transport in place (A16). Previously the only
    way to fix a typo'd env var was remove + re-add, which dropped every pinned hash for
    that server and forced all its tools back through onboarding. The registry survives
    an edit — and re-checks definitions, so genuinely changed tools still quarantine."""
    _server_or_404(name)
    if req.transport not in ("stdio", "http"):
        raise HTTPException(400, "transport must be stdio or http")
    if req.transport == "stdio" and not req.command:
        raise HTTPException(400, "stdio servers need a command")
    if req.transport == "http" and not req.url:
        raise HTTPException(400, "http servers need a url")
    spec = {"command": req.command, "args": req.args, "transport": req.transport,
            "env": req.env}
    if req.url:
        spec["url"] = req.url
    try:
        srv = await gw.mcp.edit_server(name, spec)
    except Exception as e:
        raise HTTPException(502, f"edit failed, server left running on the old spec: {e}")
    events = gw.registry.reconcile(gw.mcp.all_tools())
    for e in events:
        audit.record("registry_event", **e)
    audit.record("server_edited", server=name, by=claims["sub"], transport=req.transport,
                 tools=len(srv.tools))
    return {"server": name, "state": srv.state, "tools": len(srv.tools),
            "drift_quarantined": len([e for e in events if e["type"] == "drift_quarantine"])}


# ---------- admin: notification center (the dashboard right panel) ----------
@app.get("/api/admin/notifications")
def notifications_list(limit: int = 100, claims: dict = Depends(require_admin)):
    """Read/unread state is per operator (A22): one admin clearing the bell must not
    hide an incident from the rest of a 2–4 person team."""
    sub = claims["sub"]
    return {"notifications": notifications.list_all(limit, sub=sub),
            "unread": notifications.unread_count(sub)}


@app.post("/api/admin/notifications/read")
def notifications_read(req: NotifReadReq, claims: dict = Depends(require_admin)):
    sub = claims["sub"]
    changed = notifications.mark_read(req.ids, mark_all=req.all, sub=sub)
    return {"marked_read": changed, "unread": notifications.unread_count(sub)}


@app.post("/api/admin/notifications/clear")
def notifications_clear(claims: dict = Depends(require_admin)):
    sub = claims["sub"]
    return {"cleared": notifications.clear_read(sub), "unread": notifications.unread_count(sub)}


@app.get("/api/admin/vault")
def vault_leases(claims: dict = Depends(require_admin)):
    from .vault import vault
    return {"active_leases": vault.active_leases()}


# ---------- admin: runtime settings (the console's write side) ----------
@app.get("/api/admin/settings")
def settings_get(claims: dict = Depends(require_admin)):
    """Effective settings + which of them an admin has overridden. Rate limits, approval
    tier, DLP detectors, anomaly thresholds, alert rules and session policy are all
    editable here — no SSH, no file edit, no restart (A6/A15/A3)."""
    return {"effective": gwsettings.effective(), "overrides": gwsettings.overrides(),
            "alert_rules": list(gwsettings.ALERT_RULES),
            "servers": sorted(gw.mcp.servers)}


@app.post("/api/admin/settings")
def settings_update(req: SettingsReq, claims: dict = Depends(require_admin)):
    try:
        section = gwsettings.update(req.section, req.patch)
    except gwsettings.SettingsError as e:
        raise HTTPException(400, str(e))
    audit.record("settings_changed", by=claims["sub"], section=req.section, patch=req.patch)
    return {"section": req.section, "effective": section}


@app.post("/api/admin/settings/reset")
def settings_reset(section: str = "", claims: dict = Depends(require_admin)):
    """Drop overrides and fall back to the config.yaml baseline."""
    try:
        eff = gwsettings.reset(section or None)
    except gwsettings.SettingsError as e:
        raise HTTPException(400, str(e))
    audit.record("settings_reset", by=claims["sub"], section=section or "all")
    return {"effective": eff, "overrides": gwsettings.overrides()}


# ---------- admin: the gateway's own page (it finally monitors itself) ----------
@app.get("/api/admin/gateway")
def gateway_self(claims: dict = Depends(require_admin)):
    """Version, uptime, effective config, backup status, certificate expiry, disk growth
    (A10/A11/A13/A23) — the gateway watched everything except itself."""
    return selfinfo.overview(gw)


@app.post("/api/admin/gateway/maintenance")
def gateway_maintenance(req: MaintenanceReq, claims: dict = Depends(require_admin)):
    """Pause mediated tool calls during a patch/migration. Admins keep working (they are
    the ones fixing it) and the console stays up — unlike a global kill switch."""
    state = selfinfo.set_maintenance(req.enabled, by=claims["sub"], message=req.message)
    audit.record("maintenance_mode", by=claims["sub"], enabled=req.enabled,
                 message=req.message)
    return state


# ---------- admin: real numbers (what the console used to fabricate) ----------
@app.get("/api/admin/series")
def traffic_series(hours: int = 24, buckets: int = 24,
                   claims: dict = Depends(require_admin)):
    """Real traffic + latency time-series from the audit chain (A19/A5). The Overview
    charts were synthetic because nobody had ever computed this."""
    return insights.series(hours=hours, buckets=buckets)


@app.get("/api/admin/stats")
def call_stats(claims: dict = Depends(require_admin)):
    """Per-tool and per-server call counts, success rate, and p50/p95 latency (A5/A16)."""
    return {"tools": insights.tool_stats(), "servers": insights.server_stats()}


@app.get("/api/admin/ratelimits")
def rate_limit_usage(claims: dict = Depends(require_admin)):
    """LIVE rate-limit consumption (A9). The console's usage bars were hardcoded to 0,
    so an admin could not see who was near a limit or being throttled."""
    from .controls import rate_limiter, server_limiter, tool_limiter
    eff = gwsettings.get("rate_limits")
    return {
        "limits": eff,
        "per_user": rate_limiter.snapshot(),
        "per_tool": tool_limiter.snapshot(),
        "per_server": server_limiter.snapshot(),
        "window_seconds": 60,
    }


@app.get("/api/admin/dlp")
def dlp_activity(hours: int = 168, claims: dict = Depends(require_admin)):
    """Where PII is actually being found and masked — by detector, tool, and user (A17)."""
    return insights.dlp_activity(window_hours=hours)


@app.get("/api/admin/approvals/aging")
def approvals_aging(claims: dict = Depends(require_admin)):
    """Queue health: what is waiting, how long, what breaches SLA, and how fast decisions
    actually happen (A18)."""
    _audit_expired_approvals()
    return insights.approval_aging(gw)


@app.get("/api/admin/lockouts")
def lockouts(claims: dict = Depends(require_admin)):
    """Currently locked-out identities in one place, with the unlock action (A20)."""
    lk = auth.lockout_status()
    return {"lockouts": [{"sub": s, **v} for s, v in lk.items()], "count": len(lk)}


@app.get("/api/admin/operators")
def operators(claims: dict = Depends(require_admin)):
    """Directory of gateway operators (identities) with live status."""
    rev = set(auth.revoked())
    lk = auth.lockout_status()
    roles = POLICY["roles"]
    out = []
    for sub, info in USERS.items():
        rc = roles.get(info["role"], {})
        out.append({
            "sub": sub, "name": info["name"], "role": info["role"], "clearance": info["clearance"],
            "can_approve": bool(rc.get("can_approve")), "admin": bool(rc.get("admin")),
            "max_tool_tier": rc.get("max_tool_tier"),
            "revoked": sub in rev, "locked": sub in lk, "fails": lk.get(sub, {}).get("fails", 0),
        })
    return {"operators": out, "count": len(out)}


@app.get("/api/admin/policy")
def policy_view(claims: dict = Depends(require_admin)):
    """ABAC policy-as-code: the clearance ladder and per-role capabilities."""
    return {"clearance_order": POLICY["clearance_order"], "roles": POLICY["roles"]}


@app.get("/api/admin/config")
def config_view(claims: dict = Depends(require_admin)):
    """Non-secret runtime configuration — limits, modes, and production swap points."""
    a, g = CONFIG.get("auth", {}), CONFIG.get("gateway", {})
    return {
        "auth": {k: a.get(k) for k in ("mode", "issuer", "audience", "alg", "aal",
                 "access_ttl_seconds", "challenge_ttl_seconds", "clock_skew_seconds",
                 "lockout_threshold", "lockout_seconds", "step_up_max_age_seconds",
                 "login_rate_per_minute", "max_request_bytes")},
        "gateway": g,
        "registry": {"require_approval": (CONFIG.get("registry") or {}).get("require_approval", False)},
        "audit": {"siem_export": (CONFIG.get("audit") or {}).get("siem_export", False),
                  "siem_stream": (CONFIG.get("audit") or {}).get("siem_stream")},
        "vault": {s: {"ttl_seconds": (v or {}).get("ttl_seconds")} for s, v in (CONFIG.get("vault") or {}).items()},
        "allowed_origins": a.get("allowed_origins", []),
        "servers": [{"name": s["name"], "command": s["command"]} for s in CONFIG["servers"]],
    }


@app.get("/api/admin/servers")
def servers_view(claims: dict = Depends(require_admin)):
    """Per-MCP-server inventory: tool counts, tier spread, breaker state, governance —
    now with the REAL version (from the MCP handshake), uptime, and measured latency
    (from audit durations). All three were em-dashes in the console (A16)."""
    from .vault import vault
    stats = insights.server_stats()
    breaker = gw.breaker_snapshot()
    now = time.time()
    out = []
    for name, srv in gw.mcp.servers.items():
        entries = [e for e in (gw.registry.get(name, t["name"]) for t in srv.tools) if e]
        b = breaker.get(name, {})
        st = stats.get(name, {})
        out.append({
            "name": name, "tools": len(srv.tools),
            "state": srv.state, "drained": name in gw.drained,
            "transport": srv.transport, "started_at": srv.started_at,
            "uptime_seconds": round(now - srv.started_at) if srv.started_at
                              and srv.state == "running" else None,
            "version": srv.server_version,
            "protocol_version": srv.protocol_version,
            "breaker_open": gw._breaker_open(name), "fails": b.get("fails", 0),
            "tiers": {str(t): sum(1 for e in entries if e["tier"] == t) for t in range(4)},
            "active": sum(1 for e in entries if e["status"] == "active"),
            "pending": sum(1 for e in entries if e["status"] == "pending"),
            "quarantined": sum(1 for e in entries if e["status"] == "quarantined"),
            "rejected": sum(1 for e in entries if e["status"] == "rejected"),
            "managed_credentials": vault.manages(name),
            "calls": st.get("calls", 0), "errors": st.get("errors", 0),
            "avg_ms": st.get("avg_ms"), "p95_ms": st.get("p95_ms"),
            "rate_limit": gwsettings.rate_limit_for_server(name),
        })
    return {"servers": out}


@app.get("/api/admin/sessions")
def sessions_view(claims: dict = Depends(require_admin)):
    """Live inbound MCP sessions (connected client LLMs)."""
    return {"sessions": mcp_server.sessions_list()}


@app.get("/api/admin/alerts")
def alerts_view(claims: dict = Depends(require_admin)):
    """Anomaly & alert engine: real alerts derived from the audit chain, circuit
    breakers, registry, lockouts, and the approval queue (see app/anomaly.py)."""
    from . import anomaly
    return anomaly.evaluate(gw)


@app.get("/api/admin/investigate")
def investigate(subject: str = "", limit: int = 400,
                claims: dict = Depends(require_admin)):
    """Session forensics: reconstruct per-identity activity timelines from the audit
    chain. Without `subject`, returns a summary per identity; with it, the full
    ordered event timeline for that identity (who did what, when, to which tool)."""
    records = audit.tail(limit)
    live = {s["sub"] for s in mcp_server.sessions_list()}

    def _row(r: dict) -> dict:
        return {"ts": r.get("ts"), "event": r.get("event"),
                "server": r.get("server"), "tool": r.get("tool"),
                "tier": r.get("tier"), "classification": r.get("classification"),
                "pii_masked": r.get("pii_masked"), "approved_id": r.get("approved_id"),
                "result_digest": r.get("result_digest"),
                "role": r.get("role"), "scope": r.get("scope")}

    if subject:
        timeline = [_row(r) for r in records
                    if (r.get("user") == subject or r.get("sub") == subject
                        or r.get("by") == subject)]
        servers = sorted({t["server"] for t in timeline if t["server"]})
        tools = sorted({t["tool"] for t in timeline if t["tool"]})
        return {"subject": subject, "live": subject in live,
                "event_count": len(timeline), "servers": servers, "tools": tools,
                "timeline": list(reversed(timeline))}

    agg: dict[str, dict] = {}
    for r in records:
        sub = r.get("user") or r.get("sub") or r.get("by")
        if not sub:
            continue
        a = agg.setdefault(sub, {"subject": sub, "events": 0, "tool_calls": 0,
                                 "errors": 0, "first_ts": r.get("ts"), "last_ts": r.get("ts"),
                                 "servers": set(), "tools": set()})
        a["events"] += 1
        ev = r.get("event", "")
        if ev == "tool_call":
            a["tool_calls"] += 1
        if ev == "tool_error":
            a["errors"] += 1
        if r.get("server"):
            a["servers"].add(r["server"])
        if r.get("tool"):
            a["tools"].add(r["tool"])
        ts = r.get("ts")
        if ts:
            a["first_ts"] = min(a["first_ts"] or ts, ts)
            a["last_ts"] = max(a["last_ts"] or ts, ts)
    subjects = []
    for a in agg.values():
        subjects.append({**a, "servers": sorted(a["servers"]), "tools": sorted(a["tools"]),
                         "live": a["subject"] in live})
    subjects.sort(key=lambda x: x["last_ts"] or 0, reverse=True)
    return {"subjects": subjects, "count": len(subjects)}


# ---------- admin: live per-user activity stream ("show me everything sara's AI is doing") ----------
@app.get("/api/admin/activity")
def activity(subject: str = "", since: float = 0.0, limit: int = 100,
             claims: dict = Depends(require_admin)):
    """A live feed of what one identity's AI is doing, right now. The console polls with the
    `since` cursor so it only pulls NEW events — during an incident you watch a person's tool
    calls scroll in, instead of hand-cross-referencing the audit page. Without `subject`,
    returns the live feed across everyone."""
    records = audit.tail(2000)
    live = {s["sub"] for s in mcp_server.sessions_list()}

    def _match(r):
        who = r.get("user") or r.get("sub") or r.get("by")
        if subject and who != subject:
            return False
        return (r.get("ts") or 0) > since

    rows = []
    for r in records:
        if not _match(r):
            continue
        rows.append({
            "ts": r.get("ts"), "event": r.get("event"),
            "who": r.get("user") or r.get("sub") or r.get("by"),
            "server": r.get("server"), "tool": r.get("tool"), "tier": r.get("tier"),
            "outcome": r.get("outcome") or r.get("status"),
            "reason": r.get("reason"),
            "classification": r.get("classification"), "pii_masked": r.get("pii_masked"),
            "duration_ms": r.get("duration_ms"), "approval_id": r.get("approval_id"),
        })
    rows = rows[-limit:]
    return {
        "subject": subject or None,
        "live": (subject in live) if subject else None,
        "events": rows,
        "cursor": rows[-1]["ts"] if rows else since,     # feed this back as `since`
        "active_now": sorted(live),
    }


# ---------- admin: is the BACKEND up, not just the process ("is postgres reachable?") ----------
@app.get("/api/admin/health/servers")
async def server_health(claims: dict = Depends(require_admin)):
    """Probe each connector's actual backend — the DB behind postgres, Gitea behind gitea,
    Qdrant behind qdrant — not just whether the server process is alive. This is the
    difference between 'docs shows Online' and 'docs can actually reach its data'."""
    probes = await gw.mcp.health_all()
    summary = {"up": 0, "down": 0, "unknown": 0}
    for p in probes:
        summary[p.get("backend", "unknown")] = summary.get(p.get("backend", "unknown"), 0) + 1
    return {"servers": probes, "summary": summary}


# ---------- admin: see-as / role preview ("what does khalid's AI actually see?") ----------
@app.get("/api/admin/preview")
def preview_visibility(role: str = "", sub: str = "",
                       claims: dict = Depends(require_admin)):
    """Show the exact tool list a role — or a specific operator — would see, WITHOUT being
    them. Answers 'why can't khalid reach the database?' in one click instead of
    reverse-engineering policy.yaml. Read-only: it runs the same visibility logic the
    gateway uses, against synthesized claims."""
    roles = POLICY["roles"]
    if sub:
        u = USERS.get(sub)
        if not u:
            raise HTTPException(404, f"unknown operator '{sub}'")
        role = u["role"]
        clearance = u["clearance"]
        as_who = f"{sub} ({role})"
    else:
        if role not in roles:
            raise HTTPException(400, f"unknown role '{role}'. Roles: {sorted(roles)}")
        clearance = {"admin": "top_secret", "approver": "secret",
                     "analyst": "secret"}.get(role, "restricted")
        as_who = f"role: {role}"

    rc = roles[role]
    synth = {"sub": sub or f"preview:{role}", "role": role, "clearance": clearance}
    visible = gw.visible_tools(synth)
    by_server: dict[str, list] = {}
    for t in visible:
        by_server.setdefault(t["server"], []).append({"tool": t["name"], "tier": t["tier"]})

    # what they CANNOT see, and why — the actually-useful part
    entitled = _role_servers_for(role)
    all_servers = sorted(gw.mcp.servers)
    blocked_servers = ([] if entitled is None
                       else [s for s in all_servers if s not in entitled])
    ceiling = rc.get("max_tool_tier", -1)
    return {
        "as": as_who, "role": role, "clearance": clearance,
        "max_tool_tier": ceiling,
        "visible_tool_count": len(visible),
        "by_server": {s: sorted(v, key=lambda x: (x["tier"], x["tool"]))
                      for s, v in sorted(by_server.items())},
        "blocked_servers": blocked_servers,
        "note": (f"This role can request up to tier {ceiling}. Tools above that tier, and "
                 f"tools on servers not entitled to the role, are invisible."),
    }


def _role_servers_for(role: str):
    from .gateway import _role_servers
    return _role_servers({"role": role})


# ---------- admin: global search ("search for that thing") ----------
@app.get("/api/admin/search")
def global_search(q: str = "", claims: dict = Depends(require_admin)):
    """Search across the WHOLE system — identities, sessions, tools, audit events, API keys,
    OAuth clients, servers — from one box. The header search only filtered the current
    table; this actually looks everywhere and links you to the right page."""
    ql = (q or "").strip().lower()
    if len(ql) < 2:
        return {"query": q, "results": [], "note": "type at least 2 characters"}
    results: list[dict] = []

    def add(kind, label, sub, page, **extra):
        results.append({"kind": kind, "label": label, "detail": sub, "page": page, **extra})

    # operators / identities
    for s, u in USERS.items():
        if ql in s.lower() or ql in (u.get("name", "").lower()):
            add("identity", s, f"{u['name']} · {u['role']} · {u['clearance']}",
                "Identities", target=s)
    # live sessions
    for sess in mcp_server.sessions_list():
        if ql in (sess.get("sub", "").lower()) or ql in (sess.get("id", "").lower()):
            add("session", f"{sess.get('sub')} · {sess.get('id')}",
                f"live MCP session", "Sessions", target=sess.get("sub"))
    # tools + servers (registry)
    for e in gw.registry.entries.values():
        key = f"{e['server']}.{e['tool']}"
        if ql in key.lower() or ql in e["server"].lower():
            add("tool", key, f"tier {e['tier']} · {e['status']}", "Registry")
    # API keys
    for k in apikeys.list_keys():
        if ql in (k.get("name", "").lower()) or ql in (k.get("sub", "").lower()) or ql in k.get("kid", "").lower():
            add("api_key", k.get("name") or k["kid"], f"key for {k.get('sub')} · {k.get('scope')}",
                "API Keys")
    # OAuth clients
    for c in oauth.list_clients():
        if ql in (c.get("client_name", "").lower()) or ql in c["client_id"].lower():
            add("oauth_client", c.get("client_name") or c["client_id"],
                f"{c['active_refresh_tokens']} token(s)", "API Keys")
    # audit events (recent) — match on user/tool/server/event/reason
    seen_audit = 0
    for r in reversed(audit.tail(1500)):
        hay = " ".join(str(r.get(f, "")) for f in
                       ("event", "user", "sub", "by", "server", "tool", "reason", "scope")).lower()
        if ql in hay:
            add("audit", r.get("event", "event"),
                f"{r.get('user') or r.get('by') or ''} · {r.get('tool') or r.get('server') or ''}"
                f" · {_fmt_ts(r.get('ts'))}", "Audit")
            seen_audit += 1
            if seen_audit >= 25:
                break
    order = {"identity": 0, "session": 1, "tool": 2, "api_key": 3, "oauth_client": 4, "audit": 5}
    results.sort(key=lambda x: order.get(x["kind"], 9))
    return {"query": q, "results": results[:60], "count": len(results)}


def _fmt_ts(ts):
    return time.strftime("%m-%d %H:%M", time.localtime(ts)) if ts else ""


@app.get("/api/metrics")
def metrics(claims: dict = Depends(require_admin)):
    """Operational counters for SIEM/dashboards (event tallies, breaker, leases)."""
    from .vault import vault
    return {"event_counts": audit.counts(),
            "circuit_breaker": {s: {"fails": b["fails"], "open": gw._breaker_open(s)}
                                for s, b in gw.breaker_snapshot().items()},
            "active_credential_leases": len(vault.active_leases()),
            "pending_tool_onboarding": len(gw.registry.pending())}


@app.get("/api/health")
def health():
    # Cached full verification (see audit.chain_status): the health endpoint is polled by
    # the container healthcheck and every dashboard refresh, and an O(n) HMAC re-pass over
    # the whole log on each call made the gateway spend its CPU re-proving the same thing.
    from . import statestore
    ok, msg = audit.chain_status()
    state_ok, state_msg = statestore.healthy()
    return {"status": ("ok" if gw.started else "starting") if state_ok else "degraded",
            "auth_mode": auth._MODE,
            "instance": statestore.instance_id(),
            "state_backend": "postgres" if statestore.enabled() else "file",
            "state_ok": state_ok, "state_detail": state_msg,
            "servers": list(gw.mcp.servers.keys()),
            "tools": len(gw.mcp.all_tools()),
            "pending_tools": len(gw.registry.pending()),
            "audit_chain": msg, "audit_chain_ok": ok}


# ---------- static UI ----------
UI_DIR = ROOT / "ui"
app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")


@app.get("/")
def index():
    # index.html must never be cached: it names the current hashed JS/CSS bundle,
    # so a stale copy would pin clients to an old dashboard build. The hashed assets
    # under /ui/assets are content-addressed and safe for the browser to cache.
    return FileResponse(str(UI_DIR / "index.html"),
                        headers={"Cache-Control": "no-cache, must-revalidate"})


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
