"""FastAPI application — HTTP surface for the gateway and UI (spec §11 Phase 3-4)."""
import base64
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import audit, auth, devclient, mcp_server
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
_PROXY_REQUIRED = bool(_PROXY_CFG.get("enabled", False))
_PROXY_SECRET = _secret("MCP_PROXY_SHARED_SECRET", _PROXY_CFG.get("shared_secret") or "")
_PROXY_HEADER = _PROXY_CFG.get("header", "x-proxy-auth").lower()
# Per-IP throttle on auth endpoints (finding M1/M5: raises the cost of lockout-DoS
# and online guessing so a single source can't cheaply spam login attempts).
_login_limiter = RateLimiter(int(CONFIG["auth"].get("login_rate_per_minute", 20)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await gw.startup()
    audit.record("gateway_startup", servers=list(gw.mcp.servers.keys()))
    yield
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
    # L1: Origin validation (MCP spec MUST — DNS-rebinding defense)
    origin = request.headers.get("origin")
    if origin and "*" not in _ALLOWED_ORIGINS and origin not in _ALLOWED_ORIGINS:
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
    password: str
    otp: str = ""            # TOTP authenticator code — required only when auth.require_mfa


class KillReq(BaseModel):
    scope: str


class TierReq(BaseModel):
    tier: int                # 0 read | 1 reversible write | 2 human | 3 two-person


class ChangePwReq(BaseModel):
    old_password: str
    new_password: str


class RevokeReq(BaseModel):
    sub: str


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
    """Production sign-in: username + strong password (+ TOTP MFA when auth.require_mfa).
    Salted PBKDF2 verification, constant-time, with anti-hammering lockout."""
    if auth.locked(req.username):
        audit.record("login_locked_out", user=req.username)
        raise HTTPException(429, "Too many failed attempts. This account is temporarily locked — try again shortly.")
    got = auth.authenticate_password(req.username, req.password, req.otp)
    if not got:
        audit.record("login_failed", user=req.username, locked=auth.locked(req.username))
        raise HTTPException(401, "Incorrect username or password.")
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
    return {"sub": claims["sub"], "name": claims["name"],
            "role": claims["role"], "clearance": claims["clearance"]}


# ---------- tools (REST view for the ops console) ----------
@app.get("/api/tools")
def tools(claims: dict = Depends(current_user)):
    return {"tools": gw.visible_tools(claims)}


# ---------- inbound MCP endpoint (Streamable HTTP) ----------
# This replaces /api/chat: the gateway runs no model. Each colleague's own local
# LLM connects here as an MCP client and drives tool calls through the pipeline.
# Auth is the same TPM-bound, cert-constrained token used everywhere else.
@app.post("/mcp")
async def mcp_post(request: Request, claims: dict = Depends(fresh_password),
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


# ---------- approvals (HITL) ----------
@app.get("/api/approvals")
def list_approvals(claims: dict = Depends(current_user)):
    if not POLICY["roles"].get(claims["role"], {}).get("can_approve"):
        raise HTTPException(403, "approver role required")
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


# ---------- admin: kill switch, audit, registry ----------
@app.get("/api/admin/killswitch")
def killswitch_status(claims: dict = Depends(require_admin)):
    return {"active": kill_switch.active()}


@app.post("/api/admin/killswitch/engage")
def killswitch_engage(req: KillReq, claims: dict = Depends(require_admin)):
    kill_switch.engage(req.scope)
    audit.record("killswitch_engage", scope=req.scope, by=claims["sub"])
    return {"active": kill_switch.active()}


@app.post("/api/admin/killswitch/release")
def killswitch_release(req: KillReq, claims: dict = Depends(require_admin)):
    kill_switch.release(req.scope)
    audit.record("killswitch_release", scope=req.scope, by=claims["sub"])
    return {"active": kill_switch.active()}


@app.get("/api/admin/revocations")
def revocations(claims: dict = Depends(require_admin)):
    return {"revoked": auth.revoked(), "lockouts": auth.lockout_status()}


@app.post("/api/admin/revoke")
def revoke_identity(req: RevokeReq, claims: dict = Depends(require_admin)):
    """Identity kill-switch: block a subject within one request (<1s), independent
    of token lifetime. Rejects new logins and in-flight tokens for that subject."""
    auth.revoke_subject(req.sub)
    audit.record("identity_revoked", sub=req.sub, by=claims["sub"])
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
def audit_tail(claims: dict = Depends(require_admin)):
    ok, msg = audit.verify_chain()
    return {"chain_ok": ok, "chain_status": msg, "records": audit.tail(200)}


@app.get("/api/admin/registry")
def registry(claims: dict = Depends(require_admin)):
    return {"entries": list(gw.registry.entries.values())}


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


@app.get("/api/admin/vault")
def vault_leases(claims: dict = Depends(require_admin)):
    from .vault import vault
    return {"active_leases": vault.active_leases()}


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
    """Per-MCP-server inventory: tool counts, tier spread, breaker state, governance."""
    from .vault import vault
    out = []
    for name, srv in gw.mcp.servers.items():
        entries = [e for e in (gw.registry.get(name, t["name"]) for t in srv.tools) if e]
        b = gw._breaker.get(name, {})
        out.append({
            "name": name, "tools": len(srv.tools),
            "breaker_open": gw._breaker_open(name), "fails": b.get("fails", 0),
            "tiers": {str(t): sum(1 for e in entries if e["tier"] == t) for t in range(4)},
            "active": sum(1 for e in entries if e["status"] == "active"),
            "pending": sum(1 for e in entries if e["status"] == "pending"),
            "quarantined": sum(1 for e in entries if e["status"] == "quarantined"),
            "managed_credentials": vault.manages(name),
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


@app.get("/api/metrics")
def metrics(claims: dict = Depends(require_admin)):
    """Operational counters for SIEM/dashboards (event tallies, breaker, leases)."""
    from .vault import vault
    return {"event_counts": audit.counts(),
            "circuit_breaker": {s: {"fails": b["fails"], "open": gw._breaker_open(s)}
                                for s, b in gw._breaker.items()},
            "active_credential_leases": len(vault.active_leases()),
            "pending_tool_onboarding": len(gw.registry.pending())}


@app.get("/api/health")
def health():
    ok, msg = audit.verify_chain()
    return {"status": "ok" if gw.started else "starting",
            "auth_mode": auth._MODE,
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
