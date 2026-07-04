"""FastAPI application — HTTP surface for the gateway and UI (spec §11 Phase 3-4)."""
import base64
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import audit, auth, devclient
from .auth import USERS, verify
from .config import CONFIG, POLICY, ROOT
from .controls import RateLimiter, kill_switch
from .gateway import Gateway

gw = Gateway()

_ALLOWED_ORIGINS = CONFIG["auth"].get("allowed_origins", ["*"])
_DEV_LOGIN = CONFIG["auth"].get("dev_login_enabled", False)
_MAX_BODY = int(CONFIG["auth"].get("max_request_bytes", 65536))
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
    response.headers["MCP-Protocol-Version"] = "2025-11-25"   # A10: advertise spec revision
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


class ChatReq(BaseModel):
    message: str


class KillReq(BaseModel):
    scope: str


class RevokeReq(BaseModel):
    sub: str


def _user_view(claims: dict) -> dict:
    return {"sub": claims["sub"], "name": claims["name"],
            "role": claims["role"], "clearance": claims["clearance"]}


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


@app.post("/api/dev/login")
def dev_login(req: DevLoginReq):
    """DEV ONLY convenience: run the full two-factor challenge/response for a demo
    user. REQUIRES the PIN (second factor) — a username alone is rejected, so
    "just type sarah" no longer works. Disabled in production (dev_login_enabled)."""
    if not _DEV_LOGIN:
        raise HTTPException(404, "not found")
    if req.username not in USERS:
        raise HTTPException(401, "authentication failed")
    if auth.locked(req.username):
        audit.record("login_locked_out", user=req.username)
        raise HTTPException(429, "too many failed attempts; identity temporarily locked")
    got = devclient.obtain_token(req.username, req.pin)
    if not got:
        auth.note_failure(req.username)          # wrong PIN fails locally -> count it here
        audit.record("login_failed", user=req.username, locked=auth.locked(req.username))
        raise HTTPException(401, "authentication failed (wrong PIN or certificate)")
    token, thumb = got
    claims = verify(token, thumb)
    audit.record("login", user=claims["sub"], role=claims["role"], amr=claims["amr"], dev=True)
    return {"token": token, "thumbprint": thumb, "user": _user_view(claims)}


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


# ---------- tools & chat ----------
@app.get("/api/tools")
def tools(claims: dict = Depends(current_user)):
    return {"tools": gw.visible_tools(claims)}


@app.post("/api/chat")
async def chat(req: ChatReq, claims: dict = Depends(current_user)):
    return await gw.handle_turn(claims, req.message)


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


@app.get("/api/admin/vault")
def vault_leases(claims: dict = Depends(require_admin)):
    from .vault import vault
    return {"active_leases": vault.active_leases()}


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
    return FileResponse(str(UI_DIR / "index.html"))


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
