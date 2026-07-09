"""Integration tests for the admin control surface added in the build-out of
items 1-4: real API keys, OAuth client management, operator lifecycle + session
termination, server lifecycle (stop/start/restart/drain/add/remove), and the
in-dashboard notification center.

Runs against a live gateway on 127.0.0.1:8800 (same as test_e2e.py):
    python -m uvicorn app.main:app --port 8800
    python -m pytest tests/test_admin_controls.py -q
"""
import sys
import uuid
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = "http://127.0.0.1:8800"
# Dedicated CI admin (the human admin's password is private). Provision once with:
#   python -c "from app import auth; auth.create_operator('ciadmin','CI Admin (tests)','admin','top_secret'); auth.set_password('ciadmin','Ci!adminPytest2026',must_change=False); auth.enroll_totp('ciadmin')"
ADMIN_USER = "ciadmin"
ADMIN_PW = "Ci!adminPytest2026"


def _up() -> bool:
    try:
        return httpx.get(f"{BASE}/api/health", timeout=3).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="no gateway running on 127.0.0.1:8800")


def _totp(username: str) -> str:
    from app import auth
    return auth.totp_code(username)


def _login(username: str, password: str) -> dict:
    """Full password+TOTP login; returns auth headers."""
    r = httpx.post(f"{BASE}/api/auth/login",
                   json={"username": username, "password": password}, timeout=10)
    assert r.status_code == 200, r.text
    body = r.json()
    if body.get("mfa_required"):
        r = httpx.post(f"{BASE}/api/auth/mfa",
                       json={"mfa_ticket": body["mfa_ticket"], "otp": _totp(username)},
                       timeout=10)
        assert r.status_code == 200, r.text
        body = r.json()
    return {"Authorization": f"Bearer {body['token']}",
            "X-Client-Cert-Thumbprint": body["thumbprint"]}


@pytest.fixture(scope="module")
def admin() -> dict:
    return _login(ADMIN_USER, ADMIN_PW)


def _get(path, headers):
    return httpx.get(f"{BASE}{path}", headers=headers, timeout=15)


def _post(path, headers, json=None):
    return httpx.post(f"{BASE}{path}", headers=headers, json=json, timeout=60)


def _mcp(headers: dict, payload: dict, session: str | None = None):
    h = dict(headers)
    if session:
        h["Mcp-Session-Id"] = session
    return httpx.post(f"{BASE}/mcp", headers=h, json=payload, timeout=60)


def _mcp_init(headers: dict) -> str:
    r = _mcp(headers, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r.status_code == 200, r.text
    return r.headers["Mcp-Session-Id"]


# ─────────────────────────── 1. API keys ────────────────────────────────────
def test_apikey_lifecycle_and_scope_cap(admin):
    # create a read-scoped key acting as admin
    r = _post("/api/admin/apikeys", admin,
              {"name": "pytest-key", "sub": ADMIN_USER, "scope": "read", "ttl_days": 1})
    assert r.status_code == 200, r.text
    body = r.json()
    token = body["token"]
    kid = body["key"]["kid"]
    assert token.startswith("mcpk_")
    assert "hash" not in body["key"]

    # the key appears in the inventory (hash never exposed)
    r = _get("/api/admin/apikeys", admin)
    rows = {k["kid"]: k for k in r.json()["keys"]}
    assert kid in rows and rows[kid]["scope"] == "read" and "hash" not in rows[kid]

    # the key authenticates /mcp: initialize + tools/list work
    key_headers = {"Authorization": f"Bearer {token}"}
    sid = _mcp_init(key_headers)
    r = _mcp(key_headers, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    tools = r.json()["result"]["tools"]
    assert tools, "API key should see tools"

    # scope cap: calling any tier>=1 tool is BLOCKED before dispatch
    higher = next((t for t in tools if (t.get("_meta", {}).get("gateway", {}).get("tier") or 0) >= 1), None)
    assert higher, "need a tier>=1 tool to exercise the scope cap"
    r = _mcp(key_headers, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": higher["name"], "arguments": {}}}, sid)
    res = r.json()["result"]
    assert res["isError"] and "scope" in res["content"][0]["text"]

    # revoke -> the key stops working immediately
    r = _post(f"/api/admin/apikeys/{kid}/revoke", admin)
    assert r.status_code == 200
    r = _mcp(key_headers, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, sid)
    assert r.status_code == 401


def test_apikey_bad_requests(admin):
    assert _post("/api/admin/apikeys", admin,
                 {"name": "x", "sub": "ghost-user", "scope": "read"}).status_code == 404
    assert _post("/api/admin/apikeys", admin,
                 {"name": "x", "sub": ADMIN_USER, "scope": "banana"}).status_code == 400
    assert _post("/api/admin/apikeys/nope/revoke", admin).status_code == 404


# ─────────────────────── 2. OAuth client management ─────────────────────────
def test_oauth_client_list_and_revoke(admin):
    reg = httpx.post(f"{BASE}/oauth/register",
                     json={"redirect_uris": ["http://127.0.0.1:5xyz/cb".replace("xyz", "123")],
                           "client_name": "pytest-client"}, timeout=10)
    assert reg.status_code == 201, reg.text
    cid = reg.json()["client_id"]

    r = _get("/api/admin/oauth/clients", admin)
    ids = [c["client_id"] for c in r.json()["clients"]]
    assert cid in ids

    r = _post(f"/api/admin/oauth/clients/{cid}/revoke", admin)
    assert r.status_code == 200
    r = _get("/api/admin/oauth/clients", admin)
    assert cid not in [c["client_id"] for c in r.json()["clients"]]

    assert _post("/api/admin/oauth/clients/ghost/revoke", admin).status_code == 404


# ───────────────── 3. operator lifecycle + session termination ──────────────
def test_operator_lifecycle(admin):
    sub = "tmp" + uuid.uuid4().hex[:6]
    try:
        # create: returns one-time temp password + TOTP enrollment
        r = _post("/api/admin/operators", admin,
                  {"sub": sub, "name": "Pytest Temp", "role": "employee",
                   "clearance": "restricted"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["temp_password"] and body["totp_secret"] and body["otpauth_uri"]

        # appears in the directory
        ops = {o["sub"]: o for o in _get("/api/admin/operators", admin).json()["operators"]}
        assert sub in ops and ops[sub]["role"] == "employee"

        # the temp password + enrolled TOTP actually sign in
        h = _login(sub, body["temp_password"])
        assert _get("/api/me", h).status_code == 200

        # role change terminates existing sessions and applies the new role
        r = _post(f"/api/admin/operators/{sub}/role", admin,
                  {"role": "analyst", "clearance": "secret"})
        assert r.status_code == 200 and r.json()["role"] == "analyst"
        assert _get("/api/me", h).status_code == 401     # old session is dead

        # fresh login carries the new role
        h = _login(sub, body["temp_password"])
        # sign out everywhere kills it again
        assert _post(f"/api/admin/operators/{sub}/signout", admin).status_code == 200
        assert _get("/api/me", h).status_code == 401

        # forced password reset: old password dies, new one works
        r = _post(f"/api/admin/operators/{sub}/reset_password", admin)
        new_pw = r.json()["temp_password"]
        assert httpx.post(f"{BASE}/api/auth/login",
                          json={"username": sub, "password": body["temp_password"]},
                          timeout=10).status_code == 401
        h = _login(sub, new_pw)
        assert _get("/api/me", h).status_code == 200
    finally:
        _post(f"/api/admin/operators/{sub}/offboard", admin)

    # offboarded: gone from the directory, login refused
    ops = [o["sub"] for o in _get("/api/admin/operators", admin).json()["operators"]]
    assert sub not in ops
    assert httpx.post(f"{BASE}/api/auth/login",
                      json={"username": sub, "password": "whatever123!X"},
                      timeout=10).status_code == 401


def test_operator_guards(admin):
    # cannot offboard yourself; cannot demote yourself out of admin
    assert _post(f"/api/admin/operators/{ADMIN_USER}/offboard", admin).status_code == 400
    r = _post(f"/api/admin/operators/{ADMIN_USER}/role", admin, {"role": "employee"})
    assert r.status_code == 400
    assert _post("/api/admin/operators/ghost/offboard", admin).status_code == 404
    # duplicate create refused
    assert _post("/api/admin/operators", admin,
                 {"sub": ADMIN_USER, "role": "employee", "clearance": "restricted"}).status_code == 400


def test_mcp_session_terminate(admin):
    sid = _mcp_init(admin)
    prefix = sid[:12]
    sessions = _get("/api/admin/sessions", admin).json()["sessions"]
    assert any(s["id"] == prefix for s in sessions)
    r = _post(f"/api/admin/sessions/{prefix}/terminate", admin)
    assert r.status_code == 200 and r.json()["terminated"]["id"] == prefix
    # the session is really gone: next use demands re-initialize
    r = _mcp(admin, {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, sid)
    assert r.json()["error"]["code"] == -32001
    assert _post("/api/admin/sessions/000000000000/terminate", admin).status_code == 404


# ─────────────────────── 4. server lifecycle & drain ────────────────────────
SRV = "reports"          # lightweight local demo server, safe to bounce


def test_server_stop_start_restart(admin):
    def state():
        return {s["name"]: s for s in _get("/api/admin/servers", admin).json()["servers"]}

    try:
        r = _post(f"/api/admin/servers/{SRV}/stop", admin)
        assert r.status_code == 200 and r.json()["state"] == "stopped"
        assert state()[SRV]["state"] == "stopped"

        # a stopped server refuses tool calls (via /mcp with the admin session)
        sid = _mcp_init(admin)
        r = _mcp(admin, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                         "params": {"name": f"{SRV}__list_reports", "arguments": {}}}, sid)
        assert r.json()["result"]["isError"]

        r = _post(f"/api/admin/servers/{SRV}/start", admin)
        assert r.status_code == 200 and r.json()["state"] == "running"
        assert state()[SRV]["state"] == "running"
    finally:
        _post(f"/api/admin/servers/{SRV}/start", admin)

    r = _post(f"/api/admin/servers/{SRV}/restart", admin)
    assert r.status_code == 200 and r.json()["state"] == "running"

    # calls work again after the bounce
    sid = _mcp_init(admin)
    r = _mcp(admin, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                     "params": {"name": f"{SRV}__list_reports", "arguments": {}}}, sid)
    assert not r.json()["result"]["isError"], r.text


def test_server_drain_and_breaker(admin):
    sid = _mcp_init(admin)
    try:
        assert _post(f"/api/admin/servers/{SRV}/drain", admin).json()["drained"] is True
        r = _mcp(admin, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": f"{SRV}__list_reports", "arguments": {}}}, sid)
        res = r.json()["result"]
        assert res["isError"] and "drained" in res["content"][0]["text"]
    finally:
        assert _post(f"/api/admin/servers/{SRV}/undrain", admin).json()["drained"] is False
    r = _mcp(admin, {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                     "params": {"name": f"{SRV}__list_reports", "arguments": {}}}, sid)
    assert not r.json()["result"]["isError"]

    assert _post(f"/api/admin/servers/{SRV}/breaker_reset", admin).status_code == 200
    assert _post("/api/admin/servers/ghost/breaker_reset", admin).status_code == 404


def test_server_add_and_remove(admin):
    name = "pytest-echo"
    try:
        r = _post("/api/admin/servers/add", admin,
                  {"name": name, "command": "python", "args": ["servers/reports_server.py"],
                   "transport": "stdio", "env": {"REPORTS_DIR": "data/reports"}})
        assert r.status_code == 200, r.text
        assert r.json()["tools"] >= 1

        servers = [s["name"] for s in _get("/api/admin/servers", admin).json()["servers"]]
        assert name in servers
    finally:
        r = _post(f"/api/admin/servers/{name}/remove", admin)
    servers = [s["name"] for s in _get("/api/admin/servers", admin).json()["servers"]]
    assert name not in servers

    # invalid specs are refused cleanly
    assert _post("/api/admin/servers/add", admin,
                 {"name": "x__y", "command": "python", "args": ["z.py"]}).status_code == 400
    assert _post("/api/admin/servers/add", admin,
                 {"name": "nohttp", "transport": "http"}).status_code == 400
    r = _post("/api/admin/servers/add", admin,
              {"name": "broken", "command": "python", "args": ["servers/does_not_exist.py"]})
    assert r.status_code == 502
    servers = [s["name"] for s in _get("/api/admin/servers", admin).json()["servers"]]
    assert "broken" not in servers


# ───────────────────────── 5. notification center ───────────────────────────
def test_notifications_flow(admin):
    # the actions above produced notifications (server_stopped, apikey_created, ...)
    r = _get("/api/admin/notifications?limit=50", admin)
    assert r.status_code == 200
    body = r.json()
    assert body["notifications"], "expected notifications from prior admin actions"
    titles = " | ".join(n["title"] for n in body["notifications"])
    assert "Server stopped" in titles or "API key created" in titles

    # mark one read, then all read, then clear the read ones
    first = body["notifications"][0]["id"]
    r = _post("/api/admin/notifications/read", admin, {"ids": [first]})
    assert r.status_code == 200
    r = _post("/api/admin/notifications/read", admin, {"all": True})
    assert r.json()["unread"] == 0
    r = _post("/api/admin/notifications/clear", admin)
    assert r.status_code == 200
    assert _get("/api/admin/notifications", admin).json()["unread"] == 0


# ─────────────────────────── 6. authz on all of it ──────────────────────────
def test_admin_endpoints_require_admin():
    sara = _login("sara", "L!mfd3TySJPa8a")
    for path in ("/api/admin/apikeys", "/api/admin/oauth/clients", "/api/admin/notifications"):
        assert _get(path, sara).status_code == 403
    assert _post("/api/admin/servers/reports/stop", sara).status_code == 403
    assert _post("/api/admin/operators", sara,
                 {"sub": "evil", "role": "admin", "clearance": "top_secret"}).status_code == 403
