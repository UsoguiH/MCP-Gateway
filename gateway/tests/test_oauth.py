"""End-to-end tests for the OAuth 2.1 client-access layer (app/oauth.py + the
/oauth and /.well-known endpoints) and the "Connect your AI" APIs.

Runs against a live gateway on 127.0.0.1:8800 (same as test_e2e.py):
    python -m uvicorn app.main:app --port 8800
    python -m pytest tests/test_oauth.py -q

Covers: metadata discovery, dynamic client registration, the full authorization-
code + PKCE flow driven like a real MCP client, PKCE tampering rejection, refresh
rotation (old refresh dies), using an OAuth access token to drive a real tools/call
through /mcp, the 401 WWW-Authenticate discovery hint, and the manual connection
token path.
"""
import base64
import hashlib
import json
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = "http://127.0.0.1:8800"

DEMO_PW = {"sara": "L!mfd3TySJPa8a", "admin": "fn27pwKxev%hKm"}

REDIRECT = "http://127.0.0.1:53100/callback"


def _up() -> bool:
    try:
        return httpx.get(f"{BASE}/api/health", timeout=3).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="no gateway running on 127.0.0.1:8800")


def _mfa_required() -> bool:
    return bool(httpx.get(f"{BASE}/api/auth/info", timeout=5).json().get("mfa_required"))


def _totp(username: str) -> str:
    """Compute a current TOTP the same way the server does (tests share the key)."""
    from app import auth
    return auth.totp_code(username)


def _pkce():
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _register(client_name="pytest-mcp") -> dict:
    r = httpx.post(f"{BASE}/oauth/register",
                   json={"redirect_uris": [REDIRECT], "client_name": client_name}, timeout=10)
    r.raise_for_status()
    return r.json()


def _authorize(client_id, challenge, state="xyz", scope="mcp") -> str:
    """Drive GET (render) then POST (login) of /authorize; return the auth code."""
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
              "code_challenge": challenge, "code_challenge_method": "S256",
              "state": state, "scope": scope}
    g = httpx.get(f"{BASE}/oauth/authorize", params=params, timeout=10)
    # green login-styled authorize page: assert on the form fields, not copy text
    assert g.status_code == 200 and 'name="username"' in g.text and 'action="/oauth/authorize"' in g.text
    form = dict(params)
    form["username"] = "sara"
    form["password"] = DEMO_PW["sara"]
    if _mfa_required():
        form["otp"] = _totp("sara")
    p = httpx.post(f"{BASE}/oauth/authorize", data=form, follow_redirects=False, timeout=10)
    assert p.status_code == 302, p.text
    loc = p.headers["location"]
    q = parse_qs(urlparse(loc).query)
    assert q.get("state") == [state]
    assert "code" in q, f"no code in redirect: {loc}"
    return q["code"][0]


def _token(client_id, code, verifier) -> dict:
    r = httpx.post(f"{BASE}/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": verifier}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------
# metadata discovery
# --------------------------------------------------------------------------

def test_protected_resource_metadata():
    r = httpx.get(f"{BASE}/.well-known/oauth-protected-resource", timeout=5)
    assert r.status_code == 200
    d = r.json()
    assert d["resource"].endswith("/mcp")
    assert d["authorization_servers"]
    assert "mcp" in d["scopes_supported"]


def test_authorization_server_metadata():
    r = httpx.get(f"{BASE}/.well-known/oauth-authorization-server", timeout=5)
    assert r.status_code == 200
    d = r.json()
    assert d["authorization_endpoint"].endswith("/oauth/authorize")
    assert d["token_endpoint"].endswith("/oauth/token")
    assert d["registration_endpoint"].endswith("/oauth/register")
    assert d["code_challenge_methods_supported"] == ["S256"]
    assert "authorization_code" in d["grant_types_supported"]
    assert "refresh_token" in d["grant_types_supported"]


# --------------------------------------------------------------------------
# dynamic client registration
# --------------------------------------------------------------------------

def test_dynamic_client_registration():
    d = _register()
    assert d["client_id"].startswith("mcpc_")
    assert d["redirect_uris"] == [REDIRECT]
    assert d["token_endpoint_auth_method"] == "none"


def test_registration_rejects_bad_redirect():
    r = httpx.post(f"{BASE}/oauth/register",
                   json={"redirect_uris": ["http://evil.example/cb"]}, timeout=10)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"     # non-loopback http refused


# --------------------------------------------------------------------------
# full authorization-code + PKCE flow
# --------------------------------------------------------------------------

def test_full_authorization_code_flow_and_mcp_call():
    client = _register()
    verifier, challenge = _pkce()
    code = _authorize(client["client_id"], challenge)
    tok = _token(client["client_id"], code, verifier)
    assert tok["token_type"] == "Bearer"
    assert tok["access_token"] and tok["refresh_token"]
    assert tok["expires_in"] > 0

    # The OAuth access token must drive a real MCP call — no cert thumbprint header.
    access = tok["access_token"]
    h = {"Authorization": f"Bearer {access}",
         "Accept": "application/json, text/event-stream"}
    init = httpx.post(f"{BASE}/mcp", headers=h, timeout=10, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "pytest", "version": "1"}}})
    assert init.status_code == 200, init.text
    sid = init.headers.get("Mcp-Session-Id")
    assert sid, "initialize must mint a session for the OAuth principal"

    h2 = {**h, "Mcp-Session-Id": sid}
    tl = httpx.post(f"{BASE}/mcp", headers=h2, timeout=10, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert tl.status_code == 200
    names = [t["name"] for t in tl.json()["result"]["tools"]]
    assert any(n.startswith("files__") or n.startswith("docs__") for n in names)


def test_code_is_single_use():
    client = _register()
    verifier, challenge = _pkce()
    code = _authorize(client["client_id"], challenge)
    _token(client["client_id"], code, verifier)          # first use ok
    r = httpx.post(f"{BASE}/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client["client_id"],
        "redirect_uri": REDIRECT, "code_verifier": verifier}, timeout=10)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_pkce_tamper_rejected():
    client = _register()
    _verifier, challenge = _pkce()
    code = _authorize(client["client_id"], challenge)
    r = httpx.post(f"{BASE}/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client["client_id"],
        "redirect_uri": REDIRECT, "code_verifier": "wrong-" + secrets.token_urlsafe(48)},
        timeout=10)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_refresh_rotation():
    client = _register()
    verifier, challenge = _pkce()
    tok = _token(client["client_id"], _authorize(client["client_id"], challenge), verifier)
    r1 = httpx.post(f"{BASE}/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
        "client_id": client["client_id"]}, timeout=10)
    assert r1.status_code == 200
    new = r1.json()
    assert new["access_token"] != tok["access_token"]
    assert new["refresh_token"] != tok["refresh_token"]     # rotated
    # The OLD refresh token must now be dead (replay refused).
    r2 = httpx.post(f"{BASE}/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
        "client_id": client["client_id"]}, timeout=10)
    assert r2.status_code == 400 and r2.json()["error"] == "invalid_grant"


# --------------------------------------------------------------------------
# discovery hint + wrong-credential handling
# --------------------------------------------------------------------------

def test_unauthenticated_mcp_advertises_resource_metadata():
    r = httpx.post(f"{BASE}/mcp", timeout=10, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r.status_code == 401
    www = r.headers.get("WWW-Authenticate", "")
    assert "resource_metadata=" in www and "oauth-protected-resource" in www


def test_bad_password_rerenders_not_redirect():
    client = _register()
    _verifier, challenge = _pkce()
    params = {"response_type": "code", "client_id": client["client_id"],
              "redirect_uri": REDIRECT, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "s", "scope": "mcp",
              "username": "sara", "password": "wrong-password"}
    if _mfa_required():
        params["otp"] = "000000"
    r = httpx.post(f"{BASE}/oauth/authorize", data=params, follow_redirects=False, timeout=10)
    assert r.status_code == 200 and "Sign-in failed" in r.text     # no code leaked


def test_authorize_requires_pkce():
    client = _register()
    r = httpx.get(f"{BASE}/oauth/authorize", params={
        "response_type": "code", "client_id": client["client_id"],
        "redirect_uri": REDIRECT}, follow_redirects=False, timeout=10)
    # missing code_challenge -> redirect back with error (not a login page)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["invalid_request"]


def test_unknown_client_refused():
    r = httpx.get(f"{BASE}/oauth/authorize", params={
        "response_type": "code", "client_id": "mcpc_nope",
        "redirect_uri": REDIRECT, "code_challenge": "x", "code_challenge_method": "S256"},
        timeout=10)
    assert r.status_code == 400 and r.json()["error"] == "invalid_client"


# --------------------------------------------------------------------------
# "Connect your AI" manual token
# --------------------------------------------------------------------------

def _session_login(username="sara"):
    r = httpx.post(f"{BASE}/api/auth/login",
                   json={"username": username, "password": DEMO_PW[username]}, timeout=10)
    r.raise_for_status()
    d = r.json()
    if d.get("mfa_required"):
        d = httpx.post(f"{BASE}/api/auth/mfa",
                       json={"mfa_ticket": d["mfa_ticket"], "otp": _totp(username)},
                       timeout=10).json()
    return d["token"], d["thumbprint"]


def test_connect_status_and_manual_token():
    tok, thumb = _session_login("sara")
    h = {"Authorization": f"Bearer {tok}", "X-Client-Cert-Thumbprint": thumb}

    st = httpx.get(f"{BASE}/api/connect/status", headers=h, timeout=10)
    assert st.status_code == 200 and st.json()["user"] == "sara"

    gen = httpx.post(f"{BASE}/api/connect/token", headers=h,
                     json={"label": "LM Studio"}, timeout=10)
    assert gen.status_code == 200
    d = gen.json()
    assert d["mcp_url"].endswith("/mcp")
    assert d["config"]["mcpServers"]["company-gateway"]["url"].endswith("/mcp")
    manual = d["access_token"]

    # The manual token is a real OAuth access token — it must drive /mcp.
    h2 = {"Authorization": f"Bearer {manual}",
          "Accept": "application/json, text/event-stream"}
    init = httpx.post(f"{BASE}/mcp", headers=h2, timeout=10, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init.status_code == 200 and init.headers.get("Mcp-Session-Id")


def test_connect_token_requires_auth():
    r = httpx.post(f"{BASE}/api/connect/token", json={"label": "x"}, timeout=10)
    assert r.status_code == 401
