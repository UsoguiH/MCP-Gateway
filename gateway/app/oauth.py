"""OAuth 2.1 authorization server for the MCP endpoint (MCP authorization spec).

This fronts the gateway's existing password + MFA login with the standard OAuth
2.1 authorization-code + PKCE flow, so any spec-compliant MCP client (Claude Code
and a growing list of local-AI hosts) gets the "add the URL → a browser opens our
login → the token is handled for you" experience. The security model is unchanged:
the browser page the client opens IS our password+TOTP login; OAuth only makes the
handshake standard so we inherit every client's built-in support.

Implements the pieces an MCP client discovers and uses:
  * Protected Resource Metadata (RFC 9728)      /.well-known/oauth-protected-resource
  * Authorization Server Metadata (RFC 8414)    /.well-known/oauth-authorization-server
  * Dynamic Client Registration (RFC 7591)      POST /oauth/register
  * Authorization endpoint (code + PKCE S256)   GET/POST /oauth/authorize
  * Token endpoint (code exchange + refresh)    POST /oauth/token

Design choices for this deployment:
  * Public clients only (no client secret) — native/desktop MCP hosts. PKCE S256
    is REQUIRED on every authorization request; `plain` is refused.
  * Loopback (127.0.0.1 / localhost) and private custom-scheme redirect URIs are
    allowed for native apps; everything else must be registered exactly.
  * Authorization codes are single-use, 60 s, bound to (client_id, redirect_uri,
    code_challenge). Refresh tokens are opaque, hashed at rest, and ROTATED on
    every use (a replay of an old refresh token is refused).
  * Clients and refresh tokens persist to DATA_DIR so a restart doesn't force every
    employee to re-authorize. Auth codes are in-memory (short-lived by design).

Token minting/verification lives in app/auth.py (mint_oauth_access /
verify_oauth_access) so all signing stays in one place.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import uuid

from . import auth
from .config import CONFIG, DATA_DIR

_A = CONFIG["auth"]
_OAUTH_CFG = _A.get("oauth", {}) or {}
_CODE_TTL = int(_OAUTH_CFG.get("code_ttl_seconds", 60))
_REFRESH_TTL = int(_OAUTH_CFG.get("refresh_ttl_seconds", 60 * 60 * 24 * 30))   # 30 days
_SCOPES_SUPPORTED = ["mcp"]

_CLIENTS_FILE = DATA_DIR / "oauth_clients.json"
_REFRESH_FILE = DATA_DIR / "oauth_refresh.json"

_lock = threading.Lock()
_codes: dict[str, dict] = {}          # code -> {client_id, redirect_uri, challenge, sub, scope, exp}
_clients: dict[str, dict] = {}        # client_id -> {redirect_uris, client_name, created}
_refresh: dict[str, dict] = {}        # sha256(refresh) -> {sub, client_id, scope, exp}


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def _load():
    global _clients, _refresh
    if _CLIENTS_FILE.exists():
        try:
            _clients = json.loads(_CLIENTS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            _clients = {}
    if _REFRESH_FILE.exists():
        try:
            _refresh = json.loads(_REFRESH_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            _refresh = {}
        _gc_refresh()


def _save_clients():
    _CLIENTS_FILE.write_text(json.dumps(_clients, indent=2), encoding="utf-8")


def _save_refresh():
    _REFRESH_FILE.write_text(json.dumps(_refresh, indent=2), encoding="utf-8")


def _gc_refresh():
    now = time.time()
    dead = [k for k, v in _refresh.items() if v.get("exp", 0) < now]
    for k in dead:
        _refresh.pop(k, None)


def _gc_codes():
    now = time.time()
    for k in [k for k, v in _codes.items() if v["exp"] < now]:
        _codes.pop(k, None)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def verify_pkce(verifier: str, challenge: str) -> bool:
    """PKCE S256: base64url(sha256(verifier)) == challenge (RFC 7636)."""
    if not verifier or not challenge:
        return False
    if not (43 <= len(verifier) <= 128):
        return False
    expected = _b64url_no_pad(hashlib.sha256(verifier.encode()).digest())
    return secrets.compare_digest(expected, challenge)


def _is_loopback_uri(uri: str) -> bool:
    return (uri.startswith("http://127.0.0.1") or uri.startswith("http://localhost")
            or uri.startswith("http://[::1]"))


def redirect_uri_allowed(client: dict, redirect_uri: str) -> bool:
    """Exact-match against the client's registered URIs; loopback ports may vary
    (native-app convention) as long as host+path prefix was registered."""
    registered = client.get("redirect_uris", [])
    if redirect_uri in registered:
        return True
    # Loopback: allow any port for a registered loopback host+path (RFC 8252 §7.3).
    if _is_loopback_uri(redirect_uri):
        from urllib.parse import urlparse
        got = urlparse(redirect_uri)
        for r in registered:
            ru = urlparse(r)
            if _is_loopback_uri(r) and ru.hostname == got.hostname and ru.path == got.path:
                return True
    return False


# --------------------------------------------------------------------------
# metadata documents
# --------------------------------------------------------------------------

def protected_resource_metadata(base_url: str) -> dict:
    """RFC 9728 — tells the client which authorization server protects /mcp."""
    base = base_url.rstrip("/")
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": _SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/connect",
    }


def authorization_server_metadata(base_url: str) -> dict:
    """RFC 8414 — the endpoints and capabilities a client needs to run the flow."""
    base = base_url.rstrip("/")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "scopes_supported": _SCOPES_SUPPORTED,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],       # PKCE S256 only (no 'plain')
        "token_endpoint_auth_methods_supported": ["none"],  # public clients + PKCE
    }


# --------------------------------------------------------------------------
# dynamic client registration (RFC 7591)
# --------------------------------------------------------------------------

class OAuthError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status


def register_client(payload: dict) -> dict:
    redirect_uris = payload.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or \
            not all(isinstance(u, str) and u for u in redirect_uris):
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be a non-empty array of strings")
    for u in redirect_uris:
        if not (u.startswith("http://") or u.startswith("https://") or ":/" in u):
            raise OAuthError("invalid_redirect_uri", f"unsupported redirect_uri scheme: {u}")
        if u.startswith("http://") and not _is_loopback_uri(u):
            raise OAuthError("invalid_redirect_uri", "non-loopback redirect_uri must use https")
    client_id = "mcpc_" + secrets.token_urlsafe(16)
    now = int(time.time())
    rec = {
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "client_name": str(payload.get("client_name", ""))[:120],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "created": now,
    }
    with _lock:
        _clients[client_id] = rec
        _save_clients()
    # RFC 7591 response echoes the registration.
    return {**rec, "client_id_issued_at": now}


def get_client(client_id: str) -> dict | None:
    return _clients.get(client_id)


# --------------------------------------------------------------------------
# authorization code
# --------------------------------------------------------------------------

def create_authorization_code(client_id: str, redirect_uri: str, code_challenge: str,
                              sub: str, scope: str) -> str:
    code = secrets.token_urlsafe(32)
    with _lock:
        _gc_codes()
        _codes[code] = {
            "client_id": client_id, "redirect_uri": redirect_uri,
            "challenge": code_challenge, "sub": sub, "scope": scope,
            "exp": time.time() + _CODE_TTL,
        }
    return code


def _consume_code(code: str, client_id: str, redirect_uri: str) -> dict:
    with _lock:
        _gc_codes()
        rec = _codes.pop(code, None)          # single-use: pop regardless
    if not rec:
        raise OAuthError("invalid_grant", "authorization code invalid, expired, or already used")
    if rec["client_id"] != client_id or rec["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "code was issued to a different client or redirect_uri")
    return rec


# --------------------------------------------------------------------------
# refresh tokens (opaque, hashed at rest, rotated on use)
# --------------------------------------------------------------------------

def _issue_refresh(sub: str, client_id: str, scope: str) -> str:
    token = secrets.token_urlsafe(40)
    with _lock:
        _gc_refresh()
        _refresh[_sha256_hex(token)] = {
            "sub": sub, "client_id": client_id, "scope": scope,
            "exp": time.time() + _REFRESH_TTL,
        }
        _save_refresh()
    return token


def _rotate_refresh(refresh_token: str, client_id: str) -> dict:
    key = _sha256_hex(refresh_token)
    with _lock:
        _gc_refresh()
        rec = _refresh.pop(key, None)          # rotation: old token dies now
        if rec:
            _save_refresh()
    if not rec:
        raise OAuthError("invalid_grant", "refresh token invalid, expired, or already used")
    if rec["client_id"] != client_id:
        raise OAuthError("invalid_grant", "refresh token was issued to a different client")
    return rec


# --------------------------------------------------------------------------
# token endpoint grants
# --------------------------------------------------------------------------

def _token_response(sub: str, client_id: str, scope: str) -> dict:
    access, expires_in, _jti = auth.mint_oauth_access(sub, scope=scope)
    refresh = _issue_refresh(sub, client_id, scope)
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh,
        "scope": scope,
    }


def exchange_code(code: str, client_id: str, redirect_uri: str, code_verifier: str) -> dict:
    rec = _consume_code(code, client_id, redirect_uri)
    if not verify_pkce(code_verifier, rec["challenge"]):
        raise OAuthError("invalid_grant", "PKCE verification failed")
    return _token_response(rec["sub"], client_id, rec["scope"])


def refresh_access(refresh_token: str, client_id: str) -> dict:
    rec = _rotate_refresh(refresh_token, client_id)
    if rec["sub"] in auth.revoked():
        raise OAuthError("invalid_grant", "subject revoked")
    return _token_response(rec["sub"], client_id, rec["scope"])


_load()
