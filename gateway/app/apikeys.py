"""API keys — long-lived, scoped, revocable bearer credentials for the /mcp surface.

For automation (CI pipelines, scheduled jobs) that can't run an OAuth flow. Each
key is bound to an operator (it acts AS that operator, capped by their role) and a
scope that further caps the risk tier it may call:

    read      -> tier 0 only (read-only tools)
    standard  -> tier <= 1 (reads + reversible writes; tier 2/3 still HITL-gated
                 to the operator's role — but capped here at 1 so a leaked CI key
                 can never even queue a destructive action)
    full      -> the operator's own role ceiling applies (no extra cap)

Secrets are shown ONCE at creation and stored only as SHA-256 hashes; the stored
record keeps a display prefix so the admin can match a leaked key to its record.
Format: mcpk_<key_id>_<secret>. Revocation and expiry are enforced on every use,
as is the bound operator's revocation status — revoking a person kills their keys.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time

from . import statestore
from .config import DATA_DIR

_FILE = DATA_DIR / "api_keys.json"
_LOCK = threading.Lock()

SCOPES: dict[str, int | None] = {"read": 0, "standard": 1, "full": None}


def _load() -> dict:
    if statestore.enabled():
        return {kid: doc for kid, doc in
                statestore.all_rows("SELECT kid, doc FROM api_keys")}
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_one(rec: dict):
    statestore.run(
        "INSERT INTO api_keys (kid, doc) VALUES (%s, %s) "
        "ON CONFLICT (kid) DO UPDATE SET doc = EXCLUDED.doc",
        (rec["kid"], json.dumps(rec, ensure_ascii=False)))


def _save(d: dict):
    _FILE.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue(name: str, sub: str, scope: str, ttl_days: int | None,
          created_by: str) -> tuple[dict, str]:
    """Create a key. Returns (stored_record, full_token). The full token is never
    stored and never shown again."""
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {sorted(SCOPES)}")
    kid = secrets.token_hex(6)
    secret_part = secrets.token_urlsafe(32)
    token = f"mcpk_{kid}_{secret_part}"
    now = int(time.time())
    rec = {
        "kid": kid, "name": (name or "unnamed")[:60], "sub": sub, "scope": scope,
        "hash": _hash(token), "prefix": token[:16] + "…",
        "created": now, "created_by": created_by,
        "expires": now + int(ttl_days) * 86400 if ttl_days else None,
        "last_used": None, "revoked": False,
    }
    if statestore.enabled():
        _save_one(rec)
        return rec, token
    with _LOCK:
        d = _load()
        d[kid] = rec
        _save(d)
    return rec, token


def verify(token: str) -> dict | None:
    """Validate an API key and return gateway-shaped claims for the bound operator,
    or None. Enforces revocation, expiry, and the bound subject still existing and
    not being revoked. Adds `tier_cap` for the scope (None = no extra cap)."""
    from . import auth                              # late import: no cycle at module load
    if not token or not token.startswith("mcpk_"):
        return None
    auth.refresh_directory()     # cross-instance operator changes gate key use too
    parts = token.split("_", 2)
    if len(parts) != 3:
        return None
    kid = parts[1]
    if statestore.enabled():
        row = statestore.one("SELECT doc FROM api_keys WHERE kid = %s", (kid,))
        rec = row[0] if row else None
        if not rec or rec.get("revoked"):
            return None
        if not secrets.compare_digest(rec["hash"], _hash(token)):
            return None
        now = int(time.time())
        if rec.get("expires") and now > rec["expires"]:
            return None
        if not rec.get("last_used") or now - rec["last_used"] > 60:
            rec["last_used"] = now
            _save_one(rec)                       # throttled last-used stamp
    else:
        with _LOCK:
            d = _load()
            rec = d.get(kid)
            if not rec or rec.get("revoked"):
                return None
            if not secrets.compare_digest(rec["hash"], _hash(token)):
                return None
            now = int(time.time())
            if rec.get("expires") and now > rec["expires"]:
                return None
            # throttled last-used stamp (avoid a disk write per call)
            if not rec.get("last_used") or now - rec["last_used"] > 60:
                rec["last_used"] = now
                _save(d)
    sub = rec["sub"]
    u = auth.USERS.get(sub)
    if not u or sub in auth.revoked():
        return None
    if auth.session_not_before(sub) > rec["created"]:
        return None                                 # "sign out everywhere" kills older keys too
    return {
        "sub": sub, "name": u["name"], "role": u["role"], "clearance": u["clearance"],
        "iat": rec["created"], "auth_time": rec["created"],
        "amr": ["apikey"], "acr": "aal1", "jti": f"apikey:{kid}",
        "token_use": "api_key", "scope": rec["scope"],
        "tier_cap": SCOPES.get(rec["scope"]),
    }


def revoke(kid: str) -> dict | None:
    if statestore.enabled():
        row = statestore.one("SELECT doc FROM api_keys WHERE kid = %s", (kid,))
        if not row:
            return None
        rec = row[0]
        rec["revoked"] = True
        _save_one(rec)
        return rec
    with _LOCK:
        d = _load()
        rec = d.get(kid)
        if not rec:
            return None
        rec["revoked"] = True
        _save(d)
        return rec


def list_keys() -> list[dict]:
    """All keys, hashes redacted, newest first."""
    with _LOCK:
        d = _load()
    out = [{k: v for k, v in rec.items() if k != "hash"} for rec in d.values()]
    out.sort(key=lambda r: r["created"], reverse=True)
    return out
