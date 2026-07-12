"""Identity & tokens — TPM+PIN certificate authentication (redesign plan §1-3).

Two-factor, phishing-resistant, non-FIDO, air-gapped:

  * Factor 1 (something you have): the client certificate whose private key is
    TPM-resident and non-exportable.
  * Factor 2 (something you know): a PIN that unlocks/authorizes use of that key
    **locally, inside the TPM** (here: decrypts the PKCS#8 key). The PIN never
    reaches the gateway on the real login path.

Flow: present cert -> gateway returns a nonce -> the client signs the nonce with
its PIN-unlocked key (proof of possession AND of PIN knowledge) -> gateway
verifies the signature against the cert's public key and mints a short-lived
**ES256** session token bound to the cert (RFC 8705 `cnf.x5t#S256`) and carrying
`amr:["cert","pin"]`, an `acr` assurance level, and `auth_time` for step-up.

Hardening: anti-hammering lockout per identity (models TPM lockout), a jti replay
cache, an identity revocation deny-list, and step-up (fresh auth) for Tier-3.

PRODUCTION SWAP POINTS: token-signing key -> OpenBao Transit/HSM; the thumbprint
header -> injected by the mTLS-terminating sidecar (client copies stripped); user
directory -> Keycloak + AD/LDAP X.509 CBA with in-TPM PIN verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
import uuid

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import pki
from .config import CONFIG, DATA_DIR, secret

_A = CONFIG["auth"]
_MODE = _A.get("mode", "builtin")            # builtin (TPM+PIN) | oidc (external Keycloak)
_ISSUER = _A["issuer"]
_AUDIENCE = _A["audience"]
_ALG = _A.get("alg", "ES256")
_OIDC = _A.get("oidc", {})
_oidc_jwks = None                            # lazily-built PyJWKClient (oidc mode)
_ACCESS_TTL = int(_A.get("access_ttl_seconds", 600))
_CHALLENGE_TTL = int(_A.get("challenge_ttl_seconds", 120))
_LEEWAY = int(_A.get("clock_skew_seconds", 30))
_AAL = _A.get("aal", "aal2")
_LOCK_THRESHOLD = int(_A.get("lockout_threshold", 5))
_LOCK_SECONDS = int(_A.get("lockout_seconds", 300))
_STEP_UP_MAX_AGE = int(_A.get("step_up_max_age_seconds", 300))
# MFA (TOTP, RFC 6238) — a third authentication factor layered on cert+PIN.
# PRODUCTION SWAP POINT: per-user enrolled secret from the IdP/OpenBao, not derived.
_MFA_KEY = secret("MCP_MFA_KEY", "dev-mfa-enrollment-key-change-me").encode()
_MFA_STEP = 30
_MFA_DIGITS = 6
# Password login (production): salted PBKDF2-HMAC-SHA256. MFA is layered on top and
# gated by config (`auth.require_mfa`). Hashes live in DATA_DIR/credentials.json —
# never plaintext, never in code.
_REQUIRE_MFA = bool(_A.get("require_mfa", False))
_PBKDF2_ITERS = int(_A.get("pbkdf2_iterations", 600_000))   # OWASP 2024 floor for PBKDF2-SHA256
_CREDS_FILE = DATA_DIR / "credentials.json"

# User directory: role + NDMO clearance, keyed by certificate Common Name.
# NO passwords, NO PINs here — the PIN lives only with the user (in the TPM).
USERS = {
    "sara":   {"role": "employee", "clearance": "restricted",  "name": "Sara (Employee)"},
    "khalid": {"role": "analyst",  "clearance": "secret",      "name": "Khalid (Analyst)"},
    "noura":  {"role": "approver", "clearance": "secret",      "name": "Noura (Approver)"},
    "faisal": {"role": "approver", "clearance": "secret",      "name": "Faisal (Approver)"},
    "admin":  {"role": "admin",    "clearance": "top_secret",  "name": "Admin"},
}

_lock = threading.Lock()
_challenges: dict[str, tuple[str, float]] = {}   # nonce -> (cert_thumbprint, expiry)
_seen_jti: dict[str, float] = {}                 # jti -> expiry
_fails: dict[str, tuple[int, float]] = {}        # subject -> (count, locked_until)

# ---------- operator lifecycle (admin-managed user directory overlay) ----------
# The in-code USERS dict is the seed directory; admins manage operators from the
# dashboard. Changes persist as an overlay in DATA_DIR/operators.json:
#   {"sub": {"name","role","clearance"}}      -> created or role-edited operator
#   {"sub": {"removed": true}}                -> offboarded (even a seed user)
# Applied at import time, so USERS everywhere reflects the managed directory.
_OPS_FILE = DATA_DIR / "operators.json"


def _read_ops_overlay() -> dict:
    try:
        return json.loads(_OPS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_ops_overlay(d: dict):
    _OPS_FILE.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")


def _apply_ops_overlay():
    for sub, rec in _read_ops_overlay().items():
        if rec.get("removed"):
            USERS.pop(sub, None)
        else:
            base = USERS.get(sub, {})
            USERS[sub] = {"role": rec.get("role", base.get("role", "employee")),
                          "clearance": rec.get("clearance", base.get("clearance", "restricted")),
                          "name": rec.get("name", base.get("name", sub)),
                          **{k: v for k, v in base.items()
                             if k not in ("role", "clearance", "name")}}


def create_operator(sub: str, name: str, role: str, clearance: str) -> tuple[bool, str]:
    from .config import POLICY, CLEARANCE_ORDER
    sub = (sub or "").strip().lower()
    if not sub or not sub.replace("-", "").replace("_", "").isalnum() or len(sub) > 32:
        return False, "username must be 1-32 alphanumeric/-/_ characters"
    if sub in USERS:
        return False, f"operator {sub!r} already exists"
    if role not in POLICY["roles"]:
        return False, f"unknown role {role!r}"
    if clearance not in CLEARANCE_ORDER:
        return False, f"unknown clearance {clearance!r}"
    with _lock:
        d = _read_ops_overlay()
        d[sub] = {"name": (name or sub)[:80], "role": role, "clearance": clearance}
        _write_ops_overlay(d)
    _apply_ops_overlay()
    return True, ""


def update_operator(sub: str, role: str | None = None, clearance: str | None = None,
                    name: str | None = None) -> tuple[bool, str]:
    from .config import POLICY, CLEARANCE_ORDER
    u = USERS.get(sub)
    if not u:
        return False, f"unknown operator {sub!r}"
    if role is not None and role not in POLICY["roles"]:
        return False, f"unknown role {role!r}"
    if clearance is not None and clearance not in CLEARANCE_ORDER:
        return False, f"unknown clearance {clearance!r}"
    with _lock:
        d = _read_ops_overlay()
        rec = d.get(sub) or {}
        rec.pop("removed", None)
        rec["name"] = name if name is not None else u["name"]
        rec["role"] = role if role is not None else u["role"]
        rec["clearance"] = clearance if clearance is not None else u["clearance"]
        d[sub] = rec
        _write_ops_overlay(d)
    _apply_ops_overlay()
    return True, ""


def remove_operator(sub: str) -> tuple[bool, str]:
    """Offboard: drop from the directory, purge credential + authenticator, and
    kill every live session/token. Existing tokens die because verify() no longer
    finds the subject; belt-and-braces we also stamp a session not-before."""
    if sub not in USERS:
        return False, f"unknown operator {sub!r}"
    with _lock:
        d = _read_ops_overlay()
        d[sub] = {"removed": True}
        _write_ops_overlay(d)
        USERS.pop(sub, None)
        creds = _read_creds()
        if sub in creds:
            creds.pop(sub)
            _CREDS_FILE.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    unenroll_totp(sub)
    terminate_sessions(sub)
    return True, ""


def reset_password(sub: str) -> tuple[str | None, str]:
    """Admin reset: generate a strong temporary password (returned ONCE), force
    rotation at next login. Returns (temp_password, error)."""
    if sub not in USERS:
        return None, f"unknown operator {sub!r}"
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16))
        if password_strength(pw)[0]:
            break
    ok, msg = set_password(sub, pw, must_change=True)
    return (pw, "") if ok else (None, msg)


# ---------- session termination ("sign out everywhere") ----------
# Tokens are stateless JWTs, so termination is a per-subject not-before stamp:
# any token issued BEFORE the stamp is refused by every verifier (console
# sessions, OAuth access tokens, API keys). Persisted so it survives a restart.
_SESSION_NB_FILE = DATA_DIR / "session_nb.json"


def _load_session_nb() -> dict:
    try:
        return {k: float(v) for k, v in
                json.loads(_SESSION_NB_FILE.read_text(encoding="utf-8")).items()}
    except Exception:
        return {}


_session_nb: dict[str, float] = _load_session_nb()


def session_not_before(sub: str) -> float:
    return _session_nb.get(sub, 0.0)


def terminate_sessions(sub: str):
    """Invalidate every outstanding token for `sub` (issued before now)."""
    with _lock:
        _session_nb[sub] = time.time()
        _SESSION_NB_FILE.write_text(json.dumps(_session_nb), encoding="utf-8")
    try:                                     # refresh tokens die too (late import: no cycle)
        from . import oauth
        oauth.revoke_refresh_for_sub(sub)
    except Exception:
        pass
    try:                                     # live inbound MCP sessions drop immediately
        from . import mcp_server
        mcp_server.terminate_for(sub)
    except Exception:
        pass

# M2: revocations persist to disk so a kill survives a restart.
_REVOKED_FILE = DATA_DIR / "revoked.json"


def _load_revoked() -> set[str]:
    try:
        return set(json.loads(_REVOKED_FILE.read_text(encoding="utf-8")))
    except Exception:
        return set()


def _save_revoked():
    _REVOKED_FILE.write_text(json.dumps(sorted(_revoked_subjects)), encoding="utf-8")


_revoked_subjects: set[str] = _load_revoked()    # identity kill-switch (durable)


# ---------- anti-hammering (models TPM lockout) ----------
def locked(sub: str) -> bool:
    with _lock:
        cnt, until = _fails.get(sub, (0, 0.0))
        return until > time.time()


def _record_fail(sub: str):
    with _lock:
        cnt, until = _fails.get(sub, (0, 0.0))
        cnt += 1
        if cnt >= _LOCK_THRESHOLD:
            _fails[sub] = (cnt, time.time() + _LOCK_SECONDS)
        else:
            _fails[sub] = (cnt, until)


def note_failure(sub: str):
    """Record a failed authentication for anti-hammering (used by endpoints for
    failures that happen before authenticate(), e.g. a wrong PIN on the dev path)."""
    if sub:
        _record_fail(sub)


def _clear_fails(sub: str):
    with _lock:
        _fails.pop(sub, None)


def clear_failures(sub: str):
    """Admin action: clear an identity's failed-attempt counter / lockout."""
    _clear_fails(sub)


def lockout_status() -> dict:
    now = time.time()
    with _lock:
        return {s: {"fails": c, "locked_for": max(0, round(u - now))}
                for s, (c, u) in _fails.items() if c}


# ---------- MFA: TOTP (RFC 6238) — per-user ENROLLED secrets, encrypted at rest ----
# Each operator enrolls a fresh random secret (authenticator app via otpauth:// URI).
# Secrets are AES-256-GCM-encrypted in DATA_DIR/mfa_secrets.json under a key derived
# from MCP_GATEWAY_KEK — the same custody story as the PKI keys (HSM in production).
# The legacy derived-secret path survives ONLY as a dev fallback when
# auth.dev_login_enabled is true; in production an un-enrolled user cannot pass MFA.
_MFA_FILE = DATA_DIR / "mfa_secrets.json"


def _mfa_aes_key() -> bytes:
    kek = secret("MCP_GATEWAY_KEK", "dev-kek-change-me").encode("utf-8")
    return hashlib.sha256(b"mfa-secrets:" + kek).digest()


def _load_mfa() -> dict:
    try:
        return json.loads(_MFA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def enroll_totp(sub: str) -> tuple[str, str]:
    """Enroll (or re-enroll) a per-user TOTP secret. Returns (base32_secret,
    otpauth_uri) for the operator's authenticator app — display once, never store
    the plaintext. Re-enrollment invalidates the previous secret."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = secrets.token_bytes(20)
    nonce = secrets.token_bytes(12)
    blob = nonce + AESGCM(_mfa_aes_key()).encrypt(nonce, raw, sub.encode("utf-8"))
    with _lock:
        d = _load_mfa()
        d[sub] = base64.b64encode(blob).decode()
        _MFA_FILE.write_text(json.dumps(d, indent=2), encoding="utf-8")
    b32 = base64.b32encode(raw).decode().rstrip("=")
    uri = (f"otpauth://totp/MCP-Gateway:{sub}?secret={b32}&issuer=MCP-Gateway"
           f"&algorithm=SHA1&digits={_MFA_DIGITS}&period={_MFA_STEP}")
    return b32, uri


def unenroll_totp(sub: str) -> bool:
    with _lock:
        d = _load_mfa()
        existed = d.pop(sub, None) is not None
        _MFA_FILE.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return existed


def mfa_enrolled(sub: str) -> bool:
    return sub in _load_mfa()


def _totp_secret(sub: str) -> bytes | None:
    """Enrolled secret (decrypted per call so enrollment is visible across
    processes/restarts). Falls back to the deterministic dev secret only in dev
    mode; otherwise un-enrolled == no secret == MFA fails closed."""
    blob = _load_mfa().get(sub)
    if blob:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            raw = base64.b64decode(blob)
            return AESGCM(_mfa_aes_key()).decrypt(raw[:12], raw[12:], sub.encode("utf-8"))
        except Exception:
            return None          # wrong KEK / corrupt entry -> fail closed
    if _A.get("dev_login_enabled", False):   # DEV ONLY fallback (derived secret)
        return hmac.new(_MFA_KEY, ("totp:" + sub).encode(), hashlib.sha256).digest()[:20]
    return None


def _hotp(secret: bytes, counter: int) -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    bincode = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF)
    return str(bincode % (10 ** _MFA_DIGITS)).zfill(_MFA_DIGITS)


def totp_code(sub: str, at: float | None = None) -> str:
    """Current TOTP code for a user (enrollment tooling + tests). Raises if the
    user has no secret."""
    secret = _totp_secret(sub)
    if secret is None:
        raise ValueError(f"no TOTP secret enrolled for {sub!r}")
    return _hotp(secret, int((time.time() if at is None else at) // _MFA_STEP))


def verify_totp(sub: str, code: str, window: int = 1) -> bool:
    """Constant-time verify with a ±`window`-step tolerance for clock skew.
    Fails closed when the user has no enrolled secret."""
    if not code or not str(code).isdigit():
        return False
    secret = _totp_secret(sub)
    if secret is None:
        return False
    now = int(time.time()) // _MFA_STEP
    ok = False
    for w in range(-window, window + 1):
        # evaluate every candidate (no early return) to keep timing flat
        ok |= hmac.compare_digest(_hotp(secret, now + w), str(code))
    return ok


def totp_remaining() -> int:
    return _MFA_STEP - int(time.time()) % _MFA_STEP


# ---------- passwords (salted PBKDF2-HMAC-SHA256, constant-time) ----------
def hash_password(password: str, iterations: int | None = None) -> str:
    """Hash a password with a fresh 16-byte salt. Format: pbkdf2_sha256$iters$salt$hash."""
    iterations = iterations or _PBKDF2_ITERS
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify of a password against a stored PBKDF2 hash."""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk, bytes.fromhex(hash_hex))
    except Exception:
        return False


def password_strength(pw: str) -> tuple[bool, str]:
    """Policy: >=12 chars with lower, upper, digit, and symbol."""
    if not pw or len(pw) < 12:
        return False, "Password must be at least 12 characters."
    missing = [label for ok, label in (
        (any(c.islower() for c in pw), "a lowercase letter"),
        (any(c.isupper() for c in pw), "an uppercase letter"),
        (any(c.isdigit() for c in pw), "a digit"),
        (any(not c.isalnum() for c in pw), "a symbol")) if not ok]
    if missing:
        return False, "Password must include " + ", ".join(missing) + "."
    return True, ""


# ---------- credential store (password lifecycle) ----------
# On-disk format is per-user records: {"hash", "set_at", "must_change"}. Legacy
# flat {"user": "<hash>"} entries are read transparently and upgraded on next write.
_PW_MAX_AGE_DAYS = int(_A.get("password_max_age_days", 0))   # 0 = no expiry


def _read_creds() -> dict:
    try:
        return json.loads(_CREDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _cred_record(raw) -> dict:
    return {"hash": raw} if isinstance(raw, str) else dict(raw or {})


def _load_credentials():
    """Merge password hashes + lifecycle metadata from credentials.json into USERS."""
    for user, raw in _read_creds().items():
        if user in USERS:
            rec = _cred_record(raw)
            USERS[user]["pwd_hash"] = rec.get("hash")
            USERS[user]["pwd_set_at"] = rec.get("set_at", 0)
            USERS[user]["pwd_must_change"] = bool(rec.get("must_change", False))


def _now_epoch() -> int:
    return int(time.time())


def set_password(username: str, new_password: str, must_change: bool = True) -> tuple[bool, str]:
    """Set/rotate a user's password (admin seeding or reset). Enforces strength.
    must_change=True forces the operator to rotate it at first login (default)."""
    if username not in USERS:
        return False, f"unknown user {username!r}"
    ok, msg = password_strength(new_password)
    if not ok:
        return False, msg
    creds = _read_creds()
    with _lock:
        creds[username] = {"hash": hash_password(new_password),
                           "set_at": _now_epoch(), "must_change": must_change}
        _CREDS_FILE.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    _load_credentials()
    return True, ""


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Self-service change: verify the current password, enforce strength, and clear
    the must-change flag. Rejects reuse of the same password."""
    u = USERS.get(username)
    if not u or not u.get("pwd_hash") or not verify_password(old_password, u["pwd_hash"]):
        return False, "current password is incorrect"
    if verify_password(new_password, u["pwd_hash"]):
        return False, "new password must differ from the current one"
    return set_password(username, new_password, must_change=False)


def password_expired(username: str) -> bool:
    u = USERS.get(username) or {}
    if _PW_MAX_AGE_DAYS <= 0:
        return False
    set_at = u.get("pwd_set_at", 0) or 0
    return set_at > 0 and (_now_epoch() - set_at) > _PW_MAX_AGE_DAYS * 86400


def password_change_required(username: str) -> bool:
    u = USERS.get(username) or {}
    return bool(u.get("pwd_must_change")) or password_expired(username)


def password_status(username: str) -> dict:
    u = USERS.get(username) or {}
    set_at = u.get("pwd_set_at", 0) or 0
    return {"has_password": bool(u.get("pwd_hash")),
            "set_at": set_at,
            "age_days": round((_now_epoch() - set_at) / 86400, 1) if set_at else None,
            "max_age_days": _PW_MAX_AGE_DAYS or None,
            "expired": password_expired(username),
            "must_change": bool(u.get("pwd_must_change")),
            "change_required": password_change_required(username)}


_apply_ops_overlay()                     # admin-managed operators join/leave the directory
_load_credentials()
# A real hash to run even on unknown users, so login timing doesn't leak who exists.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def authenticate_password(username: str, password: str, otp: str = "",
                          require_mfa: bool | None = None) -> tuple[str, str] | None:
    """Production sign-in: verify a strong password (+ TOTP MFA if required) and mint
    a short-lived session token bound to a per-session secret the client replays
    (bearer-binding). Returns (token, binding) or None. Constant-time on the
    password; every failure feeds the anti-hammering lockout."""
    require_mfa = _REQUIRE_MFA if require_mfa is None else require_mfa
    u = USERS.get(username)
    if not u or username in _revoked_subjects or locked(username):
        verify_password(password or "", _DUMMY_HASH)     # flatten user-enumeration timing
        return None
    stored = u.get("pwd_hash")
    if not stored or not verify_password(password, stored):
        _record_fail(username)
        return None
    if require_mfa and not verify_totp(username, otp):
        _record_fail(username)
        return None
    _clear_fails(username)
    amr = ["pwd"] + (["otp"] if require_mfa else [])
    return _mint_session(username, amr)


# ---------- two-layer sign-in: password (layer 1) THEN TOTP (layer 2) ----------
# Layer 1 is verified before the client is ever shown the MFA step, so a wrong
# username/password is rejected immediately and never advances to layer 2. Layer 2
# requires a short-lived ticket that is only issued when layer 1 passed, so the
# password step cannot be skipped.
_MFA_TICKET_TTL = int(_A.get("challenge_ttl_seconds", 120))


def verify_password_layer(username: str, password: str) -> bool:
    """Layer 1: verify username + password only (no token, no MFA). Constant-time;
    a wrong password feeds the anti-hammering lockout. Fails-closed for unknown,
    revoked, or locked identities."""
    u = USERS.get(username)
    if not u or username in _revoked_subjects or locked(username):
        verify_password(password or "", _DUMMY_HASH)     # flatten user-enumeration timing
        return False
    stored = u.get("pwd_hash")
    if not stored or not verify_password(password, stored):
        _record_fail(username)
        return False
    return True


def issue_mfa_ticket(username: str) -> str:
    """Short-lived proof that layer 1 (password) passed. Required to attempt layer 2."""
    now = int(time.time())
    claims = {"iss": _ISSUER, "aud": _AUDIENCE, "sub": username, "purpose": "mfa",
              "iat": now, "nbf": now, "exp": now + _MFA_TICKET_TTL, "jti": uuid.uuid4().hex}
    return jwt.encode(claims, pki.signing_key(), algorithm=_ALG)


def verify_mfa_ticket(ticket: str) -> str | None:
    """Validate a layer-1 ticket; return the username it authorizes, or None."""
    try:
        c = jwt.decode(ticket, pki.signing_public_pem(), algorithms=[_ALG],
                       issuer=_ISSUER, audience=_AUDIENCE, leeway=_LEEWAY,
                       options={"require": ["exp", "iat", "nbf", "sub", "purpose", "jti"]})
    except jwt.PyJWTError:
        return None
    if c.get("purpose") != "mfa":
        return None
    return c["sub"]


def complete_mfa(username: str, otp: str) -> tuple[str, str] | None:
    """Layer 2: for a password-verified user, verify the TOTP code and mint the
    session. A wrong code feeds the lockout."""
    if username not in USERS or username in _revoked_subjects or locked(username):
        return None
    if not verify_totp(username, otp):
        _record_fail(username)
        return None
    _clear_fails(username)
    return _mint_session(username, ["pwd", "otp"])


def finish_password_only(username: str) -> tuple[str, str] | None:
    """When MFA is disabled: mint the session right after layer 1."""
    if username not in USERS:
        return None
    _clear_fails(username)
    return _mint_session(username, ["pwd"])


def session_ttl() -> int:
    """Console session lifetime, from the runtime settings overlay (admin-editable)."""
    try:
        from . import settings
        return int(settings.get("session", "ttl_seconds"))
    except Exception:
        return _ACCESS_TTL


def session_absolute_max() -> int:
    """Hard cap on a session's total age, however active the operator is."""
    try:
        from . import settings
        return int(settings.get("session", "absolute_seconds"))
    except Exception:
        return 28800


# Belt-and-braces ceiling on any session token's declared lifetime. The signing key is what
# actually prevents forgery; this bounds the damage if a token is ever minted with an absurd
# exp. It is deliberately NOT the configured TTL: lowering the TTL should shorten the NEXT
# session, not eject everyone who is currently signed in.
_TTL_HARD_CEILING = 86_400


def _mint_session(username: str, amr: list[str],
                  pwd_change_required: bool | None = None,
                  auth_time: int | None = None) -> tuple[str, str]:
    """Mint a short-lived ES256 session token bound to a per-session secret the
    client replays (bearer-binding). Shared by password login, refresh, and the dev bypass.

    `auth_time` is carried FORWARD across refreshes: it records when the operator actually
    authenticated, so the absolute session cap cannot be extended indefinitely by refreshing.
    """
    u = USERS[username]
    now = int(time.time())
    binding = secrets.token_hex(32)                      # session secret; client replays it
    claims = {
        "iss": _ISSUER, "aud": _AUDIENCE, "sub": username,
        "name": u["name"], "role": u["role"], "clearance": u["clearance"],
        "iat": now, "nbf": now, "exp": now + session_ttl(),
        "auth_time": int(auth_time or now),
        "jti": uuid.uuid4().hex, "amr": amr,
        "acr": "aal2" if "otp" in amr else "aal1",
        "cnf": {"x5t#S256": binding},                    # token usable only with the binding
        "pwd_change_required": password_change_required(username)
                               if pwd_change_required is None else pwd_change_required,
    }
    return jwt.encode(claims, pki.signing_key(), algorithm=_ALG), binding


class SessionExpired(Exception):
    """The absolute session cap is reached — the operator must authenticate again."""


def refresh_session(claims: dict) -> tuple[str, str, int]:
    """Renew a live session (A12).

    The console used to hold one fixed-lifetime token and simply die when it expired —
    mid-approval, with no warning. Now an active operator's session is renewed, which makes
    `ttl_seconds` behave as an IDLE timeout: stop working and the token lapses on its own.
    The renewal keeps the original `auth_time`, so `absolute_seconds` still forces a real
    re-authentication no matter how long someone stays active.

    Returns (token, binding, expires_in). Raises SessionExpired past the absolute cap.
    """
    sub = claims["sub"]
    authenticated_at = int(claims.get("auth_time") or claims.get("iat") or 0)
    age = int(time.time()) - authenticated_at
    cap = session_absolute_max()
    if age >= cap:
        raise SessionExpired(
            f"this session has been open for {age // 3600}h — sign in again "
            f"(the maximum is {cap // 3600}h)")
    token, binding = _mint_session(sub, claims.get("amr", ["pwd"]),
                                   auth_time=authenticated_at)
    return token, binding, session_ttl()


# DEV ONLY: bypass sign-in and mint a session directly, gated by config. Never
# enable in production (the tripwire in config.py flags it). Lets the dashboard be
# opened immediately without a password or authenticator code during local work.
_QUICK_LOGIN = bool(_A.get("dev_quick_login", False))


def dev_quick_session(username: str = "admin") -> tuple[str, str] | None:
    if not _QUICK_LOGIN or username not in USERS:
        return None
    # never forces a password change on the bypass path
    return _mint_session(username, ["dev"], pwd_change_required=False)


# ---------- challenge / response ----------
def make_challenge(cert_pem: str | bytes) -> dict | None:
    try:
        cert = pki.load_cert_from_pem(cert_pem)
    except Exception:
        return None
    if not pki.verify_cert_chain(cert):
        return None
    cn = pki.cert_common_name(cert)
    if cn not in USERS or cn in _revoked_subjects or locked(cn):
        return None
    thumb = pki.cert_thumbprint(cert)
    nonce = secrets.token_hex(32)
    with _lock:
        _gc(_challenges)
        _challenges[nonce] = (thumb, time.time() + _CHALLENGE_TTL)
    return {"nonce": nonce, "thumbprint": thumb}


def authenticate(cert_pem: str | bytes, nonce: str, signature: bytes,
                 amr_extra: list | None = None) -> str | None:
    """Verify proof (cert possession + PIN-unlocked signature), mint token. Extra
    factors already verified by the caller (e.g. `["otp"]`) are recorded in `amr`."""
    try:
        cert = pki.load_cert_from_pem(cert_pem)
    except Exception:
        return None
    cn = pki.cert_common_name(cert)
    if cn in _revoked_subjects or (cn and locked(cn)):
        return None
    thumb = pki.cert_thumbprint(cert)

    with _lock:
        entry = _challenges.pop(nonce, None)
    if not entry:
        return None
    want_thumb, expiry = entry
    if time.time() > expiry or not hmac.compare_digest(want_thumb, thumb) or not pki.verify_cert_chain(cert):
        if cn:
            _record_fail(cn)
        return None

    # Proof of possession + PIN: only a caller who unlocked the key with the PIN
    # can produce a signature that verifies against the cert's public key.
    try:
        cert.public_key().verify(signature, nonce.encode(), ec.ECDSA(hashes.SHA256()))
    except Exception:
        if cn:
            _record_fail(cn)     # wrong PIN or forged sig -> counts toward lockout
        return None

    u = USERS.get(cn)
    if not u:
        return None
    _clear_fails(cn)

    now = int(time.time())
    amr = ["cert", "pin"] + [f for f in (amr_extra or []) if f not in ("cert", "pin")]
    claims = {
        "iss": _ISSUER, "aud": _AUDIENCE, "sub": cn,
        "name": u["name"], "role": u["role"], "clearance": u["clearance"],
        "iat": now, "nbf": now, "exp": now + _ACCESS_TTL, "auth_time": now,
        "jti": uuid.uuid4().hex,
        "amr": amr,                      # factors actually used (cert, pin[, otp])
        "acr": "aal3" if "otp" in amr else _AAL,   # MFA raises the assurance level
        "cnf": {"x5t#S256": thumb},      # RFC 8705: token bound to this certificate
    }
    return jwt.encode(claims, pki.signing_key(), algorithm=_ALG)


def verify(token: str, cert_thumbprint: str | None) -> dict | None:
    """Validate a session token. In `oidc` mode, tokens come from Keycloak; in
    `builtin` mode, from this gateway (cert-bound)."""
    if _MODE == "oidc":
        return verify_oidc(token)
    return _verify_builtin(token, cert_thumbprint)


def _resolve_oidc_key(token: str):
    """Resolve the external IdP signing key for a token (via JWKS). Isolated so
    tests can inject a key without a live Keycloak."""
    global _oidc_jwks
    from jwt import PyJWKClient
    if _oidc_jwks is None:
        _oidc_jwks = PyJWKClient(_OIDC["jwks_url"], cache_keys=True)
    return _oidc_jwks.get_signing_key_from_jwt(token).key


def verify_oidc(token: str) -> dict | None:
    """Validate an external (Keycloak) JWT and map its claims to the gateway shape."""
    try:
        key = _resolve_oidc_key(token)
        claims = jwt.decode(
            token, key, algorithms=_OIDC.get("algorithms", ["RS256", "ES256"]),
            issuer=_OIDC["issuer"], audience=_OIDC["audience"], leeway=_LEEWAY,
            options={"require": ["exp", "iat", "sub"]},
        )
    except Exception:
        return None
    sub = claims.get("sub")
    if not sub or sub in _revoked_subjects:
        return None
    return {
        "sub": sub,
        "name": claims.get(_OIDC.get("name_claim", "name"), sub),
        "role": claims.get(_OIDC.get("role_claim", "role"), ""),
        "clearance": claims.get(_OIDC.get("clearance_claim", "clearance"), "public"),
        "amr": claims.get("amr", []),
        "acr": claims.get("acr", ""),
        "auth_time": claims.get("auth_time", claims.get("iat", 0)),
    }


def _verify_builtin(token: str, cert_thumbprint: str | None) -> dict | None:
    try:
        claims = jwt.decode(
            token, pki.signing_public_pem(), algorithms=[_ALG],
            issuer=_ISSUER, audience=_AUDIENCE, leeway=_LEEWAY,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub",
                                 "jti", "cnf", "amr", "auth_time"]},
        )
    except jwt.PyJWTError:
        return None
    if claims["exp"] - claims["iat"] > _TTL_HARD_CEILING:
        return None                       # absurd lifetime: reject regardless of settings
    # The absolute cap applies on every request, not just at refresh: an operator who has
    # been signed in longer than the cap must re-authenticate even if their current token
    # has not expired yet.
    if int(time.time()) - int(claims.get("auth_time") or claims["iat"]) > session_absolute_max():
        return None
    if claims["sub"] in _revoked_subjects:
        return None
    if claims["iat"] < session_not_before(claims["sub"]):
        return None                       # admin terminated this subject's sessions
    if claims["sub"] not in USERS:
        return None                       # offboarded operator: tokens die immediately
    with _lock:
        _gc(_seen_jti)
        _seen_jti[claims["jti"]] = claims["exp"]
    bound = claims.get("cnf", {}).get("x5t#S256")
    if not bound or not cert_thumbprint or not hmac.compare_digest(bound, cert_thumbprint):
        return None
    return claims


# ---------- OAuth 2.1 access tokens (MCP client authorization) ----------
# These are the tokens issued to a colleague's local-AI MCP client through the
# OAuth authorization-code flow (app/oauth.py). Unlike the interactive session
# token above, an OAuth access token is NOT cert-thumbprint bound: a standard MCP
# client (e.g. Claude Code) sends only `Authorization: Bearer`. Its protection is
# the OAuth model — PKCE at issuance, short TTL, rotated refresh tokens, per-jti
# revocability, subject revocation — over the mTLS transport that already binds the
# channel to an enrolled device. Marked `token_use:"mcp_access"` so it can never be
# confused with (or substituted for) a cert-bound console session token.
_OAUTH_ACCESS_TTL = int((_A.get("oauth", {}) or {}).get("access_ttl_seconds", 3600))
_revoked_token_jti: dict[str, float] = {}       # jti -> exp, explicit access-token kill


def mint_oauth_access(sub: str, scope: str = "mcp", ttl: int | None = None) -> tuple[str, int, str]:
    """Mint a signed OAuth access token for `sub`. Returns (jwt, expires_in, jti)."""
    if sub not in USERS:
        raise ValueError("unknown subject")
    u = USERS[sub]
    now = int(time.time())
    ttl = int(ttl or _OAUTH_ACCESS_TTL)
    jti = uuid.uuid4().hex
    claims = {
        "iss": _ISSUER, "aud": _AUDIENCE, "sub": sub,
        "name": u["name"], "role": u["role"], "clearance": u["clearance"],
        "iat": now, "nbf": now, "exp": now + ttl, "auth_time": now,
        "jti": jti, "amr": ["pwd", "otp"] if _REQUIRE_MFA else ["pwd"],
        "acr": "aal2" if _REQUIRE_MFA else "aal1",
        "token_use": "mcp_access", "scope": scope,
    }
    return jwt.encode(claims, pki.signing_key(), algorithm=_ALG), ttl, jti


def verify_oauth_access(token: str) -> dict | None:
    """Validate an OAuth access token (no cert binding). Rejects cert-bound session
    tokens (they carry `cnf`, not `token_use:mcp_access`) and vice-versa."""
    try:
        claims = jwt.decode(
            token, pki.signing_public_pem(), algorithms=[_ALG],
            issuer=_ISSUER, audience=_AUDIENCE, leeway=_LEEWAY,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
        )
    except jwt.PyJWTError:
        return None
    if claims.get("token_use") != "mcp_access":
        return None
    if claims["sub"] in _revoked_subjects:
        return None
    if claims["jti"] in _revoked_token_jti:
        return None
    if claims["iat"] < session_not_before(claims["sub"]):
        return None                       # admin terminated this subject's sessions
    if claims["sub"] not in USERS:
        return None                       # offboarded operator
    return claims


def revoke_oauth_jti(jti: str, exp: float):
    with _lock:
        _gc(_revoked_token_jti)
        _revoked_token_jti[jti] = exp


def step_up_satisfied(claims: dict, max_age: int = _STEP_UP_MAX_AGE) -> bool:
    """True if the caller authenticated recently enough for a high-risk action."""
    return (int(time.time()) - int(claims.get("auth_time", 0))) <= max_age


def has_factor(claims: dict, factor: str) -> bool:
    return factor in (claims.get("amr") or [])


# ---------- revocation (identity kill-switch) ----------
def revoke_subject(sub: str):
    with _lock:
        _revoked_subjects.add(sub)
        _save_revoked()


def unrevoke_subject(sub: str):
    with _lock:
        _revoked_subjects.discard(sub)
        _save_revoked()


def revoked() -> list[str]:
    with _lock:
        return sorted(_revoked_subjects)


def _gc(d: dict):
    now = time.time()
    for k in [k for k, v in d.items() if (v[1] if isinstance(v, tuple) else v) < now]:
        d.pop(k, None)
