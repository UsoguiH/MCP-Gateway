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

import json
import secrets
import threading
import time
import uuid

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import pki
from .config import CONFIG, DATA_DIR

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


def authenticate(cert_pem: str | bytes, nonce: str, signature: bytes) -> str | None:
    """Verify two-factor proof (cert possession + PIN-unlocked signature), mint token."""
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
    if time.time() > expiry or want_thumb != thumb or not pki.verify_cert_chain(cert):
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
    claims = {
        "iss": _ISSUER, "aud": _AUDIENCE, "sub": cn,
        "name": u["name"], "role": u["role"], "clearance": u["clearance"],
        "iat": now, "nbf": now, "exp": now + _ACCESS_TTL, "auth_time": now,
        "jti": uuid.uuid4().hex,
        "amr": ["cert", "pin"],          # two factors actually used
        "acr": _AAL,
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
    if claims["exp"] - claims["iat"] > _ACCESS_TTL:
        return None
    if claims["sub"] in _revoked_subjects:
        return None
    with _lock:
        _gc(_seen_jti)
        _seen_jti[claims["jti"]] = claims["exp"]
    bound = claims.get("cnf", {}).get("x5t#S256")
    if not bound or bound != cert_thumbprint:
        return None
    return claims


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
