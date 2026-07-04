"""Dev PKI — stand-in for the internal CA + HSM + workstation TPM+PIN (plan §1-2).

Bootstraps, on first run, the cryptographic material the auth layer needs so the
gateway is runnable now with NO external CA, HSM, or TPM:

  * an EC P-256 **CA** (dev stand-in for the OpenBao/step-ca internal CA)
  * an EC P-256 **token-signing key** (dev stand-in for OpenBao Transit / YubiHSM;
    in production the private key never leaves the HSM)
  * per-user **client certificates** whose EC private key is **sealed behind the
    user's PIN** (PKCS#8 password-encrypted). This models a **TPM 2.0 key that is
    non-exportable and released only after the PIN is verified in-chip** — the two
    factors of "TPM + PIN": something you have (the key) + something you know (PIN).

Crucially, the gateway/server only ever holds the **public** certificate. It never
holds a user's PIN and never holds the raw private key. The PIN unlocks the key
**locally** (here: to decrypt it) to sign the login challenge; a valid signature
therefore proves BOTH possession of the key AND knowledge of the PIN. This is the
same property Windows Hello for Business / PIV+PIN provide.

PRODUCTION SWAP POINTS: CA -> OpenBao/step-ca (key in HSM); token key -> OpenBao
Transit; user key + PIN -> workstation TPM 2.0 with in-chip PIN verification and
anti-hammering; the `dev_pins.json` file does not exist (the human knows the PIN).
Algorithm is ECDSA P-256 (ES256), not EdDSA (NCA NCS-1:2020 unconfirmed).
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .config import CONFIG, ROOT


def _kek() -> bytes:
    """Key-encryption key for the at-rest CA + token-signing keys (finding C2).
    PRODUCTION: set MCP_GATEWAY_KEK from a secret store, or hold the keys in an HSM
    so they never touch disk. Dev fallback keeps the demo runnable."""
    return os.environ.get("MCP_GATEWAY_KEK", "dev-kek-change-me").encode("utf-8")

_PKI_DIR = ROOT / CONFIG["auth"].get("pki_dir", "pki")
_CA_CERT = _PKI_DIR / "ca.cert.pem"
_CA_KEY = _PKI_DIR / "ca.key.pem"
_SIGN_KEY = _PKI_DIR / "token_signing.key.pem"
_USERS_DIR = _PKI_DIR / "users"

_CURVE = ec.SECP256R1()  # P-256 -> ES256
_ORG = "MCP Gateway (DEV)"

# DEV ONLY: documented demo PINs (like demo passwords) — the user "knows" these.
# There is deliberately NO API that returns them (see finding C1). In production
# there are no demo PINs: each user's PIN is verified in-TPM and never stored here.
_DEMO_PINS = {
    "sara": "481920", "khalid": "736154", "noura": "205841",
    "faisal": "619037", "admin": "950286",
}


# ---------- low-level helpers ----------
def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey, password: bytes | None = None):
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))


def _write_cert(path: Path, cert: x509.Certificate):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def cert_thumbprint(cert: x509.Certificate) -> str:
    """RFC 8705 x5t#S256: base64url(SHA-256(DER(cert))), no padding."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


# ---------- dev PIN (models the user's known PIN; absent in prod) ----------
def get_dev_pin(username: str) -> str:
    """The demo PIN for a user. DEV ONLY — documented, never served by an API.

    Known demo users get a fixed documented PIN; any other (e.g. test) user gets a
    deterministic 6-digit PIN so bootstrap is reproducible without persisting PINs.
    """
    if username in _DEMO_PINS:
        return _DEMO_PINS[username]
    h = int(hashlib.sha256(username.encode()).hexdigest(), 16) % 1_000_000
    return f"{h:06d}"


# ---------- bootstrap ----------
def _ensure_ca():
    if _CA_CERT.exists() and _CA_KEY.exists():
        return
    _PKI_DIR.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(_CURVE)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "MCP Gateway Dev Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _dt.timedelta(minutes=1))
        .not_valid_after(_now() + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_key(_CA_KEY, key, password=_kek())        # encrypted at rest (C2)
    _write_cert(_CA_CERT, cert)


def _ensure_signing_key():
    if _SIGN_KEY.exists():
        return
    _PKI_DIR.mkdir(parents=True, exist_ok=True)
    _write_key(_SIGN_KEY, ec.generate_private_key(_CURVE), password=_kek())   # encrypted at rest (C2)


def load_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    _ensure_ca()
    cert = x509.load_pem_x509_certificate(_CA_CERT.read_bytes())
    key = serialization.load_pem_private_key(_CA_KEY.read_bytes(), password=_kek())
    return cert, key


def signing_key() -> ec.EllipticCurvePrivateKey:
    _ensure_signing_key()
    return serialization.load_pem_private_key(_SIGN_KEY.read_bytes(), password=_kek())


def signing_public_pem() -> bytes:
    return signing_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def ensure_user_cert(username: str) -> x509.Certificate:
    """Ensure a CA-signed client cert + PIN-sealed private key exist for a user.

    Returns the PUBLIC certificate. The private key is written PKCS#8-encrypted
    under the user's PIN (models the TPM sealing the key behind the PIN) and is
    only recoverable via load_user_key(username, pin).
    """
    _USERS_DIR.mkdir(parents=True, exist_ok=True)
    cpath = _USERS_DIR / f"{username}.cert.pem"
    kpath = _USERS_DIR / f"{username}.key.pem"
    if cpath.exists() and kpath.exists():
        return x509.load_pem_x509_certificate(cpath.read_bytes())

    ca_cert, ca_key = load_ca()
    key = ec.generate_private_key(_CURVE)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, username),  # identity binding
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _dt.timedelta(minutes=1))
        .not_valid_after(_now() + _dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=True,
            key_cert_sign=False, crl_sign=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pin = get_dev_pin(username)
    _write_key(kpath, key, password=pin.encode())   # sealed behind the PIN
    _write_cert(cpath, cert)
    return cert


def load_user_key(username: str, pin: str) -> ec.EllipticCurvePrivateKey:
    """Decrypt (unseal) a user's private key with the PIN. Raises on wrong PIN.

    Models the TPM releasing the key only after the PIN is verified. The PIN never
    leaves this local boundary; the gateway never calls this on the real login path.
    """
    kpath = _USERS_DIR / f"{username}.key.pem"
    return serialization.load_pem_private_key(kpath.read_bytes(), password=pin.encode())


def verify_cert_chain(cert: x509.Certificate) -> bool:
    """True if `cert` was issued by our CA and is within its validity window."""
    ca_cert, _ = load_ca()
    now = _now()
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return False
    try:
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return True
    except Exception:
        return False


def load_cert_from_pem(pem: str | bytes) -> x509.Certificate:
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificate(pem)


def cert_common_name(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None
