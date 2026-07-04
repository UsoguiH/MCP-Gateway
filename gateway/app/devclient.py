"""Dev/test client helper — models the workstation + TPM+PIN side of login.

In production this runs on the user's managed workstation: the PIN is verified by
the TPM, which then signs the challenge with the sealed key; the browser presents
the cert over mTLS. Here we decrypt the PIN-sealed key on disk with the supplied
PIN and sign — exercising the exact server-side auth path without a real TPM.

DEV ONLY. Gated by `auth.dev_login_enabled` in config.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import auth, pki


def sign_challenge(key: ec.EllipticCurvePrivateKey, nonce: str) -> bytes:
    return key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))


def obtain_token(username: str, pin: str | None = None) -> tuple[str, str] | None:
    """Full two-factor challenge/response for a demo user.

    Requires the PIN to unlock the key (second factor). A wrong PIN fails to
    decrypt the key -> no signature -> authentication fails. Returns (token,
    thumbprint) or None.
    """
    cert = pki.ensure_user_cert(username)
    if pin is None:
        pin = pki.get_dev_pin(username)
    try:
        key = pki.load_user_key(username, pin)          # PIN unlocks the key (factor 2)
    except (ValueError, TypeError):
        return None                                     # wrong PIN
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    challenge = auth.make_challenge(cert_pem)
    if not challenge:
        return None
    sig = sign_challenge(key, challenge["nonce"])
    token = auth.authenticate(cert_pem, challenge["nonce"], sig)
    if not token:
        return None
    return token, challenge["thumbprint"]
