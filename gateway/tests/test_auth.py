"""Unit tests for TPM+PIN certificate authentication (no server required)."""
import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import auth, devclient, pki


@pytest.fixture(autouse=True)
def _reset_auth_state():
    auth._fails.clear(); auth._revoked_subjects.clear(); auth._save_revoked()
    yield
    auth._fails.clear(); auth._revoked_subjects.clear(); auth._save_revoked()


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _wrong_pin(username):
    real = pki.get_dev_pin(username)
    return "000000" if real != "000000" else "111111"


def test_full_flow_mints_two_factor_token():
    token, thumb = devclient.obtain_token("khalid")     # PIN defaults to the dev PIN
    claims = auth.verify(token, thumb)
    assert claims["sub"] == "khalid" and claims["role"] == "analyst"
    assert claims["amr"] == ["cert", "pin"]             # BOTH factors recorded
    assert claims["acr"] == "aal2"
    assert "auth_time" in claims
    assert claims["cnf"]["x5t#S256"] == thumb
    assert claims["aud"] == "mcp-gateway"
    assert claims["exp"] - claims["iat"] <= 600


def test_wrong_pin_cannot_unlock_key():
    # The second factor is real: a wrong PIN cannot unseal the key -> no token.
    assert devclient.obtain_token("sara", _wrong_pin("sara")) is None
    # correct PIN works
    assert devclient.obtain_token("sara", pki.get_dev_pin("sara")) is not None


def test_bad_proof_of_possession_rejected():
    cert = pki.ensure_user_cert("noura")
    ch = auth.make_challenge(_pem(cert))
    assert auth.authenticate(_pem(cert), ch["nonce"], b"forged-signature") is None


def test_signature_over_wrong_nonce_rejected():
    cert = pki.ensure_user_cert("noura")
    key = pki.load_user_key("noura", pki.get_dev_pin("noura"))
    ch = auth.make_challenge(_pem(cert))
    wrong = devclient.sign_challenge(key, "0" * 64)
    assert auth.authenticate(_pem(cert), ch["nonce"], wrong) is None


def test_verify_requires_matching_thumbprint():
    token, thumb = devclient.obtain_token("admin")
    assert auth.verify(token, thumb) is not None
    assert auth.verify(token, "wrong-thumbprint") is None
    assert auth.verify(token, None) is None


def test_challenge_can_only_be_used_once():
    cert = pki.ensure_user_cert("faisal")
    key = pki.load_user_key("faisal", pki.get_dev_pin("faisal"))
    ch = auth.make_challenge(_pem(cert))
    sig = devclient.sign_challenge(key, ch["nonce"])
    assert auth.authenticate(_pem(cert), ch["nonce"], sig) is not None
    assert auth.authenticate(_pem(cert), ch["nonce"], sig) is None   # replay of nonce fails


def test_anti_hammering_lockout():
    cert = pki.ensure_user_cert("khalid")
    for i in range(5):                              # threshold = 5
        ch = auth.make_challenge(_pem(cert))
        assert ch, "challenge issues until locked"
        assert auth.authenticate(_pem(cert), ch["nonce"], b"bad-sig-" + bytes([i])) is None
    assert auth.locked("khalid")
    assert auth.make_challenge(_pem(cert)) is None   # locked: no challenge
    # even the correct PIN is refused while locked
    assert devclient.obtain_token("khalid", pki.get_dev_pin("khalid")) is None


def test_revocation_blocks_verify_and_challenge():
    token, thumb = devclient.obtain_token("faisal")
    assert auth.verify(token, thumb) is not None
    auth.revoke_subject("faisal")
    assert auth.verify(token, thumb) is None                       # live token dies
    assert auth.make_challenge(_pem(pki.ensure_user_cert("faisal"))) is None
    auth.unrevoke_subject("faisal")
    assert auth.make_challenge(_pem(pki.ensure_user_cert("faisal"))) is not None


def test_step_up_freshness():
    token, thumb = devclient.obtain_token("noura")
    claims = auth.verify(token, thumb)
    assert auth.step_up_satisfied(claims) is True
    assert auth.step_up_satisfied({**claims, "auth_time": 0}) is False


def test_unknown_user_cert_gets_no_challenge():
    cert = pki.ensure_user_cert("ghost")            # 'ghost' not in USERS
    assert auth.make_challenge(_pem(cert)) is None


def test_untrusted_cert_not_from_our_ca_rejected():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin")])
    now = dt.datetime.now(dt.timezone.utc)
    rogue = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(minutes=1))
             .not_valid_after(now + dt.timedelta(days=1))
             .sign(key, hashes.SHA256()))
    assert pki.verify_cert_chain(rogue) is False
    assert auth.make_challenge(_pem(rogue)) is None


def test_tampered_token_rejected():
    token, thumb = devclient.obtain_token("admin")
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    assert auth.verify(tampered, thumb) is None


def test_private_key_is_pin_sealed_on_disk():
    # regression: the user key must NOT be loadable without the PIN
    pki.ensure_user_cert("sara")
    with pytest.raises(Exception):
        pki.load_user_key("sara", _wrong_pin("sara"))
    assert pki.load_user_key("sara", pki.get_dev_pin("sara")) is not None


def test_no_shared_secret_in_config():
    from app.config import CONFIG
    assert "jwt_secret" not in CONFIG["auth"]
    assert CONFIG["auth"]["alg"] == "ES256"


def test_ca_and_signing_keys_encrypted_at_rest():   # fix C2
    pki.load_ca()                                    # ensure generated
    assert pki._CA_KEY.read_text().startswith("-----BEGIN ENCRYPTED")
    assert pki._SIGN_KEY.read_text().startswith("-----BEGIN ENCRYPTED")


def test_audit_chain_is_hmac_keyed():               # fix M4
    import hashlib
    import json as _json
    import app.audit as A
    rec = {"event": "x", "prev": "0" * 64, "ts": 1.0}
    bare = hashlib.sha256(_json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    assert A._hash(rec) != bare                      # keyed, not a bare hash


def test_revocation_persists_to_disk():             # fix M2
    auth.revoke_subject("khalid")
    assert "khalid" in auth._load_revoked()          # written to disk
    auth.unrevoke_subject("khalid")
    assert "khalid" not in auth._load_revoked()


def test_oidc_mode_validates_and_maps_keycloak_claims(monkeypatch):   # A6
    import time as _t
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    now = int(_t.time())
    tok = pyjwt.encode({"iss": auth._OIDC["issuer"], "aud": auth._OIDC["audience"],
                        "sub": "kc-user", "iat": now, "exp": now + 300, "role": "analyst",
                        "clearance": "secret", "name": "KC User", "amr": ["pwd", "otp"]},
                       priv, algorithm="RS256")
    monkeypatch.setattr(auth, "_resolve_oidc_key", lambda t: key.public_key())
    monkeypatch.setattr(auth, "_MODE", "oidc")
    claims = auth.verify(tok, None)                  # oidc: no cert thumbprint
    assert claims["sub"] == "kc-user" and claims["role"] == "analyst"
    assert claims["clearance"] == "secret" and claims["amr"] == ["pwd", "otp"]
    # a token for the wrong audience is rejected
    bad = pyjwt.encode({"iss": auth._OIDC["issuer"], "aud": "someone-else", "sub": "x",
                        "iat": now, "exp": now + 300}, priv, algorithm="RS256")
    assert auth.verify(bad, None) is None


def test_config_validation_rejects_bad_config():    # A7
    from app.config import ConfigError, _validate
    with pytest.raises(ConfigError):
        _validate({"llm": {"provider": "mock"}}, {"clearance_order": [], "roles": {}})
    with pytest.raises(ConfigError):
        _validate({"llm": {"provider": "banana"}, "auth": {"issuer": "i", "audience": "a", "alg": "ES256"},
                   "gateway": {"host": "h", "port": 1, "max_tool_result_bytes": 1, "taint_min_len": 1},
                   "servers": [{"name": "n", "command": "c", "args": []}]},
                  {"clearance_order": ["public"], "roles": {"r": {"max_tool_tier": 0}}})
