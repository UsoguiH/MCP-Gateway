"""Unit tests for the credential vault and API keys (Phase 2, task 7 — test debt).

Both modules guard secrets and were previously only exercised incidentally through e2e
assertions. These pin the properties that matter:

  vault   — a credential is per-(server,user), short-lived, revoked after use, and the
            SECRET ITSELF never appears in a lease listing (the admin UI reads that).
  apikeys — a key is hashed at rest, its scope caps the risk tier it can reach, revocation
            and expiry are enforced, and revoking the PERSON kills their keys.
"""
import time

import pytest

from app import apikeys
from app.vault import Vault


# ───────────────────────────── vault ────────────────────────────────────────
@pytest.fixture
def vault():
    v = Vault()
    v.cfg = {"actions": {"ttl_seconds": 300}}      # one managed server
    v._leases.clear()
    return v


def test_vault_only_manages_configured_servers(vault):
    assert vault.manages("actions") is True
    assert vault.manages("postgres") is False
    assert vault.issue("postgres", "sara") is None   # unmanaged -> no credential injected


def test_credential_is_unique_per_server_user_and_lease(vault):
    a = vault.issue("actions", "sara")
    b = vault.issue("actions", "sara")               # same pair, new call
    c = vault.issue("actions", "khalid")

    assert a["secret"] != b["secret"], "each call must mint a fresh secret"
    assert a["secret"] != c["secret"], "two operators must never share a credential"
    assert a["lease"] != b["lease"] != c["lease"]
    assert a["exp"] > time.time()


def test_active_leases_never_expose_the_secret(vault):
    """The admin console renders this. A secret leaking into a UI payload would undo the
    whole point of injecting credentials outside model context."""
    issued = vault.issue("actions", "sara")
    leases = vault.active_leases()
    assert len(leases) == 1
    row = leases[0]
    assert row["server"] == "actions" and row["user"] == "sara"
    assert row["expires_in"] > 0
    assert "secret" not in row
    assert issued["secret"] not in str(row)


def test_revoke_drops_the_lease(vault):
    lease = vault.issue("actions", "sara")["lease"]
    assert len(vault.active_leases()) == 1
    vault.revoke(lease)
    assert vault.active_leases() == []
    vault.revoke(lease)                              # idempotent: revoking twice is fine


def test_expired_leases_are_swept(vault):
    vault.cfg = {"actions": {"ttl_seconds": 1}}
    vault.issue("actions", "sara")
    assert len(vault.active_leases()) == 1
    for rec in vault._leases.values():               # wind the clock past the TTL
        rec["exp"] = time.time() - 1
    assert vault.active_leases() == []


def test_openbao_provider_fails_loudly_without_hvac(vault, monkeypatch):
    """The production swap point must not silently fall back to dev secrets."""
    vault.provider = "openbao"
    import builtins
    real_import = builtins.__import__

    def _no_hvac(name, *a, **k):
        if name == "hvac":
            raise ModuleNotFoundError("No module named 'hvac'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_hvac)
    with pytest.raises(RuntimeError, match="hvac"):
        vault.issue("actions", "sara")


# ──────────────────────────── api keys ──────────────────────────────────────
@pytest.fixture
def keys(tmp_path, monkeypatch):
    monkeypatch.setattr(apikeys, "_FILE", tmp_path / "api_keys.json")
    return apikeys


def test_key_is_hashed_at_rest_and_shown_once(keys):
    rec, token = keys.issue("ci-pipeline", "admin", "read", ttl_days=7, created_by="ciadmin")
    assert token.startswith("mcpk_")
    assert rec["hash"] != token                       # stored as a digest...
    assert token not in str(keys.list_keys())         # ...and never returned again
    assert rec["prefix"].startswith("mcpk_")          # a stub, so a leaked key can be matched
    listed = keys.list_keys()[0]
    assert "hash" not in listed                       # the admin UI never sees the digest either


def test_scope_caps_the_risk_tier_a_key_can_reach(keys):
    """A leaked read-only CI key must not be able to queue a destructive action — not even
    for approval — regardless of the operator it is bound to."""
    for scope, cap in [("read", 0), ("standard", 1), ("full", None)]:
        _rec, token = keys.issue(f"k-{scope}", "admin", scope, None, "ciadmin")
        claims = keys.verify(token)
        assert claims is not None
        assert claims["tier_cap"] == cap
        assert claims["sub"] == "admin"
        assert claims["token_use"] == "api_key"


def test_bad_and_tampered_tokens_are_refused(keys):
    _rec, token = keys.issue("k", "admin", "read", None, "ciadmin")
    assert keys.verify(token) is not None
    assert keys.verify(token[:-4] + "aaaa") is None    # tampered secret
    assert keys.verify("mcpk_deadbeef_nope") is None   # unknown key id
    assert keys.verify("not-a-key") is None
    assert keys.verify("") is None


def test_revocation_and_expiry_are_enforced(keys):
    rec, token = keys.issue("k", "admin", "read", None, "ciadmin")
    keys.revoke(rec["kid"])
    assert keys.verify(token) is None

    rec2, token2 = keys.issue("k2", "admin", "read", ttl_days=1, created_by="ciadmin")
    assert keys.verify(token2) is not None
    store = keys._load()
    store[rec2["kid"]]["expires"] = int(time.time()) - 1     # wind past its TTL
    keys._save(store)
    assert keys.verify(token2) is None


def test_revoking_the_person_kills_their_keys(keys, monkeypatch):
    """A key acts AS an operator. Offboarding or revoking that operator must not leave a
    working credential behind."""
    from app import auth
    _rec, token = keys.issue("k", "admin", "full", None, "ciadmin")
    assert keys.verify(token) is not None

    monkeypatch.setattr(auth, "revoked", lambda: ["admin"])
    assert keys.verify(token) is None, "a revoked identity's API keys must stop working"


def test_sign_out_everywhere_kills_older_keys(keys, monkeypatch):
    from app import auth
    _rec, token = keys.issue("k", "admin", "full", None, "ciadmin")
    assert keys.verify(token) is not None

    monkeypatch.setattr(auth, "session_not_before", lambda sub: time.time() + 60)
    assert keys.verify(token) is None


def test_unknown_scope_is_refused(keys):
    with pytest.raises(ValueError, match="scope"):
        keys.issue("k", "admin", "superuser", None, "ciadmin")
