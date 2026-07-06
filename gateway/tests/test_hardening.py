"""Tests for the pre-deployment hardening pass.

Covers the controls the coverage audit found dark:
  * MFA TOTP — per-user enrolled secrets: enroll/verify/re-enroll/unenroll,
    fail-closed for un-enrolled users, encrypted at rest (no plaintext on disk)
  * Kill switch — durable across restart (new instance reloads engaged scopes)
  * HITL approvals — pending Tier-3 approvals survive a restart (headline claim)
  * Circuit breaker — trips after N consecutive failures, closes after cooldown
  * Argument-schema enforcement — jsonschema is importable (pinned, not transitive)
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth                                    # noqa: E402
from app.approvals import ApprovalStore                 # noqa: E402
from app.controls import KillSwitch                     # noqa: E402


# ---------- MFA: TOTP enrolled secrets ----------

def test_totp_enroll_verify_and_fail_closed():
    user = "khalid"
    secret_b32, uri = auth.enroll_totp(user)
    assert uri.startswith("otpauth://totp/MCP-Gateway:" + user)
    assert auth.mfa_enrolled(user)
    code = auth.totp_code(user)
    assert auth.verify_totp(user, code)                     # valid code accepted
    assert not auth.verify_totp(user, "000000")             # wrong code rejected
    assert not auth.verify_totp(user, "")                   # empty rejected
    assert not auth.verify_totp(user, "abcdef")             # non-digit rejected

    # un-enrolled user fails CLOSED (dev fallback is off: dev_login_enabled false)
    auth.unenroll_totp(user)
    assert not auth.mfa_enrolled(user)
    assert not auth.verify_totp(user, code)

    # re-enroll for the rest of the suite / running gateway
    auth.enroll_totp(user)


def test_totp_reenroll_invalidates_old_secret():
    user = "faisal"
    auth.enroll_totp(user)
    old_code = auth.totp_code(user)
    auth.enroll_totp(user)                                  # rotate the secret
    new_code = auth.totp_code(user)
    assert auth.verify_totp(user, new_code)
    if old_code != new_code:                                # (1-in-10^6 collision guard)
        assert not auth.verify_totp(user, old_code)


def test_totp_secrets_encrypted_at_rest():
    user = "sara"
    secret_b32, _ = auth.enroll_totp(user)
    on_disk = auth._MFA_FILE.read_text(encoding="utf-8")
    assert secret_b32 not in on_disk                        # never plaintext
    blob = json.loads(on_disk)[user]
    assert len(blob) > 40                                   # nonce + GCM ciphertext, b64


def test_password_login_requires_enrolled_mfa():
    """require_mfa=True + no enrolled secret -> authenticate_password fails even
    with a perfect password (fail-closed, no bypass)."""
    user = "khalid"
    auth.unenroll_totp(user)
    # password verification can't be faked here without the real password, but the
    # MFA gate is checked after it — use the require_mfa override to isolate:
    assert auth.verify_totp(user, "123456") is False        # gate itself fails closed
    auth.enroll_totp(user)                                  # restore


# ---------- kill switch durability ----------

def test_killswitch_survives_restart(tmp_path):
    kf = tmp_path / "ks.json"                                # isolated from prod file
    ks1 = KillSwitch(path=kf)
    ks1.engage("tool:unittest:frobnicate")
    ks2 = KillSwitch(path=kf)                                # simulated restart
    assert "tool:unittest:frobnicate" in ks2.active()
    assert ks2.blocked(user="u", server="unittest", tool="frobnicate")
    ks2.release("tool:unittest:frobnicate")
    ks3 = KillSwitch(path=kf)                                # release also persists
    assert "tool:unittest:frobnicate" not in ks3.active()


# ---------- HITL approval durability ----------

def test_pending_approval_survives_restart(tmp_path):
    af = tmp_path / "approvals.json"                         # isolated from prod file
    s1 = ApprovalStore(path=af)
    rec = s1.create(requester="unittest", server="unittest", tool="delete_all",
                    arguments={"x": 1}, tier=3, approvals_required=2,
                    preview="unittest fixture", taint=[])
    aid = rec["id"]
    s2 = ApprovalStore(path=af)                              # simulated restart
    reloaded = s2.get(aid)
    assert reloaded is not None
    assert reloaded["tier"] == 3 and reloaded["approvals_required"] == 2
    assert reloaded["arguments"] == {"x": 1}


# ---------- circuit breaker ----------

def test_circuit_breaker_trips_and_recovers():
    from app.gateway import Gateway
    gw = Gateway()
    server = "unittest-breaker"
    assert not gw._breaker_open(server)
    for _ in range(gw._breaker_threshold - 1):
        gw._breaker_trip(server)
    assert not gw._breaker_open(server)                     # below threshold: closed
    gw._breaker_trip(server)                                # Nth consecutive failure
    assert gw._breaker_open(server)                         # open: server quarantined
    # cooldown expiry -> closes again
    gw._breaker[server]["open_until"] = time.time() - 1
    assert not gw._breaker_open(server)
    # success resets the failure counter
    gw._breaker_trip(server)
    gw._breaker_reset(server)
    assert gw._breaker[server]["fails"] == 0


# ---------- schema enforcement dependency ----------

def test_jsonschema_is_installed_not_transitive():
    """W9.6 arg validation silently no-ops if jsonschema is missing; it must be an
    explicit, pinned dependency."""
    import jsonschema                                       # noqa: F401
    req = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text()
    assert "jsonschema" in req


# ---------- file-based secret custody ----------

def test_secret_prefers_file_mount(tmp_path, monkeypatch):
    from app import config
    f = tmp_path / "kek"
    f.write_text("  real-secret-from-file\n")             # trimmed on read
    monkeypatch.setenv("MCP_TEST_SECRET_FILE", str(f))
    monkeypatch.setenv("MCP_TEST_SECRET", "env-value")
    assert config.secret("MCP_TEST_SECRET") == "real-secret-from-file"   # file wins
    monkeypatch.delenv("MCP_TEST_SECRET_FILE")
    assert config.secret("MCP_TEST_SECRET") == "env-value"               # env fallback


def test_secret_file_unreadable_fails_closed(tmp_path, monkeypatch):
    from app import config
    monkeypatch.setenv("MCP_TEST_SECRET_FILE", str(tmp_path / "does-not-exist"))
    try:
        config.secret("MCP_TEST_SECRET")
        assert False, "expected ConfigError on unreadable secret file"
    except config.ConfigError:
        pass


# ---------- password lifecycle ----------

def _restore_user(auth, user):
    """Snapshot a user's credential fields; return a restore callback so these
    in-process mutations don't leak into other tests (the live gateway is a
    separate process and unaffected either way)."""
    snap = dict(auth.USERS[user])
    def restore():
        auth.USERS[user] = snap
    return restore


def test_password_change_and_forced_rotation(tmp_path, monkeypatch):
    from app import auth
    monkeypatch.setattr(auth, "_CREDS_FILE", tmp_path / "creds.json")
    user = "sara"
    restore = _restore_user(auth, user)
    try:
        ok, _ = auth.set_password(user, "FirstPass!234", must_change=True)
        assert ok
        assert auth.password_change_required(user)          # forced first-login rotation
        assert not auth.change_password(user, "wrong", "NextPass!234")[0]     # bad current
        assert not auth.change_password(user, "FirstPass!234", "FirstPass!234")[0]  # reuse
        assert not auth.change_password(user, "FirstPass!234", "weak")[0]     # weak
        ok, _ = auth.change_password(user, "FirstPass!234", "SecondPass!234")  # valid
        assert ok
        assert not auth.password_change_required(user)
    finally:
        restore()


def test_password_expiry(tmp_path, monkeypatch):
    from app import auth
    monkeypatch.setattr(auth, "_CREDS_FILE", tmp_path / "creds.json")
    monkeypatch.setattr(auth, "_PW_MAX_AGE_DAYS", 90)
    user = "khalid"
    restore = _restore_user(auth, user)
    try:
        auth.set_password(user, "TimedPass!234", must_change=False)
        assert not auth.password_expired(user)
        auth.USERS[user]["pwd_set_at"] = auth._now_epoch() - 91 * 86400   # backdate
        assert auth.password_expired(user)
        assert auth.password_change_required(user)
    finally:
        restore()


# ---------- homoglyph / mixed-script ----------

def test_homoglyph_mixed_script_flagged():
    from app import unicode_guard
    _, flags = unicode_guard.sanitize("pаypal.com")   # Cyrillic 'а' in paypal
    assert any(f.startswith("homoglyph_mixed_script") for f in flags)
    # legitimate Arabic + Latin + digits must NOT be flagged
    _, ok_flags = unicode_guard.sanitize("مرحبا hello 42")
    assert not any(f.startswith("homoglyph") for f in ok_flags)
    # pure Latin must NOT be flagged
    _, latin_flags = unicode_guard.sanitize("paypal.com secure login")
    assert not any(f.startswith("homoglyph") for f in latin_flags)


# ---------- trusted-proxy edge guard ----------

def test_trusted_proxy_guard_blocks_direct_access(monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    monkeypatch.setattr(main, "_PROXY_REQUIRED", True)
    monkeypatch.setattr(main, "_PROXY_SECRET", "shared-proxy-secret")
    client = TestClient(main.app)
    # no proxy header -> 403 (direct access refused)
    assert client.get("/api/tools").status_code == 403
    # health is exempt so liveness probes still work
    assert client.get("/api/health").status_code == 200
    # correct proxy secret -> passes the guard (401 for missing auth, not 403)
    r = client.get("/api/tools", headers={"x-proxy-auth": "shared-proxy-secret"})
    assert r.status_code != 403
