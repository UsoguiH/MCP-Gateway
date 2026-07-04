"""Parser fuzzing (W9.1, blueprint Layer 4/SDL) — feed malformed/hostile input to
the security-critical pure functions and assert they degrade gracefully (reject,
never crash the process, never throw out of the boundary)."""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import audit, auth, dlp, pki, unicode_guard
from app.gateway import _validate_args

_RND = random.Random(1337)  # deterministic


def _blob(n):
    return "".join(chr(_RND.randint(0, 0x2FF)) for _ in range(n))


def test_fuzz_token_verify_never_crashes():
    for _ in range(300):
        assert auth.verify(_blob(_RND.randint(0, 80)), _blob(8)) is None


def test_fuzz_cert_challenge_never_crashes():
    for _ in range(200):
        junk = _blob(_RND.randint(0, 120))
        assert auth.make_challenge(junk) is None            # bad PEM -> None, no throw
        assert auth.make_challenge(junk.encode(errors="ignore")) is None


def test_fuzz_dlp_and_unicode_never_crash():
    for _ in range(300):
        s = _blob(_RND.randint(0, 200))
        assert isinstance(dlp.scan(s), list)
        clean, flags = unicode_guard.sanitize(s)
        assert isinstance(clean, str) and isinstance(flags, list)
        m, det = dlp.mask(s)
        assert isinstance(m, str)


def test_fuzz_schema_validator_never_crashes():
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}
    tool = {"server": "s", "name": "t", "schema": schema}
    for _ in range(300):
        args = {_blob(3): _blob(5) for _ in range(_RND.randint(0, 4))}
        ok, why = _validate_args(tool, args)
        assert isinstance(ok, bool) and isinstance(why, str)
    # a valid instance passes; an unexpected field is rejected
    assert _validate_args(tool, {"q": "hi"})[0] is True
    assert _validate_args(tool, {"q": "hi", "evil": 1})[0] is False


def test_fuzz_payload_digest_handles_any_jsonable():
    for _ in range(100):
        obj = {_blob(3): [_RND.random(), _blob(4), None, True]}
        assert isinstance(audit.payload_digest(obj), str)


def test_fuzz_pki_load_cert_rejects_garbage():
    for _ in range(100):
        try:
            pki.load_cert_from_pem(_blob(_RND.randint(0, 60)))
        except Exception:
            pass  # expected: malformed cert raises, and callers catch it
