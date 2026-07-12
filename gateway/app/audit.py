"""Tamper-evident audit log (spec §4.4.9 / §4.9, closes v7 flaw B10).

Append-only JSONL with a hash chain: each record embeds the SHA-256 of the
previous record, so any edit or deletion breaks the chain and is detectable.
This is the dev stand-in for a WORM store + SIEM stream.

Log-content minimization: full payloads are hashed; only short, DLP-masked
excerpts are stored inline. Nothing here should contain raw PII.
"""
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

from .config import DATA_DIR, ROOT

_LOG = DATA_DIR / "audit_log.jsonl"
_LOCK = threading.Lock()
GENESIS = "0" * 64

# A9: live event counters (for /api/metrics) + optional SIEM export stream.
from collections import Counter as _Counter  # noqa: E402
from .config import CONFIG  # noqa: E402

_COUNTS: _Counter = _Counter()
_AUDIT_CFG = CONFIG.get("audit", {}) or {}
_SIEM_STREAM = DATA_DIR / _AUDIT_CFG.get("siem_stream", "siem_stream.jsonl") \
    if _AUDIT_CFG.get("siem_export") else None


def counts() -> dict:
    with _LOCK:
        return dict(_COUNTS)

# M4: the chain is keyed (HMAC-SHA256), not a bare hash, so an attacker who can
# write the log cannot recompute a valid chain without the key. The key is read
# from MCP_AUDIT_KEY (production: HSM/secret store) or a dev key file kept OUTSIDE
# the log's directory (pki/), so log-write access alone does not expose it.
_AUDIT_KEY_FILE = ROOT / "pki" / "audit_hmac.key"


def _audit_key() -> bytes:
    from .config import secret
    env = secret("MCP_AUDIT_KEY")               # supports MCP_AUDIT_KEY_FILE
    if env:
        return env.encode("utf-8")
    if not _AUDIT_KEY_FILE.exists():
        _AUDIT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _AUDIT_KEY_FILE.write_bytes(os.urandom(32))
    return _AUDIT_KEY_FILE.read_bytes()


def _hash(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(_audit_key(), payload, hashlib.sha256).hexdigest()


def _last_hash() -> str:
    if not _LOG.exists():
        return GENESIS
    last = GENESIS
    with open(_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = json.loads(line)["hash"]
    return last


def payload_digest(obj) -> str:
    """SHA-256 of an arbitrary JSON-able payload (for minimized logging)."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def record(event: str, **fields) -> dict:
    """Append one event to the chain and return the stored record."""
    with _LOCK:
        prev = _last_hash()
        entry = {
            "ts": round(time.time(), 3),
            "event": event,
            "prev": prev,
            **fields,
        }
        entry["hash"] = _hash(entry)
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _COUNTS[event] += 1
        if _SIEM_STREAM is not None:          # mirror to the SIEM feed (WORM/SIEM in prod)
            with open(_SIEM_STREAM, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    # Notification center: security-relevant events surface in the dashboard's
    # right panel. Outside _LOCK (its own lock), lazy import (no cycle), never raises.
    from . import notifications
    notifications.on_audit_event(entry)
    return entry


def verify_chain() -> tuple[bool, str]:
    """Recompute the WHOLE chain. Returns (ok, message). O(n) in the log length —
    every record's HMAC is recomputed, which is the point: it is what makes tampering
    detectable. Callers on a hot path should use `chain_status()` instead."""
    if not _LOG.exists():
        return True, "empty log"
    prev = GENESIS
    n = 0
    with open(_LOG, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            stored = entry.pop("hash")
            if entry["prev"] != prev:
                return False, f"broken link at line {i}: prev mismatch"
            if _hash(entry) != stored:
                return False, f"tampered content at line {i}: hash mismatch"
            prev = stored
            n += 1
    return True, f"chain intact: {n} records"


# A full verification is O(n) and, on a real log, seconds of CPU: at 6.5k records it
# measured 3.6 s. /api/health ran it on EVERY request — including the container
# healthcheck every 30 s and every dashboard poll — so the gateway spent most of its CPU
# re-proving the same thing and slow requests began timing out. The check still runs in
# full (nothing is skipped), just at most once per TTL. The Audit page's "Re-verify" button
# (/api/admin/audit/verify) calls verify_chain() directly to force a fresh pass on demand.
_VERIFY_TTL = 60.0
_verify_cache: dict = {"ts": 0.0, "result": None}


def chain_status(max_age: float = _VERIFY_TTL) -> tuple[bool, str]:
    """Cached full-chain verification — safe for hot paths (health, dashboard polls)."""
    now = time.time()
    with _LOCK:
        cached = _verify_cache["result"]
        fresh = cached is not None and (now - _verify_cache["ts"]) < max_age
    if fresh:
        return cached
    result = verify_chain()               # full pass, outside the lock (it reads the file)
    with _LOCK:
        _verify_cache["ts"] = time.time()
        _verify_cache["result"] = result
    return result


def tail(n: int = 100) -> list[dict]:
    if not _LOG.exists():
        return []
    with open(_LOG, encoding="utf-8") as f:
        lines = [json.loads(x) for x in f if x.strip()]
    return lines[-n:]
