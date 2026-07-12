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


# ---------------------------------------------------------------------------
# Incremental verification for the hot path
# ---------------------------------------------------------------------------
# A full verification is O(n) and, on a real log, seconds of CPU (3.6 s at 6.5k records,
# and it only grows). /api/health ran one on EVERY request — including the container
# healthcheck every 30 s and every dashboard poll — so the gateway spent most of its CPU
# re-proving the same thing, and requests started timing out.
#
# The chain is APPEND-ONLY, so the hot path does not need to re-verify history it has
# already verified: we remember the byte offset, record count and last hash of the verified
# prefix, and each check only walks the records appended since. That is O(new records),
# i.e. effectively free, and it still catches a broken link or a forged record the moment
# one is appended.
#
# It cannot, by construction, re-detect an edit to an OLD record — so a FULL pass still runs
# (a) at startup, seeding the state, and (b) whenever an operator hits Re-verify. Forging an
# old record requires the HMAC key; without it, any edit invalidates that record's own hash,
# which the next full pass catches.
_verify_lock = threading.Lock()
_verify_state: dict = {"offset": 0, "count": 0, "last": GENESIS,
                       "ok": True, "msg": "empty log", "checked": 0.0}


def _verify_span(offset: int, prev: str, count: int) -> tuple:
    """Verify the records after `offset`, continuing the chain from `prev`.
    Returns (ok, msg, new_offset, new_prev, new_count). Only whole lines are consumed."""
    with open(_LOG, "rb") as f:
        f.seek(offset)
        blob = f.read()
    consumed = 0
    for raw in blob.splitlines(keepends=True):
        if not raw.endswith(b"\n"):
            break                                    # a partial trailing write: stop here
        consumed += len(raw)
        line = raw.decode("utf-8").strip()
        if not line:
            continue
        entry = json.loads(line)
        stored = entry.pop("hash")
        count += 1
        if entry["prev"] != prev:
            return False, f"broken link at record {count}: prev mismatch", offset, prev, count
        if _hash(entry) != stored:
            return False, f"tampered content at record {count}: hash mismatch", offset, prev, count
        prev = stored
    return True, f"chain intact: {count} records", offset + consumed, prev, count


def chain_status(full: bool = False) -> tuple[bool, str]:
    """Verify the chain cheaply — safe for hot paths (health, dashboard polls).

    Incremental by default: only records appended since the last check are hashed.
    `full=True` re-verifies every record from genesis (the Re-verify button, startup).
    Once a break is found the failure is sticky until a full pass clears it.
    """
    if not _LOG.exists():
        return True, "empty log"
    with _verify_lock:
        st = _verify_state
        if full:
            st.update({"offset": 0, "count": 0, "last": GENESIS, "ok": True})
        elif not st["ok"]:
            return False, st["msg"]                  # stay broken until someone re-verifies
        try:
            size = _LOG.stat().st_size
            if size < st["offset"]:                  # log truncated/rotated → re-verify all
                st.update({"offset": 0, "count": 0, "last": GENESIS, "ok": True})
            elif size == st["offset"] and st["count"]:
                return True, st["msg"]               # nothing appended since the last check
            ok, msg, offset, last, count = _verify_span(st["offset"], st["last"], st["count"])
        except (OSError, ValueError, KeyError) as exc:
            return False, f"audit log unreadable: {exc}"
        st.update({"offset": offset, "count": count, "last": last, "ok": ok, "msg": msg,
                   "checked": time.time()})
        return ok, msg


def tail(n: int = 100) -> list[dict]:
    if not _LOG.exists():
        return []
    with open(_LOG, encoding="utf-8") as f:
        lines = [json.loads(x) for x in f if x.strip()]
    return lines[-n:]
