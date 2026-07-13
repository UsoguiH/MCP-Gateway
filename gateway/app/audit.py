"""Tamper-evident audit log (spec §4.4.9 / §4.9, closes v7 flaw B10).

Append-only with a hash chain: each record embeds the HMAC of the previous
record, so any edit or deletion breaks the chain and is detectable.

Two backends behind one API (Phase 3):
  * flat file (dev/test default) — append-only JSONL in DATA_DIR, exactly as
    before.
  * PostgreSQL (MCP_STATE_DB_URL set) — one chain shared by every gateway
    instance/worker. Appends serialize on a Postgres advisory lock so the
    prev-hash link is race-free across nodes; the record column stores the
    exact JSON text, so the HMAC verifies byte-identically after a file→DB
    migration and a DB→file rollback.

Log-content minimization: full payloads are hashed; only short, DLP-masked
excerpts are stored inline. Nothing here should contain raw PII.
"""
import hashlib
import hmac
import json
import os
import queue
import threading
import time
from pathlib import Path

from . import statestore
from .config import DATA_DIR, ROOT

_LOG = DATA_DIR / "audit_log.jsonl"
_LOCK = threading.Lock()
GENESIS = "0" * 64

# A9: live event counters (for /api/metrics) + optional SIEM export stream.
from collections import Counter as _Counter  # noqa: E402
from .config import CONFIG  # noqa: E402

_COUNTS: _Counter = _Counter()
_AUDIT_CFG = CONFIG.get("audit", {}) or {}
# The SIEM mirror stays a per-instance local file in BOTH backends: it is a feed
# for an external consumer (Phase 4), not a store, and per-node feeds are how
# log shippers expect to find it.
_SIEM_STREAM = DATA_DIR / _AUDIT_CFG.get("siem_stream", "siem_stream.jsonl") \
    if _AUDIT_CFG.get("siem_export") else None

_counts_cache = statestore.TTLCache(2.0)


def counts() -> dict:
    if statestore.enabled():
        def _load():
            return {e: int(n) for e, n in
                    statestore.all_rows("SELECT event, count(*) FROM audit_log GROUP BY event")}
        return _counts_cache.get(_load)
    with _LOCK:
        return dict(_COUNTS)

# M4: the chain is keyed (HMAC-SHA256), not a bare hash, so an attacker who can
# write the log cannot recompute a valid chain without the key. The key is read
# from MCP_AUDIT_KEY (production: HSM/secret store) or a dev key file kept OUTSIDE
# the log's directory (pki/), so log-write access alone does not expose it.
_AUDIT_KEY_FILE = ROOT / "pki" / "audit_hmac.key"


_key_cache: bytes | None = None


def _audit_key() -> bytes:
    """The chain's HMAC key — resolved ONCE.

    This is called for every hash: once per appended record, and once per record while
    VERIFYING the chain. It used to re-read the key from the secrets mount every time
    (~2.7 ms there), so a full verification of a 9,000-record chain spent ~24 s reading
    the same file 9,000 times. Rotating the key is a restart (see OPERATIONS §5b), so
    reading it once is exactly right.
    """
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    from .config import secret_cached
    env = secret_cached("MCP_AUDIT_KEY")        # supports MCP_AUDIT_KEY_FILE
    if env:
        _key_cache = env.encode("utf-8")
    else:
        if not _AUDIT_KEY_FILE.exists():
            _AUDIT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            _AUDIT_KEY_FILE.write_bytes(os.urandom(32))
        _key_cache = _AUDIT_KEY_FILE.read_bytes()
    return _key_cache


def _hash(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(_audit_key(), payload, hashlib.sha256).hexdigest()


# The tip of the file-backed chain, cached.
#
# This used to re-read and JSON-parse the ENTIRE log to find the last hash — on every
# append. That is O(n) per record and O(n^2) over the life of the log: by ~10k records a
# single mediated tool call (which writes two records) took ~7 SECONDS, and calls got
# slower forever. It was invisible while the dev log was small, and it is exactly the
# failure a pilot would hit a few weeks in.
#
# The cache is keyed on (path, size), so it re-scans if the file is swapped (tests point
# _LOG at a tmp file) or changed by anything other than us. Appends are already serialized
# by _LOCK, and the file backend is single-instance by definition — sharing a chain across
# processes is what the database backend is for.
_tip = {"path": None, "size": -1, "hash": GENESIS}


def _last_hash_file() -> str:
    try:
        size = _LOG.stat().st_size
    except OSError:
        size = 0
    if _tip["path"] == _LOG and _tip["size"] == size:
        return _tip["hash"]
    last = GENESIS
    if size:
        with open(_LOG, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
    _tip.update({"path": _LOG, "size": size, "hash": last})
    return last


def payload_digest(obj) -> str:
    """SHA-256 of an arbitrary JSON-able payload (for minimized logging)."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def log_signature():
    """A cheap value that changes iff the log changed (insights' cache key)."""
    if statestore.enabled():
        row = statestore.one("SELECT max(seq) FROM audit_log")
        return ("db", row[0] if row else None)
    try:
        st = _LOG.stat()
        return (st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def _mirror_siem(line: str):
    if _SIEM_STREAM is not None:
        with open(_SIEM_STREAM, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def record(event: str, **fields) -> dict:
    """Append one event to the chain and return the stored record."""
    if statestore.enabled():
        entry = _record_db(event, fields)
    else:
        with _LOCK:
            prev = _last_hash_file()
            entry = {
                "ts": round(time.time(), 3),
                "event": event,
                "prev": prev,
                **fields,
            }
            entry["hash"] = _hash(entry)
            line = json.dumps(entry, ensure_ascii=False)
            with open(_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # advance the cached tip instead of re-scanning the log on the next append
            _tip.update({"path": _LOG, "size": _LOG.stat().st_size, "hash": entry["hash"]})
            _COUNTS[event] += 1
            _mirror_siem(line)                # mirror to the SIEM feed (WORM/SIEM in prod)
    # Notification center: security-relevant events surface in the dashboard's
    # right panel. Outside _LOCK (its own lock), lazy import (no cycle), never raises.
    from . import notifications
    notifications.on_audit_event(entry)
    return entry


# ---------------------------------------------------------------------------
# group-commit writer (the chain's throughput limit, and the fix)
# ---------------------------------------------------------------------------
# The chain is strictly ordered, so every append must serialize on ONE lock across the
# whole fleet — that is what makes it tamper-evident, and it is not negotiable. But
# taking that global lock, reading the tip, inserting and committing costs ~15 ms of
# HELD lock time, and a mediated tool call writes two records. That capped the entire
# fleet near ~30 calls/s no matter how many gateway instances were added: adding a node
# added contention, not capacity.
#
# The fix is group commit. One writer thread per process drains the queue, takes the lock
# ONCE, chains every queued record in memory (it knows the tip, so it can compute each
# prev/hash in order), inserts them in a single executemany, and commits once. The cost
# per record collapses from "one lock + one commit" to a share of one.
#
# Durability is UNCHANGED: the calling thread still blocks until its record is committed,
# so a caller that has returned from record() has a record on disk — exactly as before.
# Under light load a batch is one record and the latency is identical to the old path;
# batching only kicks in under the load that needs it.
_MAX_BATCH = 64


class _Pending:
    __slots__ = ("event", "fields", "entry", "done", "error")

    def __init__(self, event, fields):
        self.event, self.fields = event, fields
        self.entry, self.error = None, None
        self.done = threading.Event()


_queue: "queue.Queue[_Pending]" = queue.Queue()
_writer_thread: threading.Thread | None = None
_writer_lock = threading.Lock()


def _ensure_writer():
    global _writer_thread
    if _writer_thread is not None and _writer_thread.is_alive():
        return
    with _writer_lock:
        if _writer_thread is not None and _writer_thread.is_alive():
            return
        _writer_thread = threading.Thread(target=_writer_loop, name="audit-chain-writer",
                                          daemon=True)
        _writer_thread.start()


def _writer_loop():
    while True:
        batch = [_queue.get()]                       # block for the first
        while len(batch) < _MAX_BATCH:               # then take whatever else is waiting
            try:
                batch.append(_queue.get_nowait())
            except queue.Empty:
                break
        try:
            _flush(batch)
        except Exception as exc:                     # the batch failed: tell every caller
            for p in batch:
                p.error = exc
        finally:
            for p in batch:
                p.done.set()


def _flush(batch: list[_Pending]):
    """Chain and commit a whole batch under ONE acquisition of the global chain lock."""
    with statestore.tx() as cur:
        # The lock and the tip-read are DELIBERATELY two statements. Folding them into one
        # (`SELECT pg_advisory_xact_lock(k), (SELECT hash ... LIMIT 1)`) saves a round trip
        # and is WRONG: PostgreSQL does not guarantee the evaluation order of a SELECT's
        # target list, so the subquery can read the tip BEFORE the lock is taken — two
        # concurrent writers then chain onto the same prev and the chain breaks. It broke
        # exactly that way in test_audit_chain_survives_concurrent_writers. The lock must be
        # HELD before the read. Do not "optimise" this back.
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (statestore.LOCK_AUDIT_CHAIN,))
        row = cur.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        rows, lines = [], []
        for p in batch:
            entry = {"ts": round(time.time(), 3), "event": p.event, "prev": prev, **p.fields}
            entry["hash"] = _hash(entry)
            prev = entry["hash"]                     # chain within the batch, in order
            line = json.dumps(entry, ensure_ascii=False)
            p.entry, p.error = entry, None
            lines.append(line)
            rows.append((entry["ts"], p.event,
                         p.fields.get("user") or p.fields.get("sub") or p.fields.get("by"),
                         p.fields.get("server"), entry["prev"], entry["hash"], line))
        cur.executemany(
            "INSERT INTO audit_log (ts, event, usr, server, prev, hash, record) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)", rows)
    _counts_cache.invalidate()
    for line in lines:
        _mirror_siem(line)


def _record_db(event: str, fields: dict) -> dict:
    """Append one event via the group-commit writer. Blocks until it is committed."""
    _ensure_writer()
    p = _Pending(event, fields)
    _queue.put(p)
    p.done.wait()
    if p.error is not None:
        raise p.error
    return p.entry


def _iter_db_records(after_seq: int = 0):
    """Stream (seq, record_text) in chain order without loading the whole table.
    A named (server-side) cursor needs a transaction block, even read-only."""
    with statestore.cx() as c:
        with c.transaction():
            with c.cursor(name=f"audit_walk_{os.getpid()}_{threading.get_ident()}") as cur:
                cur.itersize = 5000
                cur.execute("SELECT seq, record FROM audit_log WHERE seq > %s ORDER BY seq",
                            (after_seq,))
                yield from cur


def verify_chain() -> tuple[bool, str]:
    """Recompute the WHOLE chain. Returns (ok, message). O(n) in the log length —
    every record's HMAC is recomputed, which is the point: it is what makes tampering
    detectable. Callers on a hot path should use `chain_status()` instead."""
    if statestore.enabled():
        prev, n = GENESIS, 0
        for seq, text in _iter_db_records():
            entry = json.loads(text)
            stored = entry.pop("hash")
            n += 1
            if entry["prev"] != prev:
                return False, f"broken link at record {n} (seq {seq}): prev mismatch"
            if _hash(entry) != stored:
                return False, f"tampered content at record {n} (seq {seq}): hash mismatch"
            prev = stored
        return True, (f"chain intact: {n} records" if n else "empty log")
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
# A full verification is O(n) and, on a real log, seconds of CPU. /api/health used
# to run one on EVERY request. The chain is APPEND-ONLY, so the hot path only
# verifies what was appended since the last check (file mode: a byte offset; DB
# mode: a seq cursor). A FULL pass still runs at startup and on Re-verify — the
# only pass that can re-detect an edit to an OLD record.
_verify_lock = threading.Lock()
_verify_state: dict = {"backend": None, "offset": 0, "seq": 0, "count": 0,
                       "last": GENESIS, "ok": True, "msg": "empty log", "checked": 0.0}


def _verify_span_file(offset: int, prev: str, count: int) -> tuple:
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


def _verify_span_db(seq: int, prev: str, count: int) -> tuple:
    """DB twin of the file span verifier: walk records with seq > cursor."""
    for s, text in _iter_db_records(after_seq=seq):
        entry = json.loads(text)
        stored = entry.pop("hash")
        count += 1
        if entry["prev"] != prev:
            return False, f"broken link at record {count} (seq {s}): prev mismatch", seq, prev, count
        if _hash(entry) != stored:
            return False, f"tampered content at record {count} (seq {s}): hash mismatch", seq, prev, count
        prev = stored
        seq = s
    return True, f"chain intact: {count} records", seq, prev, count


def chain_status(full: bool = False) -> tuple[bool, str]:
    """Verify the chain cheaply — safe for hot paths (health, dashboard polls).

    Incremental by default: only records appended since the last check are hashed.
    `full=True` re-verifies every record from genesis (the Re-verify button, startup).
    Once a break is found the failure is sticky until a full pass clears it.
    """
    backend = "db" if statestore.enabled() else "file"
    if backend == "file" and not _LOG.exists():
        return True, "empty log"
    with _verify_lock:
        st = _verify_state
        if full or st.get("backend") != backend:     # backend flip (tests): start over
            st.update({"backend": backend, "offset": 0, "seq": 0, "count": 0,
                       "last": GENESIS, "ok": True})
        elif not st["ok"]:
            return False, st["msg"]                  # stay broken until someone re-verifies
        try:
            if backend == "db":
                # Short-circuit on an unchanged tip. The file path has always had this
                # ("nothing appended since the last check"); the DB path did not, so every
                # /api/health — the container healthcheck AND every dashboard poll —
                # opened a server-side cursor and walked it, holding the global verify
                # lock while it did. Forty concurrent health polls then queued behind each
                # other: p50 453 ms for an endpoint that does no work. One cheap
                # `max(seq)` answers "has anything been appended?" instead.
                row = statestore.one("SELECT max(seq) FROM audit_log")
                tip = row[0] if row else None
                if st["count"] and tip == st["seq"]:
                    return st["ok"], st["msg"]
                if tip is None:
                    st.update({"seq": 0, "count": 0, "last": GENESIS, "ok": True,
                               "msg": "empty log", "checked": time.time()})
                    return True, "empty log"
                ok, msg, seq, last, count = _verify_span_db(st["seq"], st["last"], st["count"])
                st.update({"seq": seq})
                if count == 0:
                    msg = "empty log"
            else:
                size = _LOG.stat().st_size
                if size < st["offset"]:              # log truncated/rotated → re-verify all
                    st.update({"offset": 0, "count": 0, "last": GENESIS, "ok": True})
                elif size == st["offset"] and st["count"]:
                    return True, st["msg"]           # nothing appended since the last check
                ok, msg, offset, last, count = _verify_span_file(st["offset"], st["last"],
                                                                 st["count"])
                st.update({"offset": offset})
        except (OSError, ValueError, KeyError) as exc:
            return False, f"audit log unreadable: {exc}"
        st.update({"count": count, "last": last, "ok": ok, "msg": msg,
                   "checked": time.time()})
        return ok, msg


def tail(n: int = 100) -> list[dict]:
    if statestore.enabled():
        rows = statestore.all_rows(
            "SELECT record FROM audit_log ORDER BY seq DESC LIMIT %s", (n,))
        return [json.loads(r[0]) for r in reversed(rows)]
    if not _LOG.exists():
        return []
    with open(_LOG, encoding="utf-8") as f:
        lines = [json.loads(x) for x in f if x.strip()]
    return lines[-n:]
