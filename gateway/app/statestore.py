"""Shared-state backend — PostgreSQL for everything that must survive a node (Phase 3).

Until now every durable store was a JSON file with an in-process lock and every
runtime table (sessions, rate windows, breaker, taint, lockouts) lived in one
process's memory. That caps the gateway at exactly one instance and makes
concurrent writes a race. This module is the seam that removes the cap:

    MCP_STATE_DB_URL set   -> every store reads/writes the `gwstate` PostgreSQL
                              database through the helpers here (multi-instance,
                              multi-worker safe)
    MCP_STATE_DB_URL unset -> every store keeps its original flat-file/in-memory
                              behaviour (the dev/test default — zero setup)

Design decision (D5: "make it scalable", 2-4 person ops team): PostgreSQL is the
ONLY shared-state service — no Redis. Ephemeral state (sessions, rate events,
breaker, taint, oauth codes, lockouts, leases) lives in UNLOGGED tables: no WAL
overhead, truncated only on crash recovery, and everything in them is
re-establishable (a client re-initializes, a rate window refills, a breaker
re-trips). Durable state (audit chain, approvals + their executed results,
registry, identities, oauth, api keys, notifications, containment) uses normal
tables. One database, one backup, one thing to operate.

Fail-closed: if the URL is set and the database cannot be reached, the gateway
refuses to boot — it must never silently fall back to per-instance files while
an operator believes state is shared.

The audit chain's `record` column is TEXT, not JSONB, deliberately: the HMAC
chain is computed over the exact JSON bytes, and JSONB normalizes numbers and
key order. TEXT round-trips byte-exact, so a chain migrated from the JSONL file
verifies unchanged and a rollback export reproduces a verifiable file.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from contextlib import contextmanager

from .config import ConfigError, clear_secret_cache, secret_cached

# One advisory-lock key per serialized concern (Postgres advisory locks are
# int64-keyed and database-wide, which is exactly the scope we need).
LOCK_AUDIT_CHAIN = 0x6D637020_00000001          # serializes audit appends
LOCK_REGISTRY = 0x6D637020_00000002             # serializes registry reconciles
LOCK_DYN_SERVERS = 0x6D637020_00000003          # serializes dynamic-inventory edits

_lock = threading.Lock()
_pool = None
_pool_url: str | None = None


def db_url() -> str | None:
    """The gwstate database URL (env or _FILE secret).

    Resolved once per process: `enabled()` below is called on EVERY store operation —
    dozens of times per mediated call — and resolving a file-mounted secret costs ~2.7 ms
    on a container secrets mount (see config.secret_cached). Tests flip the backend by
    changing the env var and calling close(), which drops the cache.
    """
    return secret_cached("MCP_STATE_DB_URL")


def enabled() -> bool:
    return bool(db_url())


def instance_id() -> str:
    """Stable identity of THIS gateway instance (HA: which node did what)."""
    return os.environ.get("MCP_INSTANCE_ID") or f"{socket.gethostname()}:{os.getpid()}"


def pool():
    """The process-wide connection pool (built on first use, schema ensured once).
    A set-but-unreachable database is a hard error — fail closed, never file-fallback."""
    global _pool, _pool_url
    url = db_url()
    if not url:
        raise ConfigError("MCP_STATE_DB_URL is not set — state backend is flat-file")
    p = _pool                                # hot path: no lock once the pool exists
    if p is not None and _pool_url == url:
        return p
    with _lock:
        if _pool is not None and _pool_url == url:
            return _pool
        if _pool is not None:
            try:
                _pool.close()
            except Exception:
                pass
            _pool = None
        try:
            from psycopg_pool import ConnectionPool
            candidate = ConnectionPool(
                url, min_size=2,
                # The whole control pipeline is DB-bound and runs in worker threads (see
                # Gateway._execute_call), so the pool — not the CPU — is what bounds
                # concurrency. Too small a pool turns into a queue in front of the queue.
                max_size=int(os.environ.get("MCP_STATE_DB_POOL", "32")),
                kwargs={"autocommit": True},
                open=True, timeout=10,
            )
            with candidate.connection() as c:
                _ensure_schema(c)
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(
                f"MCP_STATE_DB_URL is set but the state database is unreachable "
                f"({type(e).__name__}: {e}) — refusing to run with per-instance "
                f"file state while shared state was configured") from e
        _pool, _pool_url = candidate, url
        return _pool


@contextmanager
def cx():
    """A pooled autocommit connection."""
    with pool().connection() as c:
        yield c


@contextmanager
def tx():
    """A cursor inside one explicit transaction (read-modify-write, chain append)."""
    with pool().connection() as c:
        with c.transaction():
            with c.cursor() as cur:
                yield cur


def run(sql: str, params=None):
    with cx() as c:
        c.execute(sql, params)


def one(sql: str, params=None):
    with cx() as c:
        return c.execute(sql, params).fetchone()


def all_rows(sql: str, params=None) -> list:
    with cx() as c:
        return c.execute(sql, params).fetchall()


def healthy() -> tuple[bool, str]:
    """Is the shared-state database reachable right now (health endpoint)?"""
    if not enabled():
        return True, "flat-file (single instance)"
    try:
        t0 = time.perf_counter()
        one("SELECT 1")
        return True, f"postgres ok ({round((time.perf_counter() - t0) * 1000, 1)} ms)"
    except Exception as e:
        return False, f"postgres unreachable: {type(e).__name__}: {str(e)[:120]}"


# ---------------------------------------------------------------------------
# schema — idempotent, owned by the gwstate role in its own database
# ---------------------------------------------------------------------------

_SCHEMA = """
-- durable ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    seq     BIGSERIAL PRIMARY KEY,
    ts      DOUBLE PRECISION NOT NULL,
    event   TEXT NOT NULL,
    usr     TEXT,
    server  TEXT,
    prev    TEXT NOT NULL,
    hash    TEXT NOT NULL,
    record  TEXT NOT NULL          -- exact JSON bytes: the HMAC chain hashes these
);
CREATE INDEX IF NOT EXISTS audit_log_ts    ON audit_log (ts);
CREATE INDEX IF NOT EXISTS audit_log_event ON audit_log (event);
CREATE INDEX IF NOT EXISTS audit_log_usr   ON audit_log (usr);

CREATE TABLE IF NOT EXISTS approvals (
    aid         TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    requester   TEXT NOT NULL,
    created     DOUBLE PRECISION NOT NULL,
    resolved_at DOUBLE PRECISION,
    doc         JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals (status);

-- Phase 3 task 2: an approved call's result used to die with the process (a
-- user-visible bug: the requester could never fetch it after a restart).
CREATE TABLE IF NOT EXISTS approval_results (
    aid     TEXT PRIMARY KEY,
    created DOUBLE PRECISION NOT NULL,
    doc     JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS registry_tools (
    key TEXT PRIMARY KEY,
    doc JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS operators   (sub TEXT PRIMARY KEY, doc JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS credentials (sub TEXT PRIMARY KEY, doc JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS mfa_secrets (sub TEXT PRIMARY KEY, blob TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revoked_subjects (sub TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS session_nb  (sub TEXT PRIMARY KEY, nb DOUBLE PRECISION NOT NULL);

CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, doc JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_refresh (
    token_hash TEXT PRIMARY KEY,
    exp        DOUBLE PRECISION NOT NULL,
    doc        JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (kid TEXT PRIMARY KEY, doc JSONB NOT NULL);

CREATE TABLE IF NOT EXISTS notifications (
    id  TEXT PRIMARY KEY,
    ts  DOUBLE PRECISION NOT NULL,
    key TEXT,
    doc JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS notifications_ts ON notifications (ts);

CREATE TABLE IF NOT EXISTS killswitch (scope TEXT PRIMARY KEY, doc JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS drained    (server TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS settings   (section TEXT PRIMARY KEY, doc JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS kv         (name TEXT PRIMARY KEY, doc JSONB NOT NULL,
                                       updated DOUBLE PRECISION);

-- runtime (UNLOGGED: no WAL, truncated on crash recovery, all re-establishable)
CREATE UNLOGGED TABLE IF NOT EXISTS mcp_sessions (
    sid       TEXT PRIMARY KEY,
    sub       TEXT NOT NULL,
    created   DOUBLE PRECISION NOT NULL,
    last_seen DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS mcp_sessions_sub ON mcp_sessions (sub);

CREATE UNLOGGED TABLE IF NOT EXISTS rate_events (
    limiter TEXT NOT NULL,
    key     TEXT NOT NULL,
    ts      DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_events_lkt ON rate_events (limiter, key, ts);

CREATE UNLOGGED TABLE IF NOT EXISTS breaker (
    server     TEXT PRIMARY KEY,
    fails      INTEGER NOT NULL DEFAULT 0,
    open_until DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE UNLOGGED TABLE IF NOT EXISTS taint_snippets (
    session TEXT NOT NULL,
    key     TEXT NOT NULL,
    source  TEXT NOT NULL,
    ts      DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (session, key)
);

CREATE UNLOGGED TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    exp       DOUBLE PRECISION NOT NULL,
    doc       JSONB NOT NULL
);

CREATE UNLOGGED TABLE IF NOT EXISTS lockouts (
    sub          TEXT PRIMARY KEY,
    fails        INTEGER NOT NULL DEFAULT 0,
    locked_until DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE UNLOGGED TABLE IF NOT EXISTS revoked_jti (
    jti TEXT PRIMARY KEY,
    exp DOUBLE PRECISION NOT NULL
);

CREATE UNLOGGED TABLE IF NOT EXISTS vault_leases (
    lease TEXT PRIMARY KEY,
    exp   DOUBLE PRECISION NOT NULL,
    doc   JSONB NOT NULL
);
"""


def _ensure_schema(conn):
    conn.execute(_SCHEMA)


# ---------------------------------------------------------------------------
# tiny TTL cache — several hot paths re-read small tables (drained servers,
# settings overlay, the operator directory); a 1-2 s cache turns those into one
# SELECT per interval per process without meaningfully delaying propagation.
# ---------------------------------------------------------------------------

class TTLCache:
    """Single-flight TTL cache.

    When the entry lapses, exactly ONE caller reloads it; everyone else keeps using the
    value they have (at most `ttl` stale — which is the guarantee the cache offers anyway).
    Letting every in-flight request reload on expiry is what turns a cache into a
    thundering herd: under load the reload makes each request slower, which makes the TTL
    lapse again sooner, which triggers more reloads. It is a cache that gets *worse* the
    more it is needed.
    """

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._at = 0.0
        self._value = None
        self._l = threading.Lock()
        self._loading = threading.Lock()

    def get(self, loader):
        now = time.monotonic()
        with self._l:
            fresh = self._value is not None and now - self._at < self.ttl
            current = self._value
        if fresh:
            return current
        if not self._loading.acquire(blocking=False):
            # someone else is refreshing: use what we have rather than pile on
            if current is not None:
                return current
            with self._loading:                  # nothing cached yet — we must wait
                with self._l:
                    if self._value is not None:
                        return self._value
        try:
            value = loader()
            with self._l:
                self._value, self._at = value, time.monotonic()
            return value
        finally:
            self._loading.release()

    def invalidate(self):
        with self._l:
            self._value, self._at = None, 0.0


def close():
    """Close the pool (script teardown; also how a test repoints MCP_STATE_DB_URL)."""
    global _pool, _pool_url
    clear_secret_cache()                 # re-resolve MCP_STATE_DB_URL on the next call
    with _lock:
        if _pool is not None:
            try:
                _pool.close()
            except Exception:
                pass
        _pool, _pool_url = None, None


reset_for_tests = close      # the tests' name for it
