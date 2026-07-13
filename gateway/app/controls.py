"""Runtime safety controls: kill switch + rate limiter (spec §4.4.8).

Kill switch scopes: global | server:<name> | tool:<server>:<tool> | user:<sub>.
Each engagement records WHO engaged it, WHY, and (optionally) when it auto-releases
— the most powerful button in the product must leave a trail and must not be able
to strand the org because someone forgot to release it (Phase 2, A7).

Rate limiter: sliding-window budgets read from the runtime settings overlay at call
time (an admin's change applies to the next request, no restart), and introspectable
so the console can show real consumption instead of a hardcoded zero (A9/A15).

Phase 3: both controls are shared-state aware. With MCP_STATE_DB_URL set, the kill
switch persists to the gwstate database (an incident kill engaged on one node blocks
on every node ≤1 s later) and the named limiters count events in one shared window —
without it, two instances would each grant the full budget (split-brain doubling).
A limiter constructed without a `shared_name` (tests, the pre-auth login throttle)
stays in-process: unauthenticated traffic must never be able to write to the DB.
"""
import json
import threading
import time

from . import settings, statestore
from .config import DATA_DIR

_KILL_FILE = DATA_DIR / "killswitch.json"


class KillSwitch:
    """Durable: engaged scopes persist (killswitch.json, or the shared DB in
    Phase-3 mode) so an incident-time kill survives a gateway restart. Tests
    pass an isolated `path` so they never poison the shared production store.

    On-disk shape is a dict: scope -> {by, reason, ts, expires|None}. A legacy list
    of scopes (pre-Phase-2) still loads, so an in-flight containment is never lost
    by an upgrade.
    """

    def __init__(self, path=None):
        self._lock = threading.Lock()
        self._shared = path is None                 # default store follows the backend
        self._path = path or _KILL_FILE
        self._killed: dict[str, dict] = {}
        self._cache = statestore.TTLCache(1.0)
        if not self._db():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                raw = {}
            if isinstance(raw, list):                   # legacy: ["global", "server:x"]
                self._killed = {s: {"by": "?", "reason": "(engaged before reasons were recorded)",
                                    "ts": None, "expires": None} for s in raw}
            elif isinstance(raw, dict):
                self._killed = {k: v for k, v in raw.items() if isinstance(v, dict)}

    def _db(self) -> bool:
        return self._shared and statestore.enabled()

    def _save(self):
        self._path.write_text(json.dumps(self._killed, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    # -- shared-DB primitives ------------------------------------------------
    def _db_all(self, fresh: bool = False) -> dict[str, dict]:
        if fresh:
            self._cache.invalidate()
        def _load():
            return {scope: doc for scope, doc in
                    statestore.all_rows("SELECT scope, doc FROM killswitch")}
        return self._cache.get(_load)

    def _db_sweep(self) -> list[str]:
        rows = statestore.all_rows(
            "DELETE FROM killswitch WHERE (doc->>'expires') IS NOT NULL "
            "AND (doc->>'expires')::float8 <= %s RETURNING scope", (time.time(),))
        if rows:
            self._cache.invalidate()
        return [r[0] for r in rows]

    def _sweep(self) -> list[str]:
        """Drop scopes whose auto-expiry has passed. Caller holds the lock (file mode)."""
        now = time.time()
        dead = [s for s, m in self._killed.items()
                if m.get("expires") and m["expires"] <= now]
        for s in dead:
            self._killed.pop(s, None)
        if dead:
            self._save()
        return dead

    def engage(self, scope: str, by: str = "?", reason: str = "",
               ttl_minutes: int | None = None):
        meta = {
            "by": by,
            "reason": (reason or "").strip()[:200],
            "ts": round(time.time(), 3),
            "expires": time.time() + ttl_minutes * 60 if ttl_minutes else None,
        }
        if self._db():
            statestore.run(
                "INSERT INTO killswitch (scope, doc) VALUES (%s, %s) "
                "ON CONFLICT (scope) DO UPDATE SET doc = EXCLUDED.doc",
                (scope, json.dumps(meta)))
            self._cache.invalidate()
            return
        with self._lock:
            self._killed[scope] = meta
            self._save()

    def release(self, scope: str):
        if self._db():
            statestore.run("DELETE FROM killswitch WHERE scope = %s", (scope,))
            self._cache.invalidate()
            return
        with self._lock:
            self._killed.pop(scope, None)
            self._save()

    def active(self) -> list[str]:
        if self._db():
            self._db_sweep()
            return sorted(self._db_all(fresh=True))
        with self._lock:
            self._sweep()
            return sorted(self._killed)

    def details(self) -> list[dict]:
        """Engaged scopes with who/why/when/auto-release — the console's containment view."""
        if self._db():
            self._db_sweep()
            out = [{"scope": s, **m} for s, m in self._db_all(fresh=True).items()]
        else:
            with self._lock:
                self._sweep()
                out = [{"scope": s, **m} for s, m in self._killed.items()]
        out.sort(key=lambda d: d.get("ts") or 0, reverse=True)
        return out

    def expired(self) -> list[str]:
        """Sweep and report auto-released scopes (the sweeper audits them)."""
        if self._db():
            return self._db_sweep()
        with self._lock:
            return self._sweep()

    def blocked(self, *, user: str, server: str, tool: str) -> str | None:
        scopes = ("global", f"server:{server}", f"tool:{server}:{tool}", f"user:{user}")
        if self._db():
            killed = self._db_all()
            now = time.time()
            for scope in scopes:
                m = killed.get(scope)
                if m and not (m.get("expires") and m["expires"] <= now):
                    return scope
            return None
        with self._lock:
            self._sweep()
            for scope in scopes:
                if scope in self._killed:
                    return scope
        return None


class RateLimiter:
    """Sliding-window limiter whose ceiling is resolved per call.

    Accepts either a fixed `per_minute` int (a static limit) or a callable
    `limit_fn(key) -> int`, which lets the ceiling come from the settings overlay
    (admin-editable, no restart) and vary by key (per-server overrides).

    `shared_name` opts this limiter into the shared window (gwstate DB) when the
    Phase-3 backend is on: the budget is then enforced across every instance and
    worker instead of per process. The admission is one conditional INSERT, so two
    racing calls can over-admit by at most one — an acceptable bound for a limiter.
    """

    def __init__(self, per_minute, shared_name: str | None = None):
        self._limit_fn = (per_minute if callable(per_minute)
                          else (lambda _k, _n=int(per_minute): _n))
        self._name = shared_name
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_gc = 0.0

    def _db(self) -> bool:
        return self._name is not None and statestore.enabled()

    def limit_for(self, key: str = "") -> int:
        return int(self._limit_fn(key))

    @property
    def per_minute(self) -> int:                    # back-compat for existing callers/tests
        return self.limit_for("")

    def _db_gc(self, now: float):
        """Drop events older than any window cares about (piggybacks on traffic)."""
        if now - self._last_gc < 30:
            return
        self._last_gc = now
        statestore.run("DELETE FROM rate_events WHERE limiter = %s AND ts < %s",
                       (self._name, now - 120))

    def allow(self, user: str) -> bool:
        now = time.time()
        limit = self.limit_for(user)
        if self._db():
            row = statestore.one(
                "INSERT INTO rate_events (limiter, key, ts) "
                "SELECT %s, %s, %s WHERE (SELECT count(*) FROM rate_events "
                "  WHERE limiter = %s AND key = %s AND ts > %s) < %s RETURNING 1",
                (self._name, user, now, self._name, user, now - 60, limit))
            self._db_gc(now)
            return row is not None
        with self._lock:
            window = [t for t in self._hits.get(user, []) if now - t < 60]
            if len(window) >= limit:
                self._hits[user] = window
                return False
            window.append(now)
            self._hits[user] = window
            return True

    def charge(self, key: str):
        """Record one call against `key` WITHOUT checking the ceiling (the caller has
        already decided to admit it — see check_rate_limits)."""
        now = time.time()
        if self._db():
            statestore.run("INSERT INTO rate_events (limiter, key, ts) VALUES (%s, %s, %s)",
                           (self._name, key, now))
            return
        with self._lock:
            window = [t for t in self._hits.get(key, []) if now - t < 60]
            window.append(now)
            self._hits[key] = window

    def usage(self, key: str) -> int:
        """Calls made by `key` in the trailing 60 s (no side effects)."""
        now = time.time()
        if self._db():
            row = statestore.one(
                "SELECT count(*) FROM rate_events WHERE limiter = %s AND key = %s AND ts > %s",
                (self._name, key, now - 60))
            return int(row[0]) if row else 0
        with self._lock:
            return sum(1 for t in self._hits.get(key, []) if now - t < 60)

    def snapshot(self) -> list[dict]:
        """Live consumption per key — what the console's rate-limit bars now show."""
        now = time.time()
        if self._db():
            rows = statestore.all_rows(
                "SELECT key, count(*) FROM rate_events "
                "WHERE limiter = %s AND ts > %s GROUP BY key",
                (self._name, now - 60))
            out = [{"key": k, "used": int(n), "limit": self.limit_for(k)}
                   for k, n in rows if n]
        else:
            with self._lock:
                keys = list(self._hits)
                out = []
                for k in keys:
                    used = sum(1 for t in self._hits[k] if now - t < 60)
                    if used:
                        out.append({"key": k, "used": used, "limit": self.limit_for(k)})
        out.sort(key=lambda d: d["used"], reverse=True)
        return out


kill_switch = KillSwitch()
# Three independent rate-limit keys (blueprint Layer 7): contain a runaway user,
# a costly/destructive tool, and one compromised server respectively. Ceilings come
# from the settings overlay, so the console can retune them live. Each carries a
# shared_name so the budget is global across instances when the DB backend is on.
rate_limiter = RateLimiter(lambda _k: settings.get("rate_limits", "per_user_per_minute"),
                           shared_name="user")
tool_limiter = RateLimiter(lambda _k: settings.get("rate_limits", "per_tool_per_minute"),
                           shared_name="tool")
server_limiter = RateLimiter(lambda k: settings.rate_limit_for_server(k),
                             shared_name="server")

# Postgres is not on the same machine as the gateway, so every round trip costs real
# milliseconds and the hot path takes as few as possible. Checking the three budgets
# one at a time is three round trips for a control that is one decision; this does all
# three in a single statement (and, like the individual limiters, admits at most one
# extra call under a race — an acceptable bound for a rate limiter).
_TRIPLE_SQL = """
WITH lim(limiter, key, cap) AS (VALUES ('user', %(u)s, %(cu)s::int),
                                       ('tool', %(t)s, %(ct)s::int),
                                       ('server', %(s)s, %(cs)s::int)),
used AS (SELECT l.limiter, l.key, l.cap,
                (SELECT count(*) FROM rate_events r
                  WHERE r.limiter = l.limiter AND r.key = l.key AND r.ts > %(since)s) AS n
           FROM lim l),
over AS (SELECT limiter FROM used WHERE n >= cap),
ins AS (INSERT INTO rate_events (limiter, key, ts)
        SELECT limiter, key, %(now)s FROM used
         WHERE NOT EXISTS (SELECT 1 FROM over))
SELECT limiter FROM over LIMIT 1
"""


def check_rate_limits(*, user: str, server: str, tool: str) -> str | None:
    """Charge all three budgets atomically. Returns the name of the FIRST budget that
    refused ('per-user' | 'per-tool' | 'per-server'), or None when the call is admitted.

    Nothing is charged when any budget refuses — a call that never runs must not consume
    the other two budgets, or one throttled tool would starve a user's whole allowance.
    """
    tool_key = f"{user}:{server}:{tool}"
    if not statestore.enabled():
        # In-process: check all three, charge only if all three admit — same semantics
        # as the single-statement DB path below, so the two backends never disagree.
        for label, lim, key in (("per-user", rate_limiter, user),
                                ("per-tool", tool_limiter, tool_key),
                                ("per-server", server_limiter, server)):
            if lim.usage(key) >= lim.limit_for(key):
                return label
        for lim, key in ((rate_limiter, user), (tool_limiter, tool_key),
                         (server_limiter, server)):
            lim.charge(key)
        return None
    now = time.time()
    row = statestore.one(_TRIPLE_SQL, {
        "u": user, "cu": rate_limiter.limit_for(user),
        "t": tool_key, "ct": tool_limiter.limit_for(tool_key),
        "s": server, "cs": server_limiter.limit_for(server),
        "since": now - 60, "now": now,
    })
    if row is None:
        return None
    return {"user": "per-user", "tool": "per-tool", "server": "per-server"}[row[0]]
