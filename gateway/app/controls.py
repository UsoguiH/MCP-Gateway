"""Runtime safety controls: kill switch + rate limiter (spec §4.4.8).

Kill switch scopes: global | server:<name> | tool:<server>:<tool> | user:<sub>.
Each engagement records WHO engaged it, WHY, and (optionally) when it auto-releases
— the most powerful button in the product must leave a trail and must not be able
to strand the org because someone forgot to release it (Phase 2, A7).

Rate limiter: sliding-window budgets read from the runtime settings overlay at call
time (an admin's change applies to the next request, no restart), and introspectable
so the console can show real consumption instead of a hardcoded zero (A9/A15).
"""
import json
import threading
import time

from . import settings
from .config import DATA_DIR

_KILL_FILE = DATA_DIR / "killswitch.json"


class KillSwitch:
    """Durable: engaged scopes persist to data/killswitch.json so an incident-time
    kill survives a gateway restart (matching the UI's containment promise). Tests
    pass an isolated `path` so they never poison the shared production file.

    On-disk shape is a dict: scope -> {by, reason, ts, expires|None}. A legacy list
    of scopes (pre-Phase-2) still loads, so an in-flight containment is never lost
    by an upgrade.
    """

    def __init__(self, path=None):
        self._lock = threading.Lock()
        self._path = path or _KILL_FILE
        self._killed: dict[str, dict] = {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            raw = {}
        if isinstance(raw, list):                       # legacy: ["global", "server:x"]
            self._killed = {s: {"by": "?", "reason": "(engaged before reasons were recorded)",
                                "ts": None, "expires": None} for s in raw}
        elif isinstance(raw, dict):
            self._killed = {k: v for k, v in raw.items() if isinstance(v, dict)}

    def _save(self):
        self._path.write_text(json.dumps(self._killed, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    def _sweep(self) -> list[str]:
        """Drop scopes whose auto-expiry has passed. Caller holds the lock."""
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
        with self._lock:
            self._killed[scope] = {
                "by": by,
                "reason": (reason or "").strip()[:200],
                "ts": round(time.time(), 3),
                "expires": time.time() + ttl_minutes * 60 if ttl_minutes else None,
            }
            self._save()

    def release(self, scope: str):
        with self._lock:
            self._killed.pop(scope, None)
            self._save()

    def active(self) -> list[str]:
        with self._lock:
            self._sweep()
            return sorted(self._killed)

    def details(self) -> list[dict]:
        """Engaged scopes with who/why/when/auto-release — the console's containment view."""
        with self._lock:
            self._sweep()
            out = [{"scope": s, **m} for s, m in self._killed.items()]
        out.sort(key=lambda d: d.get("ts") or 0, reverse=True)
        return out

    def expired(self) -> list[str]:
        """Sweep and report auto-released scopes (the sweeper audits them)."""
        with self._lock:
            return self._sweep()

    def blocked(self, *, user: str, server: str, tool: str) -> str | None:
        with self._lock:
            self._sweep()
            for scope in (
                "global",
                f"server:{server}",
                f"tool:{server}:{tool}",
                f"user:{user}",
            ):
                if scope in self._killed:
                    return scope
        return None


class RateLimiter:
    """Sliding-window limiter whose ceiling is resolved per call.

    Accepts either a fixed `per_minute` int (a static limit) or a callable
    `limit_fn(key) -> int`, which lets the ceiling come from the settings overlay
    (admin-editable, no restart) and vary by key (per-server overrides).
    """

    def __init__(self, per_minute):
        self._limit_fn = (per_minute if callable(per_minute)
                          else (lambda _k, _n=int(per_minute): _n))
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def limit_for(self, key: str = "") -> int:
        return int(self._limit_fn(key))

    @property
    def per_minute(self) -> int:                    # back-compat for existing callers/tests
        return self.limit_for("")

    def allow(self, user: str) -> bool:
        now = time.time()
        limit = self.limit_for(user)
        with self._lock:
            window = [t for t in self._hits.get(user, []) if now - t < 60]
            if len(window) >= limit:
                self._hits[user] = window
                return False
            window.append(now)
            self._hits[user] = window
            return True

    def usage(self, key: str) -> int:
        """Calls made by `key` in the trailing 60 s (no side effects)."""
        now = time.time()
        with self._lock:
            return sum(1 for t in self._hits.get(key, []) if now - t < 60)

    def snapshot(self) -> list[dict]:
        """Live consumption per key — what the console's rate-limit bars now show."""
        now = time.time()
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
# from the settings overlay, so the console can retune them live.
rate_limiter = RateLimiter(lambda _k: settings.get("rate_limits", "per_user_per_minute"))
tool_limiter = RateLimiter(lambda _k: settings.get("rate_limits", "per_tool_per_minute"))
server_limiter = RateLimiter(lambda k: settings.rate_limit_for_server(k))
