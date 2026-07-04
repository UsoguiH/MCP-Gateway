"""Runtime safety controls: kill switch + rate limiter (spec §4.4.8).

Kill switch scopes: global | server:<name> | tool:<server>:<tool> | user:<sub>.
Rate limiter: sliding-window per-user tool-call budget.
"""
import threading
import time

from .config import GATEWAY


class KillSwitch:
    def __init__(self):
        self._killed: set[str] = set()
        self._lock = threading.Lock()

    def engage(self, scope: str):
        with self._lock:
            self._killed.add(scope)

    def release(self, scope: str):
        with self._lock:
            self._killed.discard(scope)

    def active(self) -> list[str]:
        with self._lock:
            return sorted(self._killed)

    def blocked(self, *, user: str, server: str, tool: str) -> str | None:
        with self._lock:
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
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, user: str) -> bool:
        now = time.time()
        with self._lock:
            window = [t for t in self._hits.get(user, []) if now - t < 60]
            if len(window) >= self.per_minute:
                self._hits[user] = window
                return False
            window.append(now)
            self._hits[user] = window
            return True


kill_switch = KillSwitch()
# Three independent rate-limit keys (blueprint Layer 7): contain a runaway user,
# a costly/destructive tool, and one compromised server respectively.
rate_limiter = RateLimiter(GATEWAY["rate_limit_calls_per_minute"])
tool_limiter = RateLimiter(GATEWAY.get("rate_limit_per_tool_per_minute", 10))
server_limiter = RateLimiter(GATEWAY.get("rate_limit_per_server_per_minute", 60))
