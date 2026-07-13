"""Taint tracking (spec §4.5, closes v7 flaw B1).

The privileged planner never reads untrusted tool-result text directly. When a
tool returns content, the gateway records the untrusted string values in a
per-session taint set. If a later tool call carries an argument value that
derives from tainted content, the call is flagged: its risk tier is escalated
(a tainted value can never silently drive a write), and the approval preview
highlights exactly which arguments are tainted and where they came from.

This is a pragmatic, string-provenance form of the control/data-flow separation
in CaMeL: full capability typing is the production target; this catches the core
attack (injected instructions from a document steering a privileged tool call)
and makes it visible and blockable.
"""
import re
import threading
import time

from . import statestore

_WORD = re.compile(r"[^\s]{%d,}")
_SESSION_CAP = 4000        # newest snippets kept per session (bounds a huge result)
_SNIPPET_TTL = 24 * 3600   # stale taint ages out (sessions are re-established daily)


class TaintStore:
    """Phase 3: with the shared backend on, taint follows the SESSION, not the
    process — content that tainted on one gateway instance escalates the very next
    call even when the load balancer routes it to another instance. In-memory
    behaviour (tests, single instance without the DB) is unchanged."""

    def __init__(self, min_len: int = 12):
        self.min_len = min_len
        self._sessions: dict[str, set[str]] = {}
        self._sources: dict[str, dict[str, str]] = {}  # session -> {snippet: source_label}
        self._lock = threading.Lock()
        self._swept: dict[str, float] = {}             # session -> last housekeeping (DB mode)

    def _db(self) -> bool:
        return statestore.enabled()

    def _extract(self, text: str):
        """Normalized snippets of meaningful length (shared by both backends)."""
        for chunk in re.split(r"[\n\r]+", text):
            chunk = chunk.strip()
            if len(chunk) >= self.min_len:
                yield _norm(chunk)
            # also index long individual tokens (e.g. emails, ids)
            for m in re.finditer(r"\S{%d,}" % self.min_len, chunk):
                yield _norm(m.group(0))

    def add_untrusted(self, session: str, text: str, source: str):
        """Record substrings of untrusted content as tainted for this session."""
        if not isinstance(text, str):
            return
        if self._db():
            now = time.time()
            rows = [(session, key, source, now) for key in set(self._extract(text))]
            if not rows:
                return
            with statestore.cx() as c:
                c.cursor().executemany(
                    "INSERT INTO taint_snippets (session, key, source, ts) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (session, key) DO NOTHING", rows)
            self._housekeep(session, now)
            return
        with self._lock:
            s = self._sessions.setdefault(session, set())
            src = self._sources.setdefault(session, {})
            for key in self._extract(text):
                s.add(key)
                src.setdefault(key, source)

    def _housekeep(self, session: str, now: float):
        """Cap the session's snippet set and age out stale taint — but not on every call.

        These two DELETEs used to run on every single tool result: two database round
        trips per mediated call, on the hot path, to enforce a 4000-snippet cap that a
        normal session never approaches. They now run at most once a minute per session
        (and the cap is generous), which is exactly as effective and ~14 ms/call cheaper.
        """
        last = self._swept.get(session, 0.0)
        if now - last < 60:
            return
        self._swept[session] = now
        if len(self._swept) > 5000:                # bound the bookkeeping dict itself
            for s in [s for s, t in self._swept.items() if now - t > _SNIPPET_TTL]:
                self._swept.pop(s, None)
        with statestore.cx() as c:
            c.execute(
                "DELETE FROM taint_snippets WHERE session = %s AND key IN ("
                "  SELECT key FROM taint_snippets WHERE session = %s "
                "  ORDER BY ts DESC OFFSET %s)", (session, session, _SESSION_CAP))
            c.execute("DELETE FROM taint_snippets WHERE session = %s AND ts < %s",
                      (session, now - _SNIPPET_TTL))

    def _fetch(self, session: str) -> dict[str, str]:
        return {key: source for key, source in statestore.all_rows(
            "SELECT key, source FROM taint_snippets WHERE session = %s", (session,))}

    @staticmethod
    def _match(tainted: dict[str, str], value: str) -> str | None:
        v = _norm(value)
        for key, source in tainted.items():
            if key in v or v in key:
                return source or "untrusted_content"
        return None

    def check(self, session: str, value: str) -> str | None:
        """Return the source label if `value` overlaps tainted content, else None."""
        if not isinstance(value, str) or len(value.strip()) < self.min_len:
            return None
        if self._db():
            tainted = self._fetch(session)
            return self._match(tainted, value) if tainted else None
        with self._lock:
            tainted = self._sessions.get(session)
            if not tainted:
                return None
            v = _norm(value)
            for key in tainted:
                if key in v or v in key:
                    return self._sources.get(session, {}).get(key, "untrusted_content")
        return None

    def check_args(self, session: str, arguments: dict) -> list[dict]:
        """Return [{arg, source}] for each tainted argument value."""
        args = {k: v for k, v in (arguments or {}).items()
                if isinstance(v, str) and len(v.strip()) >= self.min_len}
        if not args:
            return []
        if self._db():
            tainted = self._fetch(session)         # ONE round-trip for all args
            if not tainted:
                return []
            return [{"arg": k, "source": src} for k, v in args.items()
                    if (src := self._match(tainted, v))]
        hits = []
        for k, v in args.items():
            src = self.check(session, v)
            if src:
                hits.append({"arg": k, "source": src})
        return hits

    def clear(self, session: str):
        if self._db():
            statestore.run("DELETE FROM taint_snippets WHERE session = %s", (session,))
            return
        with self._lock:
            self._sessions.pop(session, None)
            self._sources.pop(session, None)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()
