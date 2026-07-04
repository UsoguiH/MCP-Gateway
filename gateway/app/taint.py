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

_WORD = re.compile(r"[^\s]{%d,}")


class TaintStore:
    def __init__(self, min_len: int = 12):
        self.min_len = min_len
        self._sessions: dict[str, set[str]] = {}
        self._sources: dict[str, dict[str, str]] = {}  # session -> {snippet: source_label}
        self._lock = threading.Lock()

    def add_untrusted(self, session: str, text: str, source: str):
        """Record substrings of untrusted content as tainted for this session."""
        if not isinstance(text, str):
            return
        with self._lock:
            s = self._sessions.setdefault(session, set())
            src = self._sources.setdefault(session, {})
            # Index normalized whitespace-collapsed snippets of meaningful length.
            for chunk in re.split(r"[\n\r]+", text):
                chunk = chunk.strip()
                if len(chunk) >= self.min_len:
                    key = _norm(chunk)
                    s.add(key)
                    src.setdefault(key, source)
                # also index long individual tokens (e.g. emails, ids)
                for m in re.finditer(r"\S{%d,}" % self.min_len, chunk):
                    key = _norm(m.group(0))
                    s.add(key)
                    src.setdefault(key, source)

    def check(self, session: str, value: str) -> str | None:
        """Return the source label if `value` overlaps tainted content, else None."""
        if not isinstance(value, str) or len(value.strip()) < self.min_len:
            return None
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
        hits = []
        for k, v in (arguments or {}).items():
            if isinstance(v, str):
                src = self.check(session, v)
                if src:
                    hits.append({"arg": k, "source": src})
        return hits

    def clear(self, session: str):
        with self._lock:
            self._sessions.pop(session, None)
            self._sources.pop(session, None)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()
