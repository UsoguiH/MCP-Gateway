"""Tool risk registry with hash pinning (spec §4.4.3, closes v7 flaws B4/B7).

The registry is the gateway-owned source of truth for each tool's risk tier.
Server-declared MCP annotations are advisory only and never set the tier.

Hash pinning defends against tool rug-pulls: at approval time we pin the SHA-256
of each tool's (name, description, schema). If a server later changes a tool's
description or schema, the recomputed hash won't match the pin and the tool is
auto-quarantined pending human re-review.

Default tiering heuristic for first discovery (a human then confirms):
  read-only-looking names           -> tier 0
  update/set/modify names           -> tier 1
  send/email/notify/outbound names  -> tier 2
  delete/remove/drop/purge names    -> tier 3
Unknown/ambiguous writes default to tier 2 (fail toward human review).
"""
import hashlib
import json
import threading

from . import statestore
from .config import CONFIG, DATA_DIR

_REG_FILE = DATA_DIR / "tool_registry.json"
_LOCK = threading.Lock()
# Governance: dev auto-activates new tools; production requires Risk-Board approval.
_REQUIRE_APPROVAL = (CONFIG.get("registry", {}) or {}).get("require_approval", False)

_READ_HINTS = ("search", "read", "list", "get", "lookup", "find", "view", "query",
               "describe", "show", "explain", "count", "select", "stat", "info",
               "check", "compare", "is_", "status", "size", "usage", "ratio",
               "distinct", "blocking", "inspect",
               # Retrieval/rendering verbs. Without these, harmless read-only tools
               # (extract_tables, screenshot_page, convert_document) fell to the
               # ambiguous default of tier 2 and demanded human approval for EVERY
               # read — which is how approvers are trained to rubber-stamp, and
               # rubber-stamping is what makes the tier-2 gate worthless when it
               # finally matters.
               "extract", "screenshot", "convert", "render", "preview", "summar")
_TIER1_HINTS = ("update", "set", "modify", "edit", "assign", "create", "add",
                "insert", "upsert", "rename", "refresh", "import", "analyze",
                "vacuum", "star", "watch", "fork")
_TIER2_HINTS = ("send", "email", "notify", "message", "post", "publish", "export",
                "merge", "grant", "revoke", "transfer", "submit", "upload")
_TIER3_HINTS = ("delete", "remove", "drop", "purge", "destroy", "wipe", "truncate",
                "terminate",
                # Arbitrary code execution is the most dangerous thing a tool can offer.
                # It is not a "write" — it is every write, plus every read, in one call.
                "evaluate", "eval", "execute", "exec_", "run_code", "shell", "command")


# Curated tiers for the connectors WE author. Gateway-owned, exactly like the heuristic:
# the key is "<server>:<tool>" and the server name comes from OUR config, never from the
# server's own claims — so a hostile MCP server cannot name a tool `read_page` and inherit
# a safe tier by pretending to be `browser`. The heuristic guesses; this is where we say
# what we actually know, and it is reviewed in code.
_CURATED_TIERS: dict[str, int] = {
    # browser — reading the web is safe; acting on it, or running code in it, is not.
    "browser:list_allowed_domains": 0,
    "browser:read_page": 0,
    "browser:get_page_links": 0,
    "browser:extract_tables": 0,
    "browser:screenshot_page": 0,
    "browser:search_page_text": 0,
    "browser:fill_and_submit": 2,      # submits a form on a remote site, in the user's name
    "browser:evaluate_javascript": 3,  # arbitrary JS in the page's origin: two-person

    # markitdown — pure read-only conversion of documents that files-mcp already exposes.
    "markitdown:list_supported_formats": 0,
    "markitdown:convert_document": 0,
    "markitdown:describe_document": 0,
    "markitdown:convert_url": 2,       # reaches OUT of the network; approval-gated

    # qdrant — searching memory is a read; writing to it is reversible; deleting is not.
    "qdrant:list_collections": 0,
    "qdrant:search": 0,
    "qdrant:search_vectors": 0,
    "qdrant:get_point": 0,
    "qdrant:count_points": 0,
    "qdrant:create_collection": 1,
    "qdrant:store": 1,                 # adding a passage is reversible (delete_points)
    "qdrant:upsert_vectors": 1,
    "qdrant:delete_points": 3,         # irreversible loss of knowledge
    "qdrant:delete_collection": 3,     # destroys an entire knowledge base
}


def tool_fingerprint(tool: dict) -> str:
    payload = json.dumps(
        {"name": tool["name"], "description": tool["description"], "schema": tool["schema"]},
        sort_keys=True, ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_READ_PREFIXES = ("is_", "has_", "get_", "list_", "read_", "show_", "describe_",
                  "check_", "count_", "search_", "compare_", "explain_", "view_")


def _default_tier(name: str, server: str = "") -> int:
    """Risk tier at first discovery. A curated entry for a connector we author wins; the
    name heuristic is the fallback for everything else, and it fails toward human review."""
    curated = _CURATED_TIERS.get(f"{server}:{name}")
    if curated is not None:
        return curated
    n = name.lower()
    if n.startswith(_READ_PREFIXES):   # unambiguous read/predicate prefix wins
        return 0                       # (e.g. is_pull_request_merged has "merge" inside)
    if any(h in n for h in _TIER3_HINTS):
        return 3
    if any(h in n for h in _TIER2_HINTS):
        return 2
    if any(h in n for h in _TIER1_HINTS):
        return 1
    if any(h in n for h in _READ_HINTS):
        return 0
    return 2  # ambiguous -> human review


class Registry:
    """Phase 3: with the shared backend on, entries live in the gwstate DB so a
    Risk-Board decision on one instance gates calls on every instance. The local
    dict becomes a short-TTL read cache; writes go through per-entry upserts, and
    reconcile() runs under an advisory lock so two instances booting together
    discover each tool exactly once."""

    def __init__(self):
        self._entries: dict[str, dict] = {}
        self._cache_at = 0.0
        self._reload_lock = threading.Lock()
        if not self._db():
            self._load()
        else:
            self._reload()

    def _db(self) -> bool:
        return statestore.enabled()

    @property
    def entries(self) -> dict[str, dict]:
        if self._db():
            self._maybe_reload()
        return self._entries

    @entries.setter
    def entries(self, value: dict[str, dict]):
        self._entries = value

    def _maybe_reload(self, ttl: float = 2.0):
        """Refresh the cache at most every `ttl` seconds — and with only ONE thread
        doing it.

        This is on the hot path twice over: every mediated call reads one entry, and
        tools/list reads one PER TOOL (243 of them). Without single-flight, the moment the
        TTL lapsed every in-flight request raced to re-read all ~235 rows at once — and
        because that made the request slower, the TTL then lapsed again *during* the same
        tools/list loop, which re-read them again. It fed itself: tools/list measured 17 s
        at p50 with 40 concurrent clients, at 2 req/s.

        A thread that finds a refresh already in progress just uses the current cache. It
        is at most `ttl` stale — exactly the guarantee this cache always offered.
        """
        import time
        if time.monotonic() - self._cache_at < ttl:
            return
        if not self._reload_lock.acquire(blocking=False):
            return                              # another thread is already refreshing
        try:
            if time.monotonic() - self._cache_at >= ttl:
                self._reload()
        finally:
            self._reload_lock.release()

    def _reload(self):
        import time
        self._entries = {k: doc for k, doc in
                         statestore.all_rows("SELECT key, doc FROM registry_tools")}
        self._cache_at = time.monotonic()

    def _key(self, server: str, tool: str) -> str:
        return f"{server}:{tool}"

    def _load(self):
        if _REG_FILE.exists():
            self._entries = json.loads(_REG_FILE.read_text(encoding="utf-8"))

    def _save(self):
        # file mode only: DB mode writes per-entry (a bulk save of a 2 s-stale cache
        # could overwrite another instance's fresher row).
        with _LOCK:
            _REG_FILE.write_text(
                json.dumps(self._entries, indent=2, ensure_ascii=False), encoding="utf-8"
            )

    def _mutate(self, server: str, tool: str, fn):
        """Read-modify-write ONE entry safely in either backend.

        `fn(entry) -> False` aborts (no write); any other return commits. DB mode
        locks the row for the duration, so two admins on two instances cannot
        interleave a governance decision. Returns the entry after mutation, or
        None if it does not exist / fn aborted."""
        key = self._key(server, tool)
        if self._db():
            with statestore.tx() as cur:
                row = cur.execute("SELECT doc FROM registry_tools WHERE key = %s FOR UPDATE",
                                  (key,)).fetchone()
                if not row:
                    return None
                e = row[0]
                if fn(e) is False:
                    return None
                cur.execute("UPDATE registry_tools SET doc = %s WHERE key = %s",
                            (json.dumps(e, ensure_ascii=False), key))
            self._entries[key] = e            # keep the local cache coherent immediately
            return e
        e = self._entries.get(key)
        if e is None or fn(e) is False:
            return None
        self._save()
        return e

    def _save_entry(self, key: str, cur=None):
        """Write-through one entry (DB mode); file mode rewrites the whole file."""
        if not self._db():
            self._save()
            return
        doc = json.dumps(self._entries[key], ensure_ascii=False)
        sql = ("INSERT INTO registry_tools (key, doc) VALUES (%s, %s) "
               "ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc")
        if cur is not None:
            cur.execute(sql, (key, doc))
        else:
            statestore.run(sql, (key, doc))

    def reconcile(self, tools: list[dict]) -> list[dict]:
        """Compare discovered tools against pinned entries. Returns list of change events.

        The pinned DEFINITION (description + schema) is stored alongside the hash so an
        admin can (a) read a tool's schema before approving it and (b) see exactly what
        changed when drift quarantines it — approving a hash you can't inspect is not
        governance (A8/A24).
        """
        if self._db():
            with statestore.tx() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (statestore.LOCK_REGISTRY,))
                self._entries = {k: doc for k, doc in
                                 cur.execute("SELECT key, doc FROM registry_tools").fetchall()}
                events, dirty = self._reconcile_into_entries(tools)
                for key in dirty:
                    self._save_entry(key, cur=cur)
            import time
            self._cache_at = time.monotonic()
            return events
        events, _dirty = self._reconcile_into_entries(tools)
        self._save()
        return events

    def _reconcile_into_entries(self, tools: list[dict]) -> tuple[list[dict], set]:
        events = []
        dirty: set[str] = set()
        for t in tools:
            key = self._key(t["server"], t["name"])
            fp = tool_fingerprint(t)
            definition = {"description": t.get("description", ""), "schema": t.get("schema", {})}
            entry = self._entries.get(key)
            if entry is None:
                status = "pending" if _REQUIRE_APPROVAL else "active"
                self._entries[key] = {
                    "server": t["server"],
                    "tool": t["name"],
                    "tier": _default_tier(t["name"], t["server"]),
                    "fingerprint": fp,
                    "status": status,         # prod: pending until Risk-Board approves
                    "quarantine_reason": None,
                    "definition": definition,
                }
                dirty.add(key)
                events.append({"type": "new_tool", "key": key,
                               "tier": self._entries[key]["tier"], "status": status})
            elif entry["status"] == "rejected":
                continue                      # banned by an admin: never silently resurrect
            elif entry["fingerprint"] != fp:
                entry["status"] = "quarantined"
                entry["quarantine_reason"] = "definition_drift"
                entry["pending_fingerprint"] = fp
                entry["pending_definition"] = definition   # the "after" side of the diff
                dirty.add(key)
                events.append({"type": "drift_quarantine", "key": key})
            elif not entry.get("definition"):
                entry["definition"] = definition           # backfill pre-Phase-2 entries
                dirty.add(key)
        return events, dirty

    def get(self, server: str, tool: str) -> dict | None:
        return self.entries.get(self._key(server, tool))

    def tier(self, server: str, tool: str) -> int | None:
        e = self.get(server, tool)
        return e["tier"] if e else None

    def is_active(self, server: str, tool: str) -> bool:
        e = self.get(server, tool)
        return bool(e and e["status"] == "active")

    def set_tier(self, server: str, tool: str, tier: int):
        self._mutate(server, tool, lambda e: e.__setitem__("tier", tier))

    def approve_tool(self, server: str, tool: str) -> bool:
        """Risk-Board activation of a pending (newly-onboarded) tool."""
        def fn(e):
            if e["status"] != "pending":
                return False
            e["status"] = "active"
        return self._mutate(server, tool, fn) is not None

    def pending(self) -> list[dict]:
        return [e for e in self.entries.values() if e["status"] == "pending"]

    def approve_drift(self, server: str, tool: str):
        """Accept a drifted definition (re-pin) and reactivate."""
        def fn(e):
            if not e.get("pending_fingerprint"):
                return False
            e["fingerprint"] = e.pop("pending_fingerprint")
            if e.get("pending_definition"):
                e["definition"] = e.pop("pending_definition")
            e["status"] = "active"
            e["quarantine_reason"] = None
        self._mutate(server, tool, fn)

    def quarantine(self, server: str, tool: str, reason: str) -> bool:
        """Manual containment of one tool (admin) — narrower than a kill switch and
        it survives a restart because the registry is the gate every call passes."""
        def fn(e):
            e["status"] = "quarantined"
            e["quarantine_reason"] = reason or "manual"
        return self._mutate(server, tool, fn) is not None

    def unquarantine(self, server: str, tool: str) -> bool:
        """Release a manually quarantined tool. A tool quarantined by DRIFT is not
        released here — that path must go through approve_drift (re-pin the hash),
        so a definition change can never be waved through by accident."""
        def fn(e):
            if e["status"] != "quarantined" or e.get("pending_fingerprint"):
                return False
            e["status"] = "active"
            e["quarantine_reason"] = None
        return self._mutate(server, tool, fn) is not None

    def reject(self, server: str, tool: str, reason: str = "") -> bool:
        """Risk-Board REJECTION of a tool: it stays known and permanently inactive, and
        reconcile() will not resurrect it on the next discovery. The counterpart to
        approve_tool — until now an admin could only ever say yes."""
        def fn(e):
            e["status"] = "rejected"
            e["quarantine_reason"] = (reason or "rejected by Risk Board")[:200]
        return self._mutate(server, tool, fn) is not None

    def reinstate(self, server: str, tool: str) -> bool:
        """Undo a rejection — the tool returns to `pending` for a fresh decision."""
        def fn(e):
            if e["status"] != "rejected":
                return False
            e["status"] = "pending"
            e["quarantine_reason"] = None
        return self._mutate(server, tool, fn) is not None

    def drift_diff(self, server: str, tool: str) -> dict | None:
        """What actually changed in a quarantined tool: pinned vs pending definition."""
        e = self.get(server, tool)
        if not e or not e.get("pending_fingerprint"):
            return None
        old = e.get("definition") or {}
        new = e.get("pending_definition") or {}
        changed = [f for f in ("description", "schema") if old.get(f) != new.get(f)]
        return {
            "server": server, "tool": tool,
            "pinned_fingerprint": e["fingerprint"],
            "pending_fingerprint": e["pending_fingerprint"],
            "changed_fields": changed,
            "old": old, "new": new,
        }
