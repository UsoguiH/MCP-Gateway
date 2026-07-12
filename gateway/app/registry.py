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

from .config import CONFIG, DATA_DIR

_REG_FILE = DATA_DIR / "tool_registry.json"
_LOCK = threading.Lock()
# Governance: dev auto-activates new tools; production requires Risk-Board approval.
_REQUIRE_APPROVAL = (CONFIG.get("registry", {}) or {}).get("require_approval", False)

_READ_HINTS = ("search", "read", "list", "get", "lookup", "find", "view", "query",
               "describe", "show", "explain", "count", "select", "stat", "info",
               "check", "compare", "is_", "status", "size", "usage", "ratio",
               "distinct", "blocking", "inspect")
_TIER1_HINTS = ("update", "set", "modify", "edit", "assign", "create", "add",
                "insert", "upsert", "rename", "refresh", "import", "analyze",
                "vacuum", "star", "watch", "fork")
_TIER2_HINTS = ("send", "email", "notify", "message", "post", "publish", "export",
                "merge", "grant", "revoke", "transfer")
_TIER3_HINTS = ("delete", "remove", "drop", "purge", "destroy", "wipe", "truncate",
                "terminate")


def tool_fingerprint(tool: dict) -> str:
    payload = json.dumps(
        {"name": tool["name"], "description": tool["description"], "schema": tool["schema"]},
        sort_keys=True, ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_READ_PREFIXES = ("is_", "has_", "get_", "list_", "read_", "show_", "describe_",
                  "check_", "count_", "search_", "compare_", "explain_", "view_")


def _default_tier(name: str) -> int:
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
    def __init__(self):
        self.entries: dict[str, dict] = {}
        self._load()

    def _key(self, server: str, tool: str) -> str:
        return f"{server}:{tool}"

    def _load(self):
        if _REG_FILE.exists():
            self.entries = json.loads(_REG_FILE.read_text(encoding="utf-8"))

    def _save(self):
        with _LOCK:
            _REG_FILE.write_text(
                json.dumps(self.entries, indent=2, ensure_ascii=False), encoding="utf-8"
            )

    def reconcile(self, tools: list[dict]) -> list[dict]:
        """Compare discovered tools against pinned entries. Returns list of change events.

        The pinned DEFINITION (description + schema) is stored alongside the hash so an
        admin can (a) read a tool's schema before approving it and (b) see exactly what
        changed when drift quarantines it — approving a hash you can't inspect is not
        governance (A8/A24).
        """
        events = []
        seen = set()
        for t in tools:
            key = self._key(t["server"], t["name"])
            seen.add(key)
            fp = tool_fingerprint(t)
            definition = {"description": t.get("description", ""), "schema": t.get("schema", {})}
            entry = self.entries.get(key)
            if entry is None:
                status = "pending" if _REQUIRE_APPROVAL else "active"
                self.entries[key] = {
                    "server": t["server"],
                    "tool": t["name"],
                    "tier": _default_tier(t["name"]),
                    "fingerprint": fp,
                    "status": status,         # prod: pending until Risk-Board approves
                    "quarantine_reason": None,
                    "definition": definition,
                }
                events.append({"type": "new_tool", "key": key,
                               "tier": self.entries[key]["tier"], "status": status})
            elif entry["status"] == "rejected":
                continue                      # banned by an admin: never silently resurrect
            elif entry["fingerprint"] != fp:
                entry["status"] = "quarantined"
                entry["quarantine_reason"] = "definition_drift"
                entry["pending_fingerprint"] = fp
                entry["pending_definition"] = definition   # the "after" side of the diff
                events.append({"type": "drift_quarantine", "key": key})
            elif not entry.get("definition"):
                entry["definition"] = definition           # backfill pre-Phase-2 entries
        self._save()
        return events

    def get(self, server: str, tool: str) -> dict | None:
        return self.entries.get(self._key(server, tool))

    def tier(self, server: str, tool: str) -> int | None:
        e = self.get(server, tool)
        return e["tier"] if e else None

    def is_active(self, server: str, tool: str) -> bool:
        e = self.get(server, tool)
        return bool(e and e["status"] == "active")

    def set_tier(self, server: str, tool: str, tier: int):
        e = self.get(server, tool)
        if e:
            e["tier"] = tier
            self._save()

    def approve_tool(self, server: str, tool: str) -> bool:
        """Risk-Board activation of a pending (newly-onboarded) tool."""
        e = self.get(server, tool)
        if e and e["status"] == "pending":
            e["status"] = "active"
            self._save()
            return True
        return False

    def pending(self) -> list[dict]:
        return [e for e in self.entries.values() if e["status"] == "pending"]

    def approve_drift(self, server: str, tool: str):
        """Accept a drifted definition (re-pin) and reactivate."""
        e = self.get(server, tool)
        if e and e.get("pending_fingerprint"):
            e["fingerprint"] = e.pop("pending_fingerprint")
            if e.get("pending_definition"):
                e["definition"] = e.pop("pending_definition")
            e["status"] = "active"
            e["quarantine_reason"] = None
            self._save()

    def quarantine(self, server: str, tool: str, reason: str) -> bool:
        """Manual containment of one tool (admin) — narrower than a kill switch and
        it survives a restart because the registry is the gate every call passes."""
        e = self.get(server, tool)
        if not e:
            return False
        e["status"] = "quarantined"
        e["quarantine_reason"] = reason or "manual"
        self._save()
        return True

    def unquarantine(self, server: str, tool: str) -> bool:
        """Release a manually quarantined tool. A tool quarantined by DRIFT is not
        released here — that path must go through approve_drift (re-pin the hash),
        so a definition change can never be waved through by accident."""
        e = self.get(server, tool)
        if not e or e["status"] != "quarantined":
            return False
        if e.get("pending_fingerprint"):
            return False
        e["status"] = "active"
        e["quarantine_reason"] = None
        self._save()
        return True

    def reject(self, server: str, tool: str, reason: str = "") -> bool:
        """Risk-Board REJECTION of a tool: it stays known and permanently inactive, and
        reconcile() will not resurrect it on the next discovery. The counterpart to
        approve_tool — until now an admin could only ever say yes."""
        e = self.get(server, tool)
        if not e:
            return False
        e["status"] = "rejected"
        e["quarantine_reason"] = (reason or "rejected by Risk Board")[:200]
        self._save()
        return True

    def reinstate(self, server: str, tool: str) -> bool:
        """Undo a rejection — the tool returns to `pending` for a fresh decision."""
        e = self.get(server, tool)
        if not e or e["status"] != "rejected":
            return False
        e["status"] = "pending"
        e["quarantine_reason"] = None
        self._save()
        return True

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
