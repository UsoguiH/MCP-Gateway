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

_READ_HINTS = ("search", "read", "list", "get", "lookup", "find", "view", "query")
_TIER1_HINTS = ("update", "set", "modify", "edit", "assign", "create", "add")
_TIER2_HINTS = ("send", "email", "notify", "message", "post", "publish", "export")
_TIER3_HINTS = ("delete", "remove", "drop", "purge", "destroy", "wipe")


def tool_fingerprint(tool: dict) -> str:
    payload = json.dumps(
        {"name": tool["name"], "description": tool["description"], "schema": tool["schema"]},
        sort_keys=True, ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _default_tier(name: str) -> int:
    n = name.lower()
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
        """Compare discovered tools against pinned entries. Returns list of change events."""
        events = []
        seen = set()
        for t in tools:
            key = self._key(t["server"], t["name"])
            seen.add(key)
            fp = tool_fingerprint(t)
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
                }
                events.append({"type": "new_tool", "key": key,
                               "tier": self.entries[key]["tier"], "status": status})
            elif entry["fingerprint"] != fp:
                entry["status"] = "quarantined"
                entry["quarantine_reason"] = "definition_drift"
                entry["pending_fingerprint"] = fp
                events.append({"type": "drift_quarantine", "key": key})
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
            e["status"] = "active"
            e["quarantine_reason"] = None
            self._save()

    def quarantine(self, server: str, tool: str, reason: str):
        e = self.get(server, tool)
        if e:
            e["status"] = "quarantined"
            e["quarantine_reason"] = reason
            self._save()
