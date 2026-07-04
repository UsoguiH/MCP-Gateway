"""Reference MCP server #2 — mock write actions (test fixture).

Simulates a system-of-record with reversible and irreversible actions so the
gateway's HITL tiers can be exercised:
  update_record  -> Tier 1 (reversible write, policy auto-approved)
  send_message   -> Tier 2 (outbound, human approval)
  delete_record  -> Tier 3 (destructive, two-person approval)

Writes land in data/actions_state.json so effects are visible and auditable.
Runs over stdio; the gateway spawns it.
"""
import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("actions")

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "actions_state.json"


def _load() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {
        "records": {
            "7": {"name": "Case 7 - facility access request", "status": "open"},
            "8": {"name": "Case 8 - procurement ticket", "status": "open"},
        },
        "sent_messages": [],
        "log": [],
    }


def _save(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


# Each tool accepts a gateway-injected `credential` (the backend auth secret the
# server would use to reach its system of record). The gateway supplies it at
# dispatch; the model never sees it. The server acknowledges receipt via
# `authenticated` but never echoes the secret value.
def _auth(cred: str) -> bool:
    return bool(cred)


@mcp.tool()
def update_record(record_id: str, status: str, credential: str = "") -> str:
    """Update the status field of a record (reversible write)."""
    state = _load()
    rec = state["records"].get(record_id)
    if not rec:
        return json.dumps({"error": f"record {record_id} not found"})
    old = rec["status"]
    rec["status"] = status
    state["log"].append({"ts": time.time(), "action": "update", "record": record_id,
                         "from": old, "to": status})
    _save(state)
    return json.dumps({"ok": True, "record": record_id, "old_status": old,
                       "new_status": status, "authenticated": _auth(credential)})


@mcp.tool()
def send_message(recipient: str, body: str, credential: str = "") -> str:
    """Send a message to a recipient (outbound action)."""
    state = _load()
    state["sent_messages"].append({"ts": time.time(), "recipient": recipient, "body": body})
    state["log"].append({"ts": time.time(), "action": "send", "recipient": recipient})
    _save(state)
    return json.dumps({"ok": True, "sent_to": recipient, "authenticated": _auth(credential)})


@mcp.tool()
def delete_record(record_id: str, credential: str = "") -> str:
    """Permanently delete a record (irreversible, destructive)."""
    state = _load()
    if record_id not in state["records"]:
        return json.dumps({"error": f"record {record_id} not found"})
    del state["records"][record_id]
    state["log"].append({"ts": time.time(), "action": "delete", "record": record_id})
    _save(state)
    return json.dumps({"ok": True, "deleted": record_id, "authenticated": _auth(credential)})


@mcp.tool()
def list_records(credential: str = "") -> str:
    """List all records and their statuses (read-only)."""
    return json.dumps({"records": _load()["records"], "authenticated": _auth(credential)},
                      ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()  # stdio
