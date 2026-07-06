"""HITL approval store (spec §5, closes v7 flaw B3).

Holds pending approvals. Tier 2 needs one approver; tier 3 needs two distinct
approvers. The requester can never approve their own request (separation of
duties). Approvals carry a normalized-text preview so the approver sees exactly
what the model sees (Unicode already sanitized upstream).

Durable: approvals are persisted to disk so a pending high-risk action is not
lost across a gateway restart (a restart must never silently drop an approval
awaiting a second approver).
"""
import json
import threading
import time
import uuid

from .config import DATA_DIR

_STORE_FILE = DATA_DIR / "approvals.json"


class ApprovalStore:
    def __init__(self, path=None):
        self._pending: dict[str, dict] = {}
        self._results: dict[str, dict] = {}     # aid -> executed result (in-memory only, not persisted)
        self._lock = threading.Lock()
        self._path = path or _STORE_FILE        # tests pass an isolated file
        self._load()

    def set_result(self, aid: str, result: dict):
        """Stash the executed result so the requesting agent can fetch it over MCP.
        In-memory only — result data is never written to disk with the approval."""
        with self._lock:
            self._results[aid] = result

    def get_result(self, aid: str) -> dict | None:
        with self._lock:
            return self._results.get(aid)

    def _load(self):
        try:
            self._pending = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            self._pending = {}

    def _save(self):
        self._path.write_text(json.dumps(self._pending, ensure_ascii=False), encoding="utf-8")

    def create(self, *, requester, server, tool, arguments, tier, approvals_required,
               preview, taint) -> dict:
        aid = uuid.uuid4().hex[:12]
        with self._lock:
            self._pending[aid] = {
                "id": aid,
                "requester": requester,
                "server": server,
                "tool": tool,
                "arguments": arguments,
                "tier": tier,
                "approvals_required": approvals_required,
                "approvals": [],       # list of usernames who approved
                "preview": preview,
                "taint": taint,
                "status": "pending",   # pending | approved | rejected
                "created": time.time(),
            }
            self._save()
            return dict(self._pending[aid])

    def list_pending(self) -> list[dict]:
        with self._lock:
            return [dict(a) for a in self._pending.values() if a["status"] == "pending"]

    def get(self, aid: str) -> dict | None:
        with self._lock:
            a = self._pending.get(aid)
            return dict(a) if a else None

    def approve(self, aid: str, approver: str) -> dict:
        with self._lock:
            a = self._pending.get(aid)
            if not a or a["status"] != "pending":
                return {"error": "not found or not pending"}
            if approver == a["requester"]:
                return {"error": "separation of duties: requester cannot approve own request"}
            if approver in a["approvals"]:
                return {"error": "approver already approved"}
            a["approvals"].append(approver)
            if len(a["approvals"]) >= a["approvals_required"]:
                a["status"] = "approved"
            self._save()
            return dict(a)

    def reject(self, aid: str, approver: str) -> dict:
        with self._lock:
            a = self._pending.get(aid)
            if not a or a["status"] != "pending":
                return {"error": "not found or not pending"}
            a["status"] = "rejected"
            a["rejected_by"] = approver
            self._save()
            return dict(a)

    def pop_if_resolved(self, aid: str) -> dict | None:
        with self._lock:
            a = self._pending.get(aid)
            if a and a["status"] in ("approved", "rejected"):
                return dict(a)
            return None
