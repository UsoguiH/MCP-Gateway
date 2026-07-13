"""HITL approval store (spec §5, closes v7 flaw B3).

Holds pending approvals. Tier 2 needs one approver; tier 3 needs two distinct
approvers. The requester can never approve their own request (separation of
duties). Approvals carry a normalized-text preview so the approver sees exactly
what the model sees (Unicode already sanitized upstream).

Durable: approvals are persisted (approvals.json, or the shared gwstate DB in
Phase-3 mode) so a pending high-risk action is not lost across a gateway restart.
In DB mode every vote runs in a row-locked transaction, so two approvers on two
gateway instances cannot double-approve or race the threshold.

Executed results: an approved call's result used to be in-memory only and died
with the process — the requesting agent could never fetch it after a restart
(Phase 3 task 2). In DB mode results are durable rows (the payload is already
DLP-masked by clearance before it gets here) and are pruned with the same
retention window as their approval. File mode keeps the old in-memory behaviour.

Lifecycle: a request left unapproved past `pending_ttl_hours` auto-EXPIRES (a
stale destructive action must never be rubber-stampable days later). Resolved
entries (approved / rejected / expired) are kept for `retention_hours` so the
requesting agent can still fetch its result, then pruned — the store can no
longer grow without bound.
"""
import json
import threading
import time
import uuid

from . import statestore
from .config import CONFIG, DATA_DIR

_STORE_FILE = DATA_DIR / "approvals.json"
_CFG = CONFIG.get("approvals", {}) or {}
PENDING_TTL_S = int(_CFG.get("pending_ttl_hours", 24) * 3600)
RETENTION_S = int(_CFG.get("retention_hours", 72) * 3600)


class ApprovalStore:
    def __init__(self, path=None, pending_ttl_s=None, retention_s=None):
        self._pending: dict[str, dict] = {}
        self._results: dict[str, dict] = {}     # aid -> executed result (file mode only)
        self._lock = threading.Lock()
        self._shared = path is None             # default store follows the backend
        self._path = path or _STORE_FILE        # tests pass an isolated file
        self._pending_ttl = pending_ttl_s or PENDING_TTL_S
        self._retention = retention_s or RETENTION_S
        if not self._db():
            self._load()

    def _db(self) -> bool:
        return self._shared and statestore.enabled()

    # -- executed results ------------------------------------------------------
    def set_result(self, aid: str, result: dict):
        """Stash the executed result so the requesting agent can fetch it over MCP.
        DB mode: durable (survives restarts and is visible from every instance);
        file mode: in-memory, as before."""
        if self._db():
            statestore.run(
                "INSERT INTO approval_results (aid, created, doc) VALUES (%s, %s, %s) "
                "ON CONFLICT (aid) DO UPDATE SET doc = EXCLUDED.doc",
                (aid, time.time(), json.dumps(result, ensure_ascii=False)))
            return
        with self._lock:
            self._results[aid] = result

    def get_result(self, aid: str) -> dict | None:
        if self._db():
            row = statestore.one("SELECT doc FROM approval_results WHERE aid = %s", (aid,))
            return row[0] if row else None
        with self._lock:
            return self._results.get(aid)

    # -- persistence (file mode) ------------------------------------------------
    def _load(self):
        try:
            self._pending = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            self._pending = {}

    def _save(self):
        self._prune_locked()
        self._path.write_text(json.dumps(self._pending, ensure_ascii=False), encoding="utf-8")

    def _db_put(self, a: dict):
        statestore.run(
            "INSERT INTO approvals (aid, status, requester, created, resolved_at, doc) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (aid) DO UPDATE SET status = EXCLUDED.status, "
            "resolved_at = EXCLUDED.resolved_at, doc = EXCLUDED.doc",
            (a["id"], a["status"], a["requester"], a["created"],
             a.get("resolved_at"), json.dumps(a, ensure_ascii=False)))

    def _db_prune(self, now: float | None = None):
        """Retention: resolved approvals AND their stashed results age out together."""
        cutoff = (now or time.time()) - self._retention
        statestore.run(
            "DELETE FROM approval_results WHERE aid IN "
            "(SELECT aid FROM approvals WHERE status != 'pending' "
            " AND coalesce(resolved_at, created) < %s)", (cutoff,))
        statestore.run(
            "DELETE FROM approvals WHERE status != 'pending' "
            "AND coalesce(resolved_at, created) < %s", (cutoff,))

    # -- lifecycle (call with self._lock held) --------------------------------
    def _expire_locked(self, now: float | None = None) -> list[dict]:
        """Mark pending requests older than the TTL as expired. Returns the newly
        expired entries so the caller can audit them."""
        now = now or time.time()
        expired = []
        for a in self._pending.values():
            if a["status"] == "pending" and now - a.get("created", now) > self._pending_ttl:
                a["status"] = "expired"
                a["resolved_at"] = now
                expired.append(dict(a))
        return expired

    def _prune_locked(self, now: float | None = None):
        """Drop resolved entries past the retention window (and their stashed
        results) so the store cannot grow without bound."""
        now = now or time.time()
        dead = [aid for aid, a in self._pending.items()
                if a["status"] != "pending"
                and now - a.get("resolved_at", a.get("created", now)) > self._retention]
        for aid in dead:
            self._pending.pop(aid, None)
            self._results.pop(aid, None)

    def expire_stale(self) -> list[dict]:
        """Expire overdue pending requests and persist. Returns the newly expired
        entries (callers record audit/notifications — the store stays I/O-free).
        DB mode is atomic (UPDATE .. RETURNING): with two instances sweeping
        concurrently, each expiry is claimed — and audited — exactly once."""
        if self._db():
            now = time.time()
            rows = statestore.all_rows(
                "UPDATE approvals SET status = 'expired', resolved_at = %s, "
                "doc = doc || jsonb_build_object('status', 'expired', 'resolved_at', %s::float8) "
                "WHERE status = 'pending' AND created < %s RETURNING doc",
                (now, now, now - self._pending_ttl))
            self._db_prune(now)
            return [r[0] for r in rows]
        with self._lock:
            expired = self._expire_locked()
            if expired:
                self._save()
            return expired

    def reject_all_for(self, requester: str, by: str = "system") -> list[dict]:
        """Cancel every pending request from `requester` (operator offboarded or
        revoked — an orphaned approval must never stay actionable)."""
        if self._db():
            now = time.time()
            rows = statestore.all_rows(
                "UPDATE approvals SET status = 'rejected', resolved_at = %s, "
                "doc = doc || jsonb_build_object('status', 'rejected', 'resolved_at', "
                "%s::float8, 'rejected_by', %s::text, 'reject_reason', 'requester removed') "
                "WHERE status = 'pending' AND requester = %s RETURNING doc",
                (now, now, by, requester))
            return [r[0] for r in rows]
        with self._lock:
            out = []
            for a in self._pending.values():
                if a["status"] == "pending" and a["requester"] == requester:
                    a["status"] = "rejected"
                    a["rejected_by"] = by
                    a["reject_reason"] = "requester removed"
                    a["resolved_at"] = time.time()
                    out.append(dict(a))
            if out:
                self._save()
            return out

    def create(self, *, requester, server, tool, arguments, tier, approvals_required,
               preview, taint) -> dict:
        aid = uuid.uuid4().hex[:12]
        a = {
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
        if self._db():
            self._db_put(a)
            return dict(a)
        with self._lock:
            self._pending[aid] = a
            self._save()
            return dict(a)

    def list_pending(self) -> list[dict]:
        if self._db():
            self.expire_stale()
            return [r[0] for r in statestore.all_rows(
                "SELECT doc FROM approvals WHERE status = 'pending' ORDER BY created")]
        with self._lock:
            if self._expire_locked():
                self._save()
            return [dict(a) for a in self._pending.values() if a["status"] == "pending"]

    def get(self, aid: str) -> dict | None:
        if self._db():
            row = statestore.one("SELECT doc FROM approvals WHERE aid = %s", (aid,))
            return row[0] if row else None
        with self._lock:
            a = self._pending.get(aid)
            return dict(a) if a else None

    def history(self, limit: int = 200) -> list[dict]:
        """Resolved approvals (approved / rejected / expired), newest first — the
        audit-friendly 'who decided what, when' view retained within the window."""
        if self._db():
            return [r[0] for r in statestore.all_rows(
                "SELECT doc FROM approvals WHERE status != 'pending' "
                "ORDER BY coalesce(resolved_at, created) DESC LIMIT %s", (limit,))]
        with self._lock:
            done = [dict(a) for a in self._pending.values() if a["status"] != "pending"]
        done.sort(key=lambda a: a.get("resolved_at", a.get("created", 0)), reverse=True)
        return done[:limit]

    # -- voting ------------------------------------------------------------------
    def _vote_locked_row(self, cur, aid: str):
        """Fetch one approval FOR UPDATE inside the caller's transaction: two
        concurrent votes (any instance, any worker) serialize on the row."""
        row = cur.execute("SELECT doc FROM approvals WHERE aid = %s FOR UPDATE",
                          (aid,)).fetchone()
        return row[0] if row else None

    def _vote_write(self, cur, a: dict):
        cur.execute(
            "UPDATE approvals SET status = %s, resolved_at = %s, doc = %s WHERE aid = %s",
            (a["status"], a.get("resolved_at"), json.dumps(a, ensure_ascii=False), a["id"]))

    def approve(self, aid: str, approver: str) -> dict:
        if self._db():
            with statestore.tx() as cur:
                a = self._vote_locked_row(cur, aid)
                if a and a["status"] == "pending" and \
                        time.time() - a.get("created", 0) > self._pending_ttl:
                    a["status"] = "expired"
                    a["resolved_at"] = time.time()
                    self._vote_write(cur, a)
                    return {"error": "request expired — ask the requester to re-issue it"}
                if not a or a["status"] != "pending":
                    return {"error": "not found or not pending"}
                if approver == a["requester"]:
                    return {"error": "separation of duties: requester cannot approve own request"}
                if approver in a["approvals"]:
                    return {"error": "approver already approved"}
                a["approvals"].append(approver)
                if len(a["approvals"]) >= a["approvals_required"]:
                    a["status"] = "approved"
                    a["resolved_at"] = time.time()
                self._vote_write(cur, a)
                return dict(a)
        with self._lock:
            a = self._pending.get(aid)
            if a and a["status"] == "pending" and \
                    time.time() - a.get("created", 0) > self._pending_ttl:
                a["status"] = "expired"
                a["resolved_at"] = time.time()
                self._save()
                return {"error": "request expired — ask the requester to re-issue it"}
            if not a or a["status"] != "pending":
                return {"error": "not found or not pending"}
            if approver == a["requester"]:
                return {"error": "separation of duties: requester cannot approve own request"}
            if approver in a["approvals"]:
                return {"error": "approver already approved"}
            a["approvals"].append(approver)
            if len(a["approvals"]) >= a["approvals_required"]:
                a["status"] = "approved"
                a["resolved_at"] = time.time()
            self._save()
            return dict(a)

    def reject(self, aid: str, approver: str) -> dict:
        if self._db():
            with statestore.tx() as cur:
                a = self._vote_locked_row(cur, aid)
                if not a or a["status"] != "pending":
                    return {"error": "not found or not pending"}
                a["status"] = "rejected"
                a["rejected_by"] = approver
                a["resolved_at"] = time.time()
                self._vote_write(cur, a)
                return dict(a)
        with self._lock:
            a = self._pending.get(aid)
            if not a or a["status"] != "pending":
                return {"error": "not found or not pending"}
            a["status"] = "rejected"
            a["rejected_by"] = approver
            a["resolved_at"] = time.time()
            self._save()
            return dict(a)
