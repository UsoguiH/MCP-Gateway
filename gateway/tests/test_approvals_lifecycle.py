"""Unit tests for the HITL approval lifecycle: stale-request expiry, retention
pruning (the store can no longer grow without bound), orphaned-requester
cancellation, and the resolved-history view. No running gateway needed — these
drive ApprovalStore directly against an isolated temp file.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.approvals import ApprovalStore


def _store(tmp_path, ttl_s=3600, retention_s=7200) -> ApprovalStore:
    return ApprovalStore(path=tmp_path / "appr.json",
                         pending_ttl_s=ttl_s, retention_s=retention_s)


def _mk(store, requester="sara", tier=2, need=1):
    return store.create(requester=requester, server="actions", tool="send_message",
                        arguments={"to": "x"}, tier=tier, approvals_required=need,
                        preview="p", taint=[])


def test_pending_request_expires_after_ttl(tmp_path):
    s = _store(tmp_path, ttl_s=3600)
    a = _mk(s)
    # backdate it past the TTL
    s._pending[a["id"]]["created"] = time.time() - 4000
    expired = s.expire_stale()
    assert len(expired) == 1 and expired[0]["id"] == a["id"]
    assert s.get(a["id"])["status"] == "expired"
    assert s.list_pending() == []                      # no longer offered to approvers


def test_approve_after_expiry_is_refused(tmp_path):
    s = _store(tmp_path, ttl_s=3600)
    a = _mk(s)
    s._pending[a["id"]]["created"] = time.time() - 4000
    r = s.approve(a["id"], "noura")
    assert "error" in r and "expired" in r["error"]
    assert s.get(a["id"])["status"] == "expired"       # a stale action can't be rubber-stamped


def test_resolved_entries_are_pruned_after_retention(tmp_path):
    s = _store(tmp_path, ttl_s=3600, retention_s=7200)
    a = _mk(s)
    s.reject(a["id"], "noura")
    assert s.get(a["id"])["status"] == "rejected"
    # backdate resolution past retention, then any _save() prunes it
    s._pending[a["id"]]["resolved_at"] = time.time() - 8000
    s._save()
    assert s.get(a["id"]) is None                      # gone: store cannot grow forever
    assert s.get_result(a["id"]) is None


def test_pending_never_pruned_even_if_old(tmp_path):
    s = _store(tmp_path, ttl_s=999999, retention_s=1)
    a = _mk(s)
    s._pending[a["id"]]["created"] = time.time() - 100000
    s._save()                                          # prune must not touch pending
    assert s.get(a["id"])["status"] == "pending"


def test_reject_all_for_requester(tmp_path):
    s = _store(tmp_path)
    a1, a2 = _mk(s, "sara"), _mk(s, "sara")
    a3 = _mk(s, "khalid")
    cancelled = s.reject_all_for("sara", by="admin")
    assert {c["id"] for c in cancelled} == {a1["id"], a2["id"]}
    assert s.get(a1["id"])["status"] == "rejected"
    assert s.get(a1["id"])["reject_reason"] == "requester removed"
    assert s.get(a3["id"])["status"] == "pending"      # other requesters untouched


def test_history_returns_resolved_newest_first(tmp_path):
    s = _store(tmp_path)
    a1, a2, a3 = _mk(s), _mk(s), _mk(s)
    now = time.time()
    s.reject(a1["id"], "noura")
    s._pending[a1["id"]]["resolved_at"] = now - 60      # older, but within retention
    s.reject(a2["id"], "faisal")
    s._pending[a2["id"]]["resolved_at"] = now - 10      # newer
    hist = s.history()
    ids = [h["id"] for h in hist]
    assert ids[0] == a2["id"] and ids[1] == a1["id"]   # newest resolved first
    assert a3["id"] not in ids                          # still pending -> not in history


def test_two_person_still_requires_two_and_stamps_resolved(tmp_path):
    s = _store(tmp_path)
    a = _mk(s, "sara", tier=3, need=2)
    r1 = s.approve(a["id"], "noura")
    assert r1["status"] == "pending" and "resolved_at" not in r1
    r2 = s.approve(a["id"], "faisal")
    assert r2["status"] == "approved" and r2.get("resolved_at")
    # SoD still enforced
    b = _mk(s, "sara", tier=3, need=2)
    assert "error" in s.approve(b["id"], "sara")
