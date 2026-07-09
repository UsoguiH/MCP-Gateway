"""In-dashboard notification center — the delivery channel for gateway events.

Instead of email/webhooks, the gateway surfaces everything an admin must not miss
in the dashboard's right panel: approvals waiting, breakers opening, quarantines,
containment, lockouts, operator lifecycle changes. Notifications derive from the
audit chain (one integration point — every module already records there), persist
to DATA_DIR so they survive a restart, and carry read/unread state per deployment
(single admin console; per-operator read state is a future refinement).

Dedupe: repeated identical events (e.g. a brute-force burst of login_failed)
collapse into one unread notification with a bumped count instead of a flood.
"""
from __future__ import annotations

import json
import threading
import time
import uuid

from .config import DATA_DIR

_FILE = DATA_DIR / "notifications.json"
_LOCK = threading.Lock()
_MAX = 300                      # ring buffer: keep the newest N


def _load() -> list[dict]:
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save(items: list[dict]):
    _FILE.write_text(json.dumps(items[-_MAX:], indent=1, ensure_ascii=False),
                     encoding="utf-8")


def notify(severity: str, title: str, detail: str = "", source: str = "gateway",
           key: str | None = None) -> dict:
    """Append a notification. If `key` matches an UNREAD notification with the same
    key, bump its count and timestamp instead of stacking duplicates."""
    with _LOCK:
        items = _load()
        if key:
            for n in reversed(items):
                if n.get("key") == key and not n.get("read"):
                    n["count"] = n.get("count", 1) + 1
                    n["ts"] = round(time.time(), 3)
                    n["detail"] = detail or n.get("detail", "")
                    _save(items)
                    return n
        n = {"id": uuid.uuid4().hex[:12], "ts": round(time.time(), 3),
             "severity": severity, "title": title, "detail": detail,
             "source": source, "read": False, "count": 1}
        if key:
            n["key"] = key
        items.append(n)
        _save(items)
        return n


def list_all(limit: int = 100) -> list[dict]:
    with _LOCK:
        items = _load()
    return list(reversed(items[-limit:]))          # newest first


def unread_count() -> int:
    with _LOCK:
        return sum(1 for n in _load() if not n.get("read"))


def mark_read(ids: list[str] | None = None, mark_all: bool = False) -> int:
    """Mark notifications read (by id, or everything). Returns how many changed."""
    changed = 0
    with _LOCK:
        items = _load()
        want = set(ids or [])
        for n in items:
            if not n.get("read") and (mark_all or n["id"] in want):
                n["read"] = True
                changed += 1
        if changed:
            _save(items)
    return changed


def clear_read() -> int:
    """Drop notifications that have been read. Returns how many were removed."""
    with _LOCK:
        items = _load()
        keep = [n for n in items if not n.get("read")]
        removed = len(items) - len(keep)
        if removed:
            _save(keep)
    return removed


# ---------------------------------------------------------------------------
# audit-chain subscriber: map security events -> notifications
# ---------------------------------------------------------------------------
# Each entry: event -> (severity, title_fn, detail_fn, key_fn|None). key_fn makes
# repeats collapse. Events not listed produce no notification (tool_call etc. are
# traffic, not news).

def _t(entry, field, fallback="?"):
    return entry.get(field) or fallback


_RULES: dict[str, tuple] = {
    "approval_requested": (
        "warning",
        lambda e: f"Approval needed — {_t(e,'server')}.{_t(e,'tool')}",
        lambda e: f"Requested by {_t(e,'user')} · tier {e.get('tier')} · "
                  f"{e.get('approvals_required', 1)} signer(s) required.",
        None),
    "approval_vote": (
        "info",
        lambda e: f"Approval {_t(e,'action')}d by {_t(e,'approver')}",
        lambda e: f"Request {_t(e,'approval_id')} · status: {_t(e,'status', e.get('action',''))}.",
        None),
    "approval_expired": (
        "warning",
        lambda e: f"Approval expired — {_t(e,'server')}.{_t(e,'tool')}",
        lambda e: f"Requested by {_t(e,'requester')}; waited {e.get('waited_hours')}h with no "
                  "decision and was auto-expired. The requester must re-issue it.",
        None),
    "approval_cancelled": (
        "info",
        lambda e: f"Approval cancelled — {_t(e,'requester')}",
        lambda e: f"{_t(e,'reason','requester removed')} (by {_t(e,'by')}).",
        None),
    "circuit_open": (
        "critical",
        lambda e: f"Circuit breaker opened — {_t(e,'server')}",
        lambda e: f"Server quarantined for {e.get('cooldown_s')}s after repeated failures.",
        lambda e: f"breaker:{_t(e,'server')}"),
    "registry_event": (
        "warning",
        lambda e: ("Tool drift quarantined" if e.get("type") == "drift_quarantine"
                   else "New tool discovered"),
        lambda e: f"{_t(e,'key')} ({_t(e,'status','see registry')}).",
        lambda e: f"registry:{e.get('type')}:{_t(e,'key')}"),
    "killswitch_engage": (
        "critical",
        lambda e: f"Kill switch ENGAGED — {_t(e,'scope')}",
        lambda e: f"Containment engaged by {_t(e,'by')}.",
        None),
    "killswitch_release": (
        "info",
        lambda e: f"Kill switch released — {_t(e,'scope')}",
        lambda e: f"Released by {_t(e,'by')}.",
        None),
    "login_failed": (
        "warning",
        lambda e: f"Failed sign-in — {_t(e,'user')}",
        lambda e: "Repeated failures collapse into this alert; check Identities for lockout.",
        lambda e: f"loginfail:{_t(e,'user')}"),
    "login_locked_out": (
        "warning",
        lambda e: f"Identity locked out — {_t(e,'user')}",
        lambda e: "Anti-hammering lockout engaged after repeated failures.",
        lambda e: f"lockout:{_t(e,'user')}"),
    "identity_revoked": (
        "warning",
        lambda e: f"Identity revoked — {_t(e,'sub')}",
        lambda e: f"Revoked by {_t(e,'by')}. All tokens for this subject are now refused.",
        None),
    "identity_unrevoked": (
        "info",
        lambda e: f"Identity restored — {_t(e,'sub')}",
        lambda e: f"Restored by {_t(e,'by')}.",
        None),
    "tool_error": (
        "warning",
        lambda e: f"Tool error — {_t(e,'server')}.{_t(e,'tool')}",
        lambda e: str(e.get("error", ""))[:140],
        lambda e: f"toolerr:{_t(e,'server')}"),
    "gateway_startup": (
        "info",
        lambda e: "Gateway started",
        lambda e: f"{len(e.get('servers', []))} MCP server(s) connected.",
        None),
    "tool_quarantined": (
        "critical",
        lambda e: f"Tool quarantined — {_t(e,'server')}.{_t(e,'tool')}",
        lambda e: _t(e, "reason", "definition drift"),
        None),
    "oauth_client_registered": (
        "info",
        lambda e: "New OAuth client registered",
        lambda e: f"{_t(e,'client_name','(unnamed)')} · {_t(e,'client_id')}.",
        None),
    "oauth_client_revoked": (
        "warning",
        lambda e: f"OAuth client revoked — {_t(e,'client_name', e.get('client_id','?'))}",
        lambda e: f"Revoked by {_t(e,'by')}; its refresh tokens are dead.",
        None),
    "apikey_created": (
        "info",
        lambda e: f"API key created — {_t(e,'name')}",
        lambda e: f"For {_t(e,'sub')} · scope {_t(e,'scope')} · by {_t(e,'by')}.",
        None),
    "apikey_revoked": (
        "warning",
        lambda e: f"API key revoked — {_t(e,'name', e.get('kid','?'))}",
        lambda e: f"Revoked by {_t(e,'by')}.",
        None),
    "operator_created": (
        "info",
        lambda e: f"Operator created — {_t(e,'sub')}",
        lambda e: f"Role {_t(e,'role')} · clearance {_t(e,'clearance')} · by {_t(e,'by')}.",
        None),
    "operator_offboarded": (
        "warning",
        lambda e: f"Operator offboarded — {_t(e,'sub')}",
        lambda e: f"Removed by {_t(e,'by')}; sessions terminated, credentials purged.",
        None),
    "operator_role_changed": (
        "info",
        lambda e: f"Role changed — {_t(e,'sub')}",
        lambda e: f"{_t(e,'old_role')}/{_t(e,'old_clearance')} → "
                  f"{_t(e,'role')}/{_t(e,'clearance')} by {_t(e,'by')}.",
        None),
    "password_reset_forced": (
        "info",
        lambda e: f"Password reset — {_t(e,'sub')}",
        lambda e: f"Temporary password issued by {_t(e,'by')}; rotation forced at next login.",
        None),
    "sessions_terminated": (
        "warning",
        lambda e: f"Signed out everywhere — {_t(e,'sub')}",
        lambda e: f"All sessions and refresh tokens killed by {_t(e,'by')}.",
        None),
    "mcp_session_terminated": (
        "info",
        lambda e: f"MCP session terminated — {_t(e,'sub')}",
        lambda e: f"Session {_t(e,'sid')} disconnected by {_t(e,'by')}.",
        None),
    "server_stopped": (
        "warning",
        lambda e: f"Server stopped — {_t(e,'server')}",
        lambda e: f"Stopped by {_t(e,'by')}; its tools are offline until started.",
        None),
    "server_started": (
        "info",
        lambda e: f"Server started — {_t(e,'server')}",
        lambda e: f"Started by {_t(e,'by')}.",
        None),
    "server_restarted": (
        "info",
        lambda e: f"Server restarted — {_t(e,'server')}",
        lambda e: f"Restarted by {_t(e,'by')}.",
        None),
    "server_drained": (
        "warning",
        lambda e: f"Server drained — {_t(e,'server')}",
        lambda e: f"New calls refused (by {_t(e,'by')}); in-flight work finishes.",
        None),
    "server_undrained": (
        "info",
        lambda e: f"Server resumed — {_t(e,'server')}",
        lambda e: f"Traffic restored by {_t(e,'by')}.",
        None),
    "breaker_reset": (
        "info",
        lambda e: f"Circuit breaker reset — {_t(e,'server')}",
        lambda e: f"Force-closed by {_t(e,'by')}.",
        None),
    "server_added": (
        "info",
        lambda e: f"Server added — {_t(e,'server')}",
        lambda e: f"Connected by {_t(e,'by')} · {e.get('tools', 0)} tool(s) discovered.",
        None),
    "server_removed": (
        "warning",
        lambda e: f"Server removed — {_t(e,'server')}",
        lambda e: f"Removed by {_t(e,'by')}.",
        None),
    "mfa_enrolled": (
        "info",
        lambda e: f"MFA enrolled — {_t(e,'user')}",
        lambda e: f"Authenticator (re)enrolled by {_t(e,'by')}.",
        None),
}


def on_audit_event(entry: dict):
    """Called by audit.record() for every event; must never raise."""
    try:
        rule = _RULES.get(entry.get("event", ""))
        if not rule:
            return
        sev, title_fn, detail_fn, key_fn = rule
        notify(sev, title_fn(entry), detail_fn(entry),
               source=entry.get("event", "audit"),
               key=key_fn(entry) if key_fn else None)
    except Exception:
        pass
