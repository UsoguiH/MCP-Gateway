"""Anomaly & alert engine — turns the gateway's raw signals into actionable alerts.

The gateway records everything but, until now, never *noticed* anything. This
module derives real alerts from the live audit chain, circuit breakers, registry
state, lockouts, and the approval queue, so an operator is told when something is
wrong instead of having to go look. It is deterministic (no ML): threshold- and
rule-based detection over data the gateway already holds.

Severities: critical (act now) | warning (investigate) | info (awareness).
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict

from . import audit, auth, settings
from .controls import kill_switch


def _mk(sev: str, key: str, title: str, detail: str, source: str, ts=None, count=1) -> dict:
    return {"id": key, "severity": sev, "title": title, "detail": detail,
            "source": source, "ts": ts, "count": count}


def evaluate(gw, *, window: int | None = None, approval_sla_seconds: int | None = None,
             login_fail_threshold: int | None = None,
             error_rate_threshold: float | None = None) -> dict:
    """Compute the current alert set. `gw` is the Gateway (for breaker/registry/
    approvals). Reads the last `window` audit records for behavioural signals.

    Thresholds default to the runtime settings overlay (admin-editable in the console),
    and each rule can be switched off there — the Alerts page toggles are now real
    (A3/A6). Explicit keyword args still win, so tests can pin exact values.
    """
    cfg = settings.get("anomaly")
    window = int(window if window is not None else cfg["window"])
    approval_sla_seconds = int(approval_sla_seconds if approval_sla_seconds is not None
                               else cfg["approval_sla_seconds"])
    login_fail_threshold = int(login_fail_threshold if login_fail_threshold is not None
                               else cfg["login_fail_threshold"])
    error_rate_threshold = float(error_rate_threshold if error_rate_threshold is not None
                                 else cfg["error_rate_threshold"])
    on = settings.alert_rule_enabled

    alerts: list[dict] = []
    now = time.time()
    records = audit.tail(window)

    # 1. Audit chain integrity — tamper evidence. Highest priority.
    # Cached full verification: a tamper alert that is at most 60 s old is exactly right
    # for an alert engine, and an O(n) HMAC re-pass on every poll of the Anomaly page
    # would cost seconds of CPU per request.
    ok, msg = audit.chain_status()
    if not ok:
        alerts.append(_mk("critical", "audit_chain", "Audit chain integrity FAILED",
                          msg, "audit", now))

    # 2. Circuit breakers open — a server is failing or quarantined.
    if on("breaker_open"):
        for server, b in gw._breaker.items():
            if gw._breaker_open(server):
                alerts.append(_mk("critical", f"breaker:{server}",
                                  f"Circuit breaker open — {server}",
                                  f"{server} exceeded the failure threshold and is quarantined "
                                  f"({b.get('fails', 0)} consecutive failures).",
                                  "circuit-breaker", now))

    # 3. Registry: quarantined tools (rug-pull / definition drift).
    if on("tool_quarantine"):
        for e in gw.registry.entries.values():
            if e.get("status") == "quarantined":
                alerts.append(_mk("critical", f"quarantine:{e['server']}:{e['tool']}",
                                  f"Tool quarantined — {e['server']}.{e['tool']}",
                                  f"Reason: {e.get('quarantine_reason', 'definition drift')}. "
                                  "Review and re-pin before it can run again.", "registry", now))

    # 4. Pending tool onboarding — new tools awaiting Risk-Board approval.
    pending = gw.registry.pending()
    if pending:
        alerts.append(_mk("warning", "onboarding",
                          f"{len(pending)} tool(s) awaiting onboarding approval",
                          "Newly discovered tools are pending and cannot be called until approved.",
                          "registry", now, count=len(pending)))

    # 5. Approval-queue SLA — Tier-2/3 actions waiting too long go unnoticed.
    stale = [p for p in gw.approvals.list_pending()
             if now - p.get("created", now) > approval_sla_seconds] if on("approval_sla") else []
    if stale:
        oldest = max(now - p.get("created", now) for p in stale)
        alerts.append(_mk("warning", "approval_sla",
                          f"{len(stale)} approval(s) breaching SLA",
                          f"Oldest has waited {int(oldest // 60)} min (SLA "
                          f"{approval_sla_seconds // 60} min). A held action is stalling.",
                          "approvals", now, count=len(stale)))

    # ---- behavioural signals from the audit tail ----
    login_fails: Counter = Counter()
    tool_calls: Counter = Counter()
    tool_errors = 0
    tool_total = 0
    blocked = 0
    first_seen: dict[str, set] = defaultdict(set)   # user -> set(tool) they invoked
    last_ts_by_key: dict[str, float] = {}
    for r in records:
        ev = r.get("event", "")
        ts = r.get("ts")
        if ev == "login_failed":
            login_fails[r.get("user", "unknown")] += 1
        elif ev == "tool_call":
            tool_total += 1
            if r.get("user") and r.get("tool"):
                first_seen[r["user"]].add(r["tool"])
                tool_calls[r["tool"]] += 1
        elif ev == "tool_error":
            tool_total += 1
            tool_errors += 1
        elif ev in ("killswitch_engage", "identity_revoked", "step_up_required",
                    "login_locked_out"):
            blocked += 1
        if ts:
            last_ts_by_key[ev] = ts

    # 6. Brute-force / credential stuffing — repeated login failures per identity.
    for user, n in (login_fails.items() if on("login_failures") else []):
        if n >= login_fail_threshold:
            alerts.append(_mk("warning", f"loginfail:{user}",
                              f"Repeated login failures — {user}",
                              f"{n} failed sign-ins for {user} in the recent window "
                              "(possible credential stuffing / brute force).",
                              "auth", last_ts_by_key.get("login_failed"), count=n))

    # 7. Locked-out identities (anti-hammering fired).
    lk = _safe(auth.lockout_status, {}) if on("lockout") else {}
    for sub, v in (lk or {}).items():
        alerts.append(_mk("warning", f"lockout:{sub}", f"Identity locked out — {sub}",
                          f"{v.get('fails', 0)} failed attempts; auto-unlocks in "
                          f"{v.get('locked_for', 0)}s. Clear it after out-of-band checks.",
                          "auth", now))

    # 8. Elevated tool error rate — a backend or agent is misbehaving.
    if tool_total >= 10 and on("error_rate"):
        rate = tool_errors / tool_total
        if rate >= error_rate_threshold:
            alerts.append(_mk("warning", "error_rate",
                              f"Elevated tool error rate — {rate*100:.0f}%",
                              f"{tool_errors} errors in {tool_total} recent tool calls.",
                              "traffic", now))

    # 9. Containment currently active (kill switch) — awareness banner.
    active = _safe(kill_switch.active, [])
    if active:
        alerts.append(_mk("info", "killswitch_active",
                          f"Kill switch active ({len(active)} scope(s))",
                          "Containment is engaged: " + ", ".join(active[:5]) + ".",
                          "containment", now, count=len(active)))

    # 10. Revoked identities present — awareness.
    rev = _safe(auth.revoked, [])
    if rev:
        alerts.append(_mk("info", "revoked",
                          f"{len(rev)} identity(ies) revoked",
                          "Revoked: " + ", ".join(rev[:5]) + ".", "identity", now, count=len(rev)))

    sev_rank = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda a: (sev_rank.get(a["severity"], 3), -(a.get("count") or 0)))
    summary = Counter(a["severity"] for a in alerts)
    return {
        "alerts": alerts,
        "summary": {"critical": summary.get("critical", 0),
                    "warning": summary.get("warning", 0),
                    "info": summary.get("info", 0), "total": len(alerts)},
        "evaluated_at": now,
        "window": window,
    }


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default
