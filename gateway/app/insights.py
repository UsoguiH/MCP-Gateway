"""Audit-derived analytics — the truth behind the console's numbers (Phase 2, A2/A5/A16–A19).

The dashboard used to synthesize what it couldn't measure: a canned "+11.01%" delta, a
hardcoded weekly latency curve, a transport pie stuck at one value, em-dashes wherever a
duration belonged. Every one of those numbers exists in the audit chain — nobody had ever
computed it. This module does, from the one source of truth the gateway already keeps.

  * series()        — real traffic/latency time-series (bucketed audit timestamps)
  * tool_stats()    — calls, error rate, p50/p95 duration per tool
  * server_stats()  — the same per server (feeds the Servers table's latency column)
  * dlp_activity()  — masking rollup: by detector, by tool, by user
  * approval_aging()— time-to-decide + what is rotting in the queue right now
  * query()         — filtered, paginated audit search (+ CSV export) for investigations
"""
from __future__ import annotations

import csv
import io
import threading
import time
from collections import Counter, defaultdict

from . import audit

# Events that represent a mediated call (the traffic the console charts).
_CALL_EVENTS = ("tool_call", "tool_error", "blocked", "resource_read")
_MAX_SCAN = 20_000                     # cap the log walk so an admin page can't stall the gateway

# One dashboard load fans out to series + stats + ratelimits + dlp + aging + audit, and
# each one wants the audit tail. Re-reading and re-parsing a multi-MB JSONL six times per
# refresh is pure waste, so the parsed tail is cached and invalidated by the log's
# (size, mtime) — an append changes both, so a stale read is not possible.
_cache_lock = threading.Lock()
_cache: dict = {"sig": None, "records": []}


def _log_signature():
    try:
        st = audit._LOG.stat()
        return (st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def _records(limit: int = _MAX_SCAN) -> list[dict]:
    sig = _log_signature()
    with _cache_lock:
        if sig is not None and _cache["sig"] == sig:
            return _cache["records"]
    records = audit.tail(limit)
    with _cache_lock:
        _cache["sig"] = sig
        _cache["records"] = records
    return records


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100) * (len(s) - 1)))))
    return round(s[k], 1)


# ---------------------------------------------------------------------------
# time-series (A19) — replaces the synthetic trend curve
# ---------------------------------------------------------------------------

def series(hours: int = 24, buckets: int = 24) -> dict:
    """Bucket the audit tail into a real traffic + latency time-series.

    Returns evenly-spaced buckets covering the trailing `hours`, each with call counts
    by outcome and p50/p95 duration. Empty buckets are present (value 0) so the chart
    shows quiet periods honestly instead of interpolating over them.
    """
    hours = max(1, min(int(hours), 24 * 30))
    buckets = max(2, min(int(buckets), 240))
    now = time.time()
    span = hours * 3600
    start = now - span
    width = span / buckets

    slots = [{"t": round(start + i * width), "calls": 0, "errors": 0, "blocked": 0,
              "_durations": []} for i in range(buckets)]

    for r in _records():
        ts = r.get("ts")
        ev = r.get("event", "")
        if not ts or ts < start or ev not in _CALL_EVENTS:
            continue
        idx = min(buckets - 1, int((ts - start) / width))
        s = slots[idx]
        if ev == "blocked":
            s["blocked"] += 1
            continue
        s["calls"] += 1
        if ev == "tool_error":
            s["errors"] += 1
        d = r.get("duration_ms")
        if isinstance(d, (int, float)):
            s["_durations"].append(float(d))

    out = []
    for s in slots:
        durations = s.pop("_durations")
        out.append({**s, "p50_ms": _pct(durations, 50), "p95_ms": _pct(durations, 95)})

    total = sum(s["calls"] for s in out)
    half = len(out) // 2
    first, second = sum(s["calls"] for s in out[:half]), sum(s["calls"] for s in out[half:])
    # A real delta: second half vs first half of the window. None when there is no
    # baseline to compare against — the console renders "—", never a fabricated number.
    delta = round((second - first) / first * 100, 1) if first else None
    return {"buckets": out, "hours": hours, "total_calls": total, "delta_pct": delta,
            "generated_at": now}


# ---------------------------------------------------------------------------
# per-tool / per-server statistics (A5/A16)
# ---------------------------------------------------------------------------

def _stats_by(field: str) -> dict[str, dict]:
    agg: dict[str, dict] = defaultdict(
        lambda: {"calls": 0, "errors": 0, "blocked": 0, "last_ts": None, "_d": []})
    for r in _records():
        ev = r.get("event", "")
        key = r.get(field)
        if not key or ev not in _CALL_EVENTS:
            continue
        a = agg[key]
        if ev == "blocked":
            a["blocked"] += 1
        else:
            a["calls"] += 1
            if ev == "tool_error":
                a["errors"] += 1
        ts = r.get("ts")
        if ts and (a["last_ts"] is None or ts > a["last_ts"]):
            a["last_ts"] = ts
        d = r.get("duration_ms")
        if isinstance(d, (int, float)):
            a["_d"].append(float(d))
    out = {}
    for key, a in agg.items():
        durations = a.pop("_d")
        calls = a["calls"]
        out[key] = {
            **a,
            "success_pct": round((calls - a["errors"]) / calls * 100, 1) if calls else None,
            "avg_ms": round(sum(durations) / len(durations), 1) if durations else None,
            "p50_ms": _pct(durations, 50),
            "p95_ms": _pct(durations, 95),
            "samples": len(durations),
        }
    return out


def tool_stats() -> dict[str, dict]:
    return _stats_by("tool")


def server_stats() -> dict[str, dict]:
    return _stats_by("server")


# ---------------------------------------------------------------------------
# DLP activity rollup (A17)
# ---------------------------------------------------------------------------

def dlp_activity(window_hours: int = 24 * 7) -> dict:
    """Where PII is actually being found and masked — by detector, tool, and user.

    The events existed in the audit chain from day one; nothing ever aggregated them, so
    an admin could not answer "which tool leaks the most PII?" without grepping the log.
    """
    since = time.time() - window_hours * 3600
    by_detector: Counter = Counter()
    by_tool: Counter = Counter()
    by_user: Counter = Counter()
    masked_calls = detected_calls = 0
    for r in _records():
        if r.get("event") not in ("tool_call", "resource_read"):
            continue
        if (r.get("ts") or 0) < since:
            continue
        det = r.get("pii_detected") or []
        if not det:
            continue
        detected_calls += 1
        if r.get("pii_masked"):
            masked_calls += 1
        for kind in det:
            by_detector[kind] += 1
        label = f"{r.get('server', '?')}.{r.get('tool', 'resource')}"
        by_tool[label] += len(det)
        if r.get("user"):
            by_user[r["user"]] += len(det)
    return {
        "window_hours": window_hours,
        "detected_calls": detected_calls,
        "masked_calls": masked_calls,
        "unmasked_calls": detected_calls - masked_calls,   # cleared callers saw the raw value
        "by_detector": [{"type": k, "count": v} for k, v in by_detector.most_common()],
        "by_tool": [{"tool": k, "count": v} for k, v in by_tool.most_common(10)],
        "by_user": [{"user": k, "count": v} for k, v in by_user.most_common(10)],
        "total_detections": sum(by_detector.values()),
    }


# ---------------------------------------------------------------------------
# approval aging (A18)
# ---------------------------------------------------------------------------

def approval_aging(gw, sla_seconds: int | None = None) -> dict:
    """Queue health: what is waiting, how long, and how fast decisions actually happen."""
    from . import settings
    sla = int(sla_seconds if sla_seconds is not None
              else settings.get("anomaly", "approval_sla_seconds"))
    now = time.time()
    pending = []
    for p in gw.approvals.list_pending():
        age = now - p.get("created", now)
        pending.append({
            "id": p["id"], "server": p.get("server"), "tool": p.get("tool"),
            "requester": p.get("requester"), "tier": p.get("tier"),
            "age_seconds": round(age), "breaching_sla": age > sla,
            "signatures": len(p.get("approvals", [])),
            "approvals_required": p.get("approvals_required", 1),
        })
    pending.sort(key=lambda a: a["age_seconds"], reverse=True)

    # time-to-decide, from the audit chain: approval_requested -> approval_vote
    requested: dict[str, float] = {}
    decided: list[float] = []
    for r in _records():
        ev = r.get("event")
        aid = r.get("approval_id")
        if not aid:
            continue
        if ev == "approval_requested":
            requested[aid] = r.get("ts") or 0
        elif ev == "approval_vote" and aid in requested:
            dt = (r.get("ts") or 0) - requested.pop(aid)
            if dt >= 0:
                decided.append(dt)
    return {
        "pending": pending,
        "pending_count": len(pending),
        "breaching_sla": sum(1 for p in pending if p["breaching_sla"]),
        "sla_seconds": sla,
        "oldest_seconds": pending[0]["age_seconds"] if pending else 0,
        "decided_samples": len(decided),
        "median_decide_seconds": round(_pct(decided, 50) or 0),
        "p95_decide_seconds": round(_pct(decided, 95) or 0),
    }


# ---------------------------------------------------------------------------
# audit search + export (A2)
# ---------------------------------------------------------------------------

_EXPORT_FIELDS = ("ts", "event", "user", "server", "tool", "tier", "outcome", "reason",
                  "status", "duration_ms", "classification", "pii_masked", "hash")


def query(*, event: str = "", user: str = "", server: str = "", tool: str = "",
          text: str = "", since: float | None = None, until: float | None = None,
          limit: int = 100, offset: int = 0) -> dict:
    """Filtered, paginated audit search — the difference between an incident answered in
    minutes and one answered by SSH-ing in to grep a 2 MB JSONL file."""
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    needle = (text or "").lower()

    matched: list[dict] = []
    for r in _records():
        if event and r.get("event") != event:
            continue
        if user and r.get("user") != user:
            continue
        if server and r.get("server") != server:
            continue
        if tool and r.get("tool") != tool:
            continue
        ts = r.get("ts") or 0
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        if needle:
            hay = " ".join(str(v) for v in r.values()).lower()
            if needle not in hay:
                continue
        matched.append(r)

    matched.reverse()                                   # newest first
    page = matched[offset:offset + limit]
    return {"records": page, "total": len(matched), "limit": limit, "offset": offset,
            "has_more": offset + limit < len(matched)}


def facets() -> dict:
    """Distinct values for the audit filter dropdowns (events/users/servers/tools)."""
    ev, us, sv, tl = set(), set(), set(), set()
    for r in _records():
        ev.add(r.get("event", ""))
        if r.get("user"):
            us.add(r["user"])
        if r.get("server"):
            sv.add(r["server"])
        if r.get("tool"):
            tl.add(r["tool"])
    return {"events": sorted(x for x in ev if x), "users": sorted(us),
            "servers": sorted(sv), "tools": sorted(tl)}


def export_csv(records: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(_EXPORT_FIELDS), extrasaction="ignore",
                       lineterminator="\n")
    w.writeheader()
    for r in records:
        row = {k: r.get(k) for k in _EXPORT_FIELDS}
        if row.get("ts"):
            row["ts"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"]))
        w.writerow(row)
    return buf.getvalue()
