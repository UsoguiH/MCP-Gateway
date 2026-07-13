"""Gateway self-page — the gateway finally monitors itself (Phase 2, A10/A11/A13/A23).

The console watched every server, tool, identity and call, and knew nothing about the
gateway process running it: no version, no uptime, no effective config, no idea whether
last night's backup ran, no warning that the TLS certificates it depends on expire in
three weeks. Those blind spots are how a system dies quietly on a Sunday.

Everything here is read-only introspection of the local process and its own files.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from . import statestore
from .config import CONFIG, DATA_DIR, POLICY, ROOT

VERSION = "1.0.0"                       # gateway control-plane version
STARTED_AT = time.time()

_TLS_DIR = ROOT / "deploy" / "tls"
_PKI_DIR = ROOT / "pki"
_BACKUP_DIRS = (Path("D:/Backups/mcp"), ROOT.parent / "Backups" / "mcp")

# Certificates the gateway's front door and identity layer depend on.
_CERT_FILES = (
    ("server", _TLS_DIR / "server.crt"),
    ("client (operator)", _TLS_DIR / "client.crt"),
    ("mTLS CA", _TLS_DIR / "ca.crt"),
    ("gateway CA", _PKI_DIR / "ca.cert.pem"),
)

WARN_DAYS = 30                          # amber below this; red once expired


# ---------------------------------------------------------------------------
# certificate expiry (A13)
# ---------------------------------------------------------------------------

def _cert_expiry(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        not_after = cert.not_valid_after_utc.timestamp()
        subject = cert.subject.rfc4514_string()
    except Exception:
        return None
    days = (not_after - time.time()) / 86400
    return {
        "not_after": round(not_after),
        "days_left": round(days, 1),
        "subject": subject[:120],
        "status": "expired" if days <= 0 else ("expiring" if days <= WARN_DAYS else "ok"),
    }


def certificates() -> list[dict]:
    """Every certificate this deployment depends on, with days left. An expiring cert is
    a guaranteed outage with a known date — the one class of failure that should never
    surprise anyone."""
    out = []
    for label, path in _CERT_FILES:
        info = _cert_expiry(path)
        if info:
            out.append({"name": label, "path": str(path.relative_to(ROOT)), **info})
    out.sort(key=lambda c: c["days_left"])
    return out


# ---------------------------------------------------------------------------
# backups (A10)
# ---------------------------------------------------------------------------

def backups() -> dict:
    """Status of the scheduled backup (scripts/backup.ps1 writes timestamped folders).
    A backup silently failing for three weeks is discovered on the day it is needed —
    unless something looks."""
    for root in _BACKUP_DIRS:
        try:
            if not root.is_dir():
                continue
            runs = sorted((d for d in root.iterdir() if d.is_dir()),
                          key=lambda d: d.stat().st_mtime, reverse=True)
            if not runs:
                continue
            latest = runs[0]
            age_h = (time.time() - latest.stat().st_mtime) / 3600
            size = sum(f.stat().st_size for f in latest.rglob("*") if f.is_file())
            return {
                "configured": True,
                "location": str(root),
                "latest": latest.name,
                "latest_ts": round(latest.stat().st_mtime),
                "age_hours": round(age_h, 1),
                "size_bytes": size,
                "retained_runs": len(runs),
                # daily schedule: anything older than ~36 h means the job is not running
                "status": "ok" if age_h <= 36 else "stale",
            }
        except OSError:
            continue
    return {"configured": False, "status": "unknown",
            "detail": "No backup runs found. scripts/backup.ps1 is scheduled at 02:00 daily."}


# ---------------------------------------------------------------------------
# disk & log growth (A23)
# ---------------------------------------------------------------------------

def storage() -> dict:
    """Disk headroom plus the size of the append-only stores that grow forever."""
    files = []
    total = 0
    for f in sorted(DATA_DIR.glob("*")):
        if f.is_file():
            size = f.stat().st_size
            total += size
            files.append({"name": f.name, "bytes": size,
                          "modified": round(f.stat().st_mtime)})
    files.sort(key=lambda x: x["bytes"], reverse=True)
    try:
        usage = shutil.disk_usage(DATA_DIR)
        disk = {"total_bytes": usage.total, "free_bytes": usage.free,
                "used_pct": round((usage.total - usage.free) / usage.total * 100, 1)}
    except OSError:
        disk = {}

    # growth rate of the audit chain: bytes/day since its first record
    audit_log = DATA_DIR / "audit_log.jsonl"
    growth = None
    if audit_log.exists():
        try:
            with open(audit_log, encoding="utf-8") as fh:
                first = fh.readline()
            import json as _json
            t0 = _json.loads(first).get("ts") if first.strip() else None
            days = max((time.time() - t0) / 86400, 0.01) if t0 else None
            if days:
                per_day = audit_log.stat().st_size / days
                free = disk.get("free_bytes")
                growth = {
                    "bytes_per_day": round(per_day),
                    "days_of_history": round(days, 1),
                    "days_until_full": round(free / per_day) if free and per_day > 0 else None,
                }
        except Exception:
            growth = None

    return {"data_dir": str(DATA_DIR), "data_bytes": total, "files": files[:15],
            "disk": disk, "audit_growth": growth}


# ---------------------------------------------------------------------------
# the page (A11)
# ---------------------------------------------------------------------------

def _redact(cfg: dict) -> dict:
    """Effective config with anything secret-shaped removed — this is a UI surface."""
    SECRET_HINTS = ("secret", "key", "password", "token", "pin")

    def walk(o):
        if isinstance(o, dict):
            return {k: ("***" if any(h in k.lower() for h in SECRET_HINTS)
                        and isinstance(v, (str, int)) else walk(v))
                    for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(cfg)


def overview(gw=None) -> dict:
    """Everything the gateway knows about itself, in one payload."""
    from . import settings
    now = time.time()
    uptime = now - STARTED_AT
    servers = sorted(gw.mcp.servers) if gw is not None else []
    tools = len(gw.mcp.all_tools()) if gw is not None else 0
    state_ok, state_msg = statestore.healthy()
    return {
        "version": VERSION,
        "env": os.environ.get("MCP_ENV", "development"),
        "started_at": round(STARTED_AT),
        "uptime_seconds": round(uptime),
        "pid": os.getpid(),
        "instance_id": statestore.instance_id(),
        "state_backend": {"backend": "postgres" if statestore.enabled() else "file",
                          "ok": state_ok, "detail": state_msg},
        "python": f"{os.sys.version_info.major}.{os.sys.version_info.minor}."
                  f"{os.sys.version_info.micro}",
        "servers": servers,
        "server_count": len(servers),
        "tool_count": tools,
        "maintenance": maintenance_status(),
        "certificates": certificates(),
        "backups": backups(),
        "storage": storage(),
        "settings_overrides": settings.overrides(),
        "effective_config": _redact({"auth": CONFIG.get("auth", {}),
                                     "gateway": CONFIG.get("gateway", {}),
                                     "approvals": CONFIG.get("approvals", {}),
                                     "registry": CONFIG.get("registry", {}),
                                     "audit": CONFIG.get("audit", {}),
                                     "policy": POLICY}),
        "generated_at": now,
    }


# ---------------------------------------------------------------------------
# maintenance mode (A11)
# ---------------------------------------------------------------------------
# Refuse new /mcp work while an operator patches or migrates, without killing the
# console (which is how you'd fix things) and without the finality of a kill switch.

_MAINT_FILE = DATA_DIR / "maintenance.json"
_maint_cache = statestore.TTLCache(1.0)


def maintenance_status() -> dict:
    if statestore.enabled():
        def _load():
            row = statestore.one("SELECT doc FROM kv WHERE name = 'maintenance'")
            return row[0] if row else {"enabled": False}
        m = _maint_cache.get(_load)
        return m if m.get("enabled") else {"enabled": False}
    try:
        import json
        m = json.loads(_MAINT_FILE.read_text(encoding="utf-8"))
        if m.get("enabled"):
            return m
    except (OSError, ValueError):
        pass
    return {"enabled": False}


def set_maintenance(enabled: bool, by: str = "?", message: str = "") -> dict:
    import json
    state = {"enabled": bool(enabled), "by": by,
             "message": (message or "Gateway is in maintenance — tool calls are paused.")[:200],
             "since": round(time.time(), 3)}
    if statestore.enabled():
        statestore.run(
            "INSERT INTO kv (name, doc, updated) VALUES ('maintenance', %s, %s) "
            "ON CONFLICT (name) DO UPDATE SET doc = EXCLUDED.doc, updated = EXCLUDED.updated",
            (json.dumps(state, ensure_ascii=False), time.time()))
        _maint_cache.invalidate()
        return state
    _MAINT_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return state
