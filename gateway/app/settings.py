"""Runtime-editable settings — the write side of the admin console (Phase 2, A3/A6/A15).

Until now every knob lived in config.yaml / policy.yaml or was hardcoded in Python,
so "tighten the analyst rate limit" meant SSH + file edit + restart, and the console's
Alerts/Settings toggles persisted nothing at all. This module is a small, validated,
persisted OVERLAY on top of the YAML defaults:

    effective value = persisted override  ->  else YAML/config default

Every consumer (rate limiter, DLP, anomaly engine, approvals, session policy) reads
through here at call time, so an admin's change takes effect on the next request with
no restart. Writes are audited by the caller. The YAML files remain the deploy-time
baseline and are never rewritten — an override can always be dropped to fall back.
"""
from __future__ import annotations

import json
import threading
import time

from . import statestore
from .config import CONFIG, DATA_DIR, GATEWAY, POLICY

_FILE = DATA_DIR / "settings.json"
_LOCK = threading.Lock()
_overrides: dict = {}
_db_loaded_at = 0.0        # TTL on the DB read: an admin's change on one instance
_DB_TTL = 2.0              # is enforced on every other instance within ~2 s

_APPROVALS = CONFIG.get("approvals", {}) or {}
_AUTH = CONFIG.get("auth", {}) or {}

# Alert rules the anomaly engine evaluates; an admin may switch any of them off.
ALERT_RULES = ("breaker_open", "login_failures", "error_rate", "approval_sla",
               "tool_quarantine", "lockout")


def _defaults() -> dict:
    """The YAML/config baseline, in the same shape as the overlay."""
    return {
        "rate_limits": {
            "per_user_per_minute": int(GATEWAY["rate_limit_calls_per_minute"]),
            "per_tool_per_minute": int(GATEWAY.get("rate_limit_per_tool_per_minute", 10)),
            "per_server_per_minute": int(GATEWAY.get("rate_limit_per_server_per_minute", 60)),
            "per_server_overrides": {},          # server -> calls/min (beats the global)
        },
        "approvals": {
            "min_tier": int(POLICY.get("approval_min_tier", 2)),
            "pending_ttl_hours": int(_APPROVALS.get("pending_ttl_hours", 24)),
        },
        "dlp": {
            "enabled": True,
            "detectors": {"national_id": True, "iqama": True, "iban": True},
        },
        "anomaly": {
            "login_fail_threshold": 3,
            "error_rate_threshold": 0.20,
            "approval_sla_seconds": 900,
            "window": 500,
        },
        "alerts": {"rules": {r: True for r in ALERT_RULES}},
        # Console session policy (A12). `ttl_seconds` is effectively the IDLE window: an
        # active operator's token is silently renewed, so it only ever expires after they
        # stop working. `absolute_seconds` caps the total session regardless of activity —
        # past it, re-authentication is required. `warn_seconds` is how long before expiry
        # the console warns (it used to just log you out mid-approval, with no warning).
        "session": {
            "ttl_seconds": int(_AUTH.get("session_ttl_seconds", 1800)),          # 30 min idle
            "absolute_seconds": int(_AUTH.get("session_absolute_seconds", 28800)),  # 8 h cap
            "warn_seconds": int(_AUTH.get("expiry_warning_seconds", 120)),       # 2 min notice
        },
    }


# Bounds so a fat-fingered admin cannot disable the control plane from the UI.
_BOUNDS = {
    ("rate_limits", "per_user_per_minute"): (1, 10_000),
    ("rate_limits", "per_tool_per_minute"): (1, 10_000),
    ("rate_limits", "per_server_per_minute"): (1, 100_000),
    ("approvals", "min_tier"): (0, 3),
    ("approvals", "pending_ttl_hours"): (1, 720),
    ("anomaly", "login_fail_threshold"): (1, 1000),
    ("anomaly", "error_rate_threshold"): (0.01, 1.0),
    ("anomaly", "approval_sla_seconds"): (60, 86_400),
    ("anomaly", "window"): (50, 100_000),
    ("session", "ttl_seconds"): (60, 86_400),
    ("session", "absolute_seconds"): (300, 604_800),
    ("session", "warn_seconds"): (15, 3_600),
}


class SettingsError(ValueError):
    """A rejected settings write (unknown key, wrong type, out of bounds)."""


def _load():
    global _overrides, _db_loaded_at
    if statestore.enabled():
        _overrides = {section: doc for section, doc in
                      statestore.all_rows("SELECT section, doc FROM settings")}
        _db_loaded_at = time.monotonic()
        return
    try:
        _overrides = json.loads(_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _overrides = {}


def _refresh():
    """DB mode: pick up overrides written by other instances (TTL-bounded)."""
    if statestore.enabled() and time.monotonic() - _db_loaded_at >= _DB_TTL:
        _load()


def _save():
    # file mode only: DB mode writes per-section at the call sites (update/reset)
    _FILE.write_text(json.dumps(_overrides, indent=2, ensure_ascii=False), encoding="utf-8")


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def effective() -> dict:
    """Defaults merged with persisted overrides — what the gateway actually enforces."""
    with _LOCK:
        _refresh()
        return _merge(_defaults(), _overrides)


def overrides() -> dict:
    """Only the values an admin has changed (what makes this deployment non-default)."""
    with _LOCK:
        _refresh()
        return json.loads(json.dumps(_overrides))


def get(section: str, key: str | None = None):
    eff = effective().get(section, {})
    return eff if key is None else eff.get(key)


def _coerce(section: str, key: str, value, default):
    if isinstance(default, bool):                    # bool before int (bool is an int)
        if not isinstance(value, bool):
            raise SettingsError(f"{section}.{key} must be true/false")
        return value
    if isinstance(default, int) and not isinstance(default, bool):
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise SettingsError(f"{section}.{key} must be a whole number")
    elif isinstance(default, float):
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise SettingsError(f"{section}.{key} must be a number")
    lo_hi = _BOUNDS.get((section, key))
    if lo_hi and not (lo_hi[0] <= value <= lo_hi[1]):
        raise SettingsError(f"{section}.{key} must be between {lo_hi[0]} and {lo_hi[1]}")
    return value


def update(section: str, patch: dict) -> dict:
    """Apply a validated patch to one section. Returns the section's new effective value.
    Unknown sections/keys are refused so a typo can't silently do nothing."""
    defaults = _defaults()
    if section not in defaults:
        raise SettingsError(f"unknown settings section '{section}'")
    if not isinstance(patch, dict) or not patch:
        raise SettingsError("patch must be a non-empty object")
    base = defaults[section]
    clean: dict = {}
    for key, value in patch.items():
        if key not in base:
            raise SettingsError(f"unknown key '{section}.{key}'")
        default = base[key]
        if key == "per_server_overrides":
            if not isinstance(value, dict):
                raise SettingsError("per_server_overrides must be an object of server -> calls/min")
            ov = {}
            for srv, lim in value.items():
                try:
                    lim = int(lim)
                except (TypeError, ValueError):
                    raise SettingsError(f"rate limit for '{srv}' must be a whole number")
                if not (1 <= lim <= 100_000):
                    raise SettingsError(f"rate limit for '{srv}' must be between 1 and 100000")
                ov[str(srv)] = lim
            clean[key] = ov
        elif key == "detectors":
            if not isinstance(value, dict):
                raise SettingsError("detectors must be an object of name -> true/false")
            for det, on in value.items():
                if det not in default:
                    raise SettingsError(f"unknown DLP detector '{det}'")
                if not isinstance(on, bool):
                    raise SettingsError(f"detector '{det}' must be true/false")
            clean[key] = {**default, **value}
        elif key == "rules":
            if not isinstance(value, dict):
                raise SettingsError("rules must be an object of rule -> true/false")
            for rule, on in value.items():
                if rule not in ALERT_RULES:
                    raise SettingsError(f"unknown alert rule '{rule}'")
                if not isinstance(on, bool):
                    raise SettingsError(f"rule '{rule}' must be true/false")
            clean[key] = {**default, **value}
        else:
            clean[key] = _coerce(section, key, value, default)

    with _LOCK:
        _refresh()
        cur = dict(_overrides.get(section, {}))
        for k, v in clean.items():
            if isinstance(v, dict) and isinstance(cur.get(k), dict):
                cur[k] = {**cur[k], **v}
            else:
                cur[k] = v
        _overrides[section] = cur
        if statestore.enabled():               # write ONLY the touched section: an
            statestore.run(                    # all-section save could clobber another
                "INSERT INTO settings (section, doc) VALUES (%s, %s) "   # instance's
                "ON CONFLICT (section) DO UPDATE SET doc = EXCLUDED.doc",  # fresh write
                (section, json.dumps(cur, ensure_ascii=False)))
        else:
            _save()
    return effective()[section]


def reset(section: str | None = None) -> dict:
    """Drop overrides (one section, or all) and fall back to the YAML baseline."""
    with _LOCK:
        if section is None:
            _overrides.clear()
            if statestore.enabled():
                statestore.run("DELETE FROM settings")
        else:
            if section not in _defaults():
                raise SettingsError(f"unknown settings section '{section}'")
            _overrides.pop(section, None)
            if statestore.enabled():
                statestore.run("DELETE FROM settings WHERE section = %s", (section,))
        if not statestore.enabled():
            _save()
    return effective()


# ---- convenience accessors used on hot paths --------------------------------

def rate_limit_for_server(server: str) -> int:
    rl = get("rate_limits")
    return int(rl["per_server_overrides"].get(server, rl["per_server_per_minute"]))


def alert_rule_enabled(rule: str) -> bool:
    return bool(get("alerts", "rules").get(rule, True))


_load()
