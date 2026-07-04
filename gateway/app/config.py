"""Configuration loader with startup validation (fail fast on misconfig)."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)


class ConfigError(Exception):
    """Raised when config.yaml / policy.yaml is missing required, valid values."""


def _require(obj: dict, path: str, typ=None):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise ConfigError(f"missing required config key: {path}")
        cur = cur[part]
    if typ is not None and not isinstance(cur, typ):
        raise ConfigError(f"config key {path} must be {typ.__name__}, got {type(cur).__name__}")
    return cur


def _validate(config: dict, policy: dict):
    # No llm.* block: inference is client-side now (each colleague's local LLM
    # connects to the inbound MCP endpoint). The gateway runs no model.
    _require(config, "auth.mode", str) if "mode" in config.get("auth", {}) else None
    for k in ("auth.issuer", "auth.audience", "auth.alg"):
        _require(config, k, str)
    for k in ("gateway.host", "gateway.max_tool_result_bytes", "gateway.taint_min_len"):
        _require(config, k)
    _require(config, "gateway.port", int)
    if not isinstance(config.get("servers"), list) or not config["servers"]:
        raise ConfigError("config.servers must be a non-empty list")
    for s in config["servers"]:
        if not {"name", "command", "args"} <= set(s):
            raise ConfigError(f"each server needs name/command/args: {s}")
    _require(policy, "clearance_order", list)
    _require(policy, "roles", dict)
    for role, rc in policy["roles"].items():
        if "max_tool_tier" not in rc:
            raise ConfigError(f"policy role '{role}' missing max_tool_tier")


with open(ROOT / "config.yaml", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

with open(ROOT / "policy.yaml", encoding="utf-8") as f:
    POLICY = yaml.safe_load(f)

_validate(CONFIG, POLICY)

GATEWAY = CONFIG["gateway"]
CLEARANCE_ORDER = POLICY["clearance_order"]


def clearance_rank(level: str) -> int:
    """Rank of an NDMO classification level; unknown labels rank highest (fail closed)."""
    try:
        return CLEARANCE_ORDER.index(level)
    except ValueError:
        return len(CLEARANCE_ORDER)
