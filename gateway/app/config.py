"""Configuration loader with startup validation (fail fast on misconfig)."""
import os
import warnings
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)


class ConfigError(Exception):
    """Raised when config.yaml / policy.yaml is missing required, valid values."""


def secret(name: str, default: str | None = None) -> str | None:
    """Load a secret, preferring a file mount over an env var so real deployments
    use Docker/Kubernetes secrets (never a value on the process command line or in
    `docker inspect`). Resolution order:
      1. ${NAME}_FILE  -> read the file's contents (trimmed)   [production]
      2. ${NAME}       -> the env var                          [dev/compose]
      3. default
    A file path that is set but unreadable is a hard error (fail closed — never
    silently fall back to a dev default when an operator intended a real secret)."""
    file_ref = os.environ.get(name + "_FILE")
    if file_ref:
        try:
            return Path(file_ref).read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ConfigError(f"{name}_FILE set but unreadable: {file_ref} ({e})")
    return os.environ.get(name, default)


# A container secrets mount is not a cheap read: on Docker Desktop's filesystem layer,
# one open+read+decode of /run/secrets/<x> measured 2.7 ms. That is fine once at boot and
# ruinous on a hot path — and secret() WAS on several: statestore.enabled() resolved the
# state-DB URL on every store call (dozens per mediated request), and audit._audit_key()
# re-read the HMAC key for every hash, i.e. once per record while verifying the chain.
# The gateway was spending most of its "database time" reading a file, while the database
# itself answered in 0.13 ms.
#
# A file-mounted secret cannot change without restarting the process that mounted it, so
# it is resolved ONCE. Rotation is a restart — which it already was.
_secret_cache: dict[tuple[str, str | None], str | None] = {}
_secret_lock = __import__("threading").Lock()


def secret_cached(name: str, default: str | None = None) -> str | None:
    """`secret()` resolved once per process. Use on any path that runs per request."""
    key = (name, default)
    try:
        return _secret_cache[key]
    except KeyError:
        pass
    value = secret(name, default)               # may raise ConfigError — never cache that
    with _secret_lock:
        _secret_cache[key] = value
    return value


def clear_secret_cache():
    """Tests (and a deliberate in-process re-read) drop the resolved secrets."""
    with _secret_lock:
        _secret_cache.clear()


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


# Pre-deploy tripwires: a production run must not use dev conveniences or the
# well-known dev secrets. We warn loudly (not fail) so pilots/dev still boot; set
# MCP_ENV=production to turn these into hard startup errors.
_DEV_SECRETS = {"dev-kek-change-me", "dev-audit-key-change-me",
                "dev-vault-key-change-me", "dev-mfa-enrollment-key-change-me"}


def _production_tripwires(config: dict):
    a = config.get("auth", {})
    issues = []
    if a.get("dev_login_enabled"):
        issues.append("auth.dev_login_enabled is true (dev login must be OFF in production)")
    if a.get("dev_quick_login"):
        issues.append("auth.dev_quick_login is true (password/MFA bypass — must be OFF in production)")
    if not a.get("require_mfa", False):
        issues.append("auth.require_mfa is false (enable the TOTP second factor)")
    if not (config.get("registry", {}) or {}).get("require_approval", False):
        issues.append("registry.require_approval is false (new tools auto-activate without Risk-Board review)")
    for var in ("MCP_GATEWAY_KEK", "MCP_AUDIT_KEY", "MCP_VAULT_KEY", "MCP_MFA_KEY"):
        val = secret(var)
        if val in _DEV_SECRETS or (var != "MCP_MFA_KEY" and not val):
            issues.append(f"{var} is unset or a known dev default (supply {var}_FILE or a real secret)")
    proxy_on = config.get("auth", {}).get("trusted_proxy", {}).get("enabled") or \
        os.environ.get("MCP_TRUSTED_PROXY", "").lower() in ("1", "true", "yes")
    if not proxy_on:
        issues.append("trusted proxy is off (set auth.trusted_proxy.enabled or MCP_TRUSTED_PROXY=1; "
                      "the gateway must run behind the mTLS terminator, not be directly reachable)")
    # jsonschema enforces `additionalProperties: false` on every tool call. Without it the
    # gateway now REFUSES calls rather than skipping the check (see gateway._validate_args),
    # so a missing library is a broken deployment: say so at boot, not on the first call.
    try:
        import jsonschema                                            # noqa: F401
    except ModuleNotFoundError:
        issues.append("jsonschema is not installed — tool-argument schema validation cannot "
                      "run and every mediated call will be refused (pip install -r requirements.txt)")
    # The `docs` and `actions` servers are TEST FIXTURES: in-code sample data and an
    # in-memory record store the e2e suite drives. They are useful in dev and must never be
    # reachable by a real user, so production refuses to start with them registered
    # (H9). Remove them from config.yaml's `servers:` for a production deployment.
    fixtures = {"docs", "actions"} & {s.get("name") for s in (config.get("servers") or [])}
    if fixtures:
        issues.append(f"pilot test fixtures are registered as servers: {sorted(fixtures)} — "
                      "remove them from config.yaml `servers:` before serving real users")
    if issues:
        strict = os.environ.get("MCP_ENV", "").lower() in ("production", "prod")
        header = "PRODUCTION CONFIG CHECK FAILED:" if strict else \
            "PRODUCTION CONFIG WARNING (set MCP_ENV=production to enforce):"
        msg = header + "\n  - " + "\n  - ".join(issues)
        if strict:
            raise ConfigError(msg)
        warnings.warn(msg, stacklevel=2)


with open(ROOT / "config.yaml", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

with open(ROOT / "policy.yaml", encoding="utf-8") as f:
    POLICY = yaml.safe_load(f)

_validate(CONFIG, POLICY)
_production_tripwires(CONFIG)

GATEWAY = CONFIG["gateway"]
CLEARANCE_ORDER = POLICY["clearance_order"]


def clearance_rank(level: str) -> int:
    """Rank of an NDMO classification level; unknown labels rank highest (fail closed)."""
    try:
        return CLEARANCE_ORDER.index(level)
    except ValueError:
        return len(CLEARANCE_ORDER)
