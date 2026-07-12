"""Unit tests for scripts/purge_test_artifacts.py (Phase 2 task 2).

Builds a synthetic data dir mixing real records with pytest debris and verifies
the sweep removes exactly the debris — dry-run leaves files untouched.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from purge_test_artifacts import purge  # noqa: E402


def _write(dirpath: Path, name: str, data):
    (dirpath / name).write_text(json.dumps(data), encoding="utf-8")


def _read(dirpath: Path, name: str):
    return json.loads((dirpath / name).read_text(encoding="utf-8"))


def _seed(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    _write(d, "tool_registry.json", {
        "postgres:query": {"server": "postgres", "tool": "query", "tier": 0,
                           "fingerprint": "aa", "status": "active", "quarantine_reason": None},
        "pytest-echo:list_reports": {"server": "pytest-echo", "tool": "list_reports", "tier": 0,
                                     "fingerprint": "bb", "status": "pending",
                                     "quarantine_reason": None},
    })
    _write(d, "oauth_clients.json", {
        "mcpc_real": {"client_id": "mcpc_real", "client_name": "Claude Code (company-gateway)",
                      "redirect_uris": ["http://127.0.0.1/cb"], "created": 1},
        "mcpc_test1": {"client_id": "mcpc_test1", "client_name": "pytest-mcp",
                       "redirect_uris": ["http://127.0.0.1/cb"], "created": 2},
        "mcpc_test2": {"client_id": "mcpc_test2", "client_name": "pytest-client",
                       "redirect_uris": ["http://127.0.0.1/cb"], "created": 3},
    })
    _write(d, "oauth_refresh.json", {
        "hash_real": {"sub": "sara", "client_id": "mcpc_real", "scope": "mcp", "exp": 9e9},
        "hash_test": {"sub": "admin", "client_id": "mcpc_test1", "scope": "mcp", "exp": 9e9},
    })
    _write(d, "api_keys.json", {
        "kid1": {"kid": "kid1", "name": "ops-automation", "sub": "admin", "revoked": False},
        "kid2": {"kid": "kid2", "name": "pytest-key", "sub": "admin", "revoked": False},
    })
    _write(d, "operators.json", {
        "ciadmin": {"name": "CI Admin (tests)", "role": "admin", "clearance": "top_secret"},
        "tmp3a2b1c": {"name": "Pytest Temp", "role": "employee", "clearance": "restricted"},
    })
    _write(d, "credentials.json", {"ciadmin": {"hash": "x"}, "tmp3a2b1c": {"hash": "y"}})
    _write(d, "mfa_secrets.json", {"ciadmin": "enc", "tmp3a2b1c": "enc"})
    _write(d, "servers_dynamic.json", {"added": [{"name": "pytest-echo", "command": "python"},
                                                 {"name": "reports2", "command": "python"}],
                                       "removed": ["pytest-echo", "docs"]})
    _write(d, "notifications.json", [
        {"id": "1", "title": "Server added — pytest-echo", "detail": "", "key": "", "read": False},
        {"id": "2", "title": "API key created — pytest-key", "detail": "", "key": "", "read": True},
        {"id": "3", "title": "Circuit breaker opened — gitea", "detail": "", "key": "breaker:gitea",
         "read": False},
        {"id": "4", "title": "Operator created — tmp3a2b1c", "detail": "Pytest Temp", "key": "",
         "read": True},
    ])
    return d


def test_purge_removes_only_test_artifacts(tmp_path):
    d = _seed(tmp_path)
    removed = purge(d)

    reg = _read(d, "tool_registry.json")
    assert "postgres:query" in reg and "pytest-echo:list_reports" not in reg

    clients = _read(d, "oauth_clients.json")
    assert list(clients) == ["mcpc_real"]
    refresh = _read(d, "oauth_refresh.json")
    assert list(refresh) == ["hash_real"]          # test client's token went with it

    keys = _read(d, "api_keys.json")
    assert list(keys) == ["kid1"]

    ops = _read(d, "operators.json")
    assert list(ops) == ["ciadmin"]                # ciadmin survives; tmp operator gone
    assert list(_read(d, "credentials.json")) == ["ciadmin"]
    assert list(_read(d, "mfa_secrets.json")) == ["ciadmin"]

    dyn = _read(d, "servers_dynamic.json")
    assert [s["name"] for s in dyn["added"]] == ["reports2"]
    assert dyn["removed"] == ["docs"]

    notifs = _read(d, "notifications.json")
    assert [n["id"] for n in notifs] == ["3"]      # only the real breaker alert survives

    assert set(removed) == {"tool_registry", "oauth_clients", "oauth_refresh", "api_keys",
                            "operators", "credentials", "mfa_secrets", "servers_dynamic",
                            "notifications"}


def test_purge_dry_run_changes_nothing(tmp_path):
    d = _seed(tmp_path)
    before = {p.name: p.read_text(encoding="utf-8") for p in d.iterdir()}
    removed = purge(d, dry_run=True)
    after = {p.name: p.read_text(encoding="utf-8") for p in d.iterdir()}
    assert before == after
    assert removed                                  # it still reports what it would do


def test_purge_clean_dir_reports_nothing(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    _write(d, "tool_registry.json", {"postgres:query": {"server": "postgres", "tool": "query",
                                                        "tier": 0, "fingerprint": "aa",
                                                        "status": "active",
                                                        "quarantine_reason": None}})
    assert purge(d) == {}


def test_purge_missing_files_are_skipped(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    assert purge(d) == {}
