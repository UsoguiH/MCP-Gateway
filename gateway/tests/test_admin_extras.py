"""Tests for the four "reach for it and it's not there" admin features:
  activity  — live per-user feed
  health    — is the BACKEND reachable, not just the process
  preview   — see-as / role visibility
  search    — global cross-system search

The health-probe interpretation and see-as visibility are unit-tested here (no server
needed); the endpoints are smoke-tested live in test_admin_controls-style suites.
"""
import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── backend health probe: tell "process up, backend down" apart ──────────────
class _FakeContent:
    def __init__(self, text): self.text = text

class _FakeResult:
    def __init__(self, text): self.content = [_FakeContent(text)]

class _FakeSession:
    def __init__(self, reply=None, raises=None, hang=False):
        self._reply, self._raises, self._hang = reply, raises, hang
    async def call_tool(self, tool, args):
        if self._hang:
            await asyncio.sleep(30)
        if self._raises:
            raise self._raises
        return _FakeResult(self._reply)


def _server(name, session, state="running"):
    from app.mcp_manager import ManagedServer
    s = ManagedServer(name, command="python")
    s.session = session
    s.state = state
    s.server_version = "1.0"
    s.tools = [{"name": "x"}]
    return s


def _probe(server, timeout=2.0):
    return asyncio.run(server.health_probe(timeout))


def test_health_probe_reports_backend_up_on_a_clean_result():
    from app import mcp_manager
    # postgres has a defined probe (server_info); a clean JSON reply → backend up
    s = _server("postgres", _FakeSession(reply=json.dumps({"version": "PostgreSQL 17"})))
    r = _probe(s)
    assert r["backend"] == "up" and r["latency_ms"] is not None and r["probe"] == "server_info"


def test_health_probe_detects_backend_down_from_an_error_body():
    """Our connectors return {"error": ...} when their backend is unreachable — the process
    answers but the DB is gone. The probe must surface that as 'down', not 'up'."""
    s = _server("postgres", _FakeSession(reply=json.dumps({"error": "could not connect to server"})))
    r = _probe(s)
    assert r["backend"] == "down"
    assert "could not connect" in r["detail"]


def test_health_probe_times_out_without_hanging_the_page():
    s = _server("postgres", _FakeSession(hang=True))
    r = _probe(s, timeout=0.3)
    assert r["backend"] == "down" and "did not answer" in r["detail"]


def test_health_probe_reports_stopped_process():
    s = _server("postgres", None, state="stopped")
    r = _probe(s)
    assert r["backend"] == "down" and "not running" in r["detail"]


def test_health_probe_marks_unprobed_servers_process_only():
    # a server with no entry in BACKEND_PROBES: process responds, backend not probed
    s = _server("some-custom-server", _FakeSession(reply="ok"))
    r = _probe(s)
    assert r["backend"] == "unknown" and "not probed" in r["detail"]


def test_backend_probes_are_all_no_arg_read_tools():
    """A health probe must never call something with side effects. Every probe is a known
    read-only, no-argument tool."""
    from app.mcp_manager import BACKEND_PROBES
    for server, (tool, args) in BACKEND_PROBES.items():
        assert args == {}, f"{server} probe {tool} must take no arguments"
        assert not any(w in tool for w in ("delete", "drop", "send", "update", "create",
                                           "write", "remove")), f"{server} probe {tool} looks mutating"


# ── see-as / role preview: the visibility logic ──────────────────────────────
def test_preview_uses_the_real_visibility_logic(monkeypatch):
    """See-as must show EXACTLY what the gateway would let that role see — same function,
    synthesized claims — so it can't drift from reality."""
    from app.gateway import Gateway
    gw = Gateway.__new__(Gateway)

    # a tiny fake surface: two servers, three tools at different tiers
    tools = [
        {"server": "files", "name": "read", "schema": {}},
        {"server": "postgres", "name": "query", "schema": {}},
        {"server": "postgres", "name": "drop_table", "schema": {}},
    ]
    gw.mcp = types.SimpleNamespace(all_tools=lambda: tools,
                                   servers={"files": None, "postgres": None})
    reg = {("files", "read"): 0, ("postgres", "query"): 0, ("postgres", "drop_table"): 3}
    gw.registry = types.SimpleNamespace(
        get=lambda s, t: {"tier": reg.get((s, t)), "status": "active"} if (s, t) in reg else None)

    # analyst: entitled to files+postgres, max tier 2 → sees read + query, NOT drop_table (t3)
    monkeypatch.setattr("app.config.POLICY", {
        "roles": {"analyst": {"max_tool_tier": 2, "servers": ["files", "postgres"]},
                  "employee": {"max_tool_tier": 2, "servers": ["files"]}}}, raising=False)

    visible = gw.visible_tools({"sub": "x", "role": "analyst", "clearance": "secret"})
    names = {(t["server"], t["name"]) for t in visible}
    assert ("files", "read") in names
    assert ("postgres", "query") in names
    assert ("postgres", "drop_table") not in names          # tier 3 > analyst ceiling

    # employee: not entitled to postgres at all → sees only files
    vis2 = gw.visible_tools({"sub": "y", "role": "employee", "clearance": "restricted"})
    assert {t["server"] for t in vis2} == {"files"}
