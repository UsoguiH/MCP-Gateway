"""Every MCP server module must import and register its tools (Phase 2 regression).

Why this exists: the `mcp` dependency was pinned to a RANGE (>=1.2,<2.0) and drifted to
1.8.1, whose FastMCP calls `issubclass()` on raw annotations. Four server modules used
`from __future__ import annotations` — which makes every annotation a string — so
`Tool.from_function` raised `TypeError: issubclass() arg 1 must be a class` at import
time. All four production connectors (postgres, gitea, files, reports) failed to start
and the gateway could not boot at all.

Nothing caught it: the unit suites import the servers' helper functions, not the FastMCP
tool registration, and the e2e suites skip when the backends are unreachable. This test
imports each server module the way the gateway actually spawns it, so an SDK upgrade that
breaks tool registration fails CI instead of production.
"""
import importlib
import sys
from pathlib import Path

import pytest

SERVERS_DIR = Path(__file__).resolve().parents[1] / "servers"

# (module, minimum tools it must register)
SERVER_MODULES = [
    ("postgres_server", 60),
    ("gitea_server", 90),
    ("files_server", 6),
    ("reports_server", 2),
    ("docs_server", 2),
    ("actions_server", 4),
    ("browser_server", 8),
    ("markitdown_server", 4),
    ("qdrant_server", 10),
]


@pytest.fixture(scope="module", autouse=True)
def _servers_on_path():
    sys.path.insert(0, str(SERVERS_DIR))
    yield
    sys.path.remove(str(SERVERS_DIR))


@pytest.mark.parametrize("module_name,min_tools", SERVER_MODULES)
def test_server_module_imports_and_registers_tools(module_name, min_tools):
    """Import must succeed AND the FastMCP tool registry must be populated — an import
    that silently registers zero tools is just as dead as one that raises."""
    mod = importlib.import_module(module_name)
    assert hasattr(mod, "mcp"), f"{module_name} exposes no FastMCP instance"

    # FastMCP keeps its registry privately; list_tools() is the public accessor and is
    # what the gateway's discovery calls.
    import anyio
    tools = anyio.run(mod.mcp.list_tools)
    assert len(tools) >= min_tools, (
        f"{module_name} registered {len(tools)} tools, expected >= {min_tools}")


@pytest.mark.parametrize("module_name,_min", SERVER_MODULES)
def test_importing_a_server_writes_nothing_to_stdout(module_name, _min):
    """An MCP stdio server speaks JSON-RPC over STDOUT. Anything else written there —
    a library banner, a progress bar, a parser warning — lands inside the protocol stream
    and desynchronises the transport. The connection then dies with an opaque
    `OSError: [Errno 22] Invalid argument` on the next flush, which looks like anything
    except the actual cause.

    This bit us for real: markitdown's document parsers print, and fastembed prints a
    model-download progress bar. Both corrupted the channel. Guard every server, forever.
    """
    import io
    import contextlib
    import subprocess

    # A fresh interpreter: import the module and report anything it printed. In-process
    # would not catch it, because pytest has already replaced sys.stdout.
    code = (f"import sys; sys.path.insert(0, {str(SERVERS_DIR)!r});"
            f"import {module_name}")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, f"{module_name} failed to import: {r.stderr[-400:]}"
    assert r.stdout == "", (
        f"{module_name} wrote to stdout on import — that corrupts the MCP protocol "
        f"stream. Captured: {r.stdout[:300]!r}")


def test_no_server_uses_future_annotations():
    """`from __future__ import annotations` turns annotations into strings, which the
    pinned FastMCP cannot introspect. Guard the whole directory, not just today's files."""
    offenders = [p.name for p in SERVERS_DIR.glob("*.py")
                 if "from __future__ import annotations" in p.read_text(encoding="utf-8")]
    assert not offenders, (
        f"{offenders} use `from __future__ import annotations`; FastMCP calls issubclass() "
        "on the annotation and will fail to register their tools at import time.")
