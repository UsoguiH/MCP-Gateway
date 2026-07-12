"""MCP connection manager (spec §4.4).

Owns a persistent session to each configured MCP server and discovers its full
surface — **tools, resources, and prompts** — then forwards validated operations.
Each server is serialized by an async lock, and a crashed server is **auto-restarted**
(reconnect + rediscover) on the next operation, so a transient subprocess death no
longer takes the server down until a gateway restart.

Transports: `stdio` (co-located subprocess) or `http` (remote Streamable-HTTP MCP
server), chosen per server in config (`transport: stdio|http`, with `url` for http).
The authorization / HITL / DLP / audit layers above this module are transport-agnostic.
"""
import asyncio
import json
import os
import sys
import time
from contextlib import AsyncExitStack

import anyio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import CONFIG, DATA_DIR, ROOT

# Admin-managed server inventory overlay (survives restarts): servers added or
# removed from the dashboard without editing config.yaml.
#   {"added": [spec, ...], "removed": ["name", ...]}
_DYN_FILE = DATA_DIR / "servers_dynamic.json"


def _read_dynamic() -> dict:
    try:
        d = json.loads(_DYN_FILE.read_text(encoding="utf-8"))
        return {"added": list(d.get("added", [])), "removed": list(d.get("removed", []))}
    except Exception:
        return {"added": [], "removed": []}


def _write_dynamic(d: dict):
    _DYN_FILE.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")


def effective_server_specs() -> list[dict]:
    """config.yaml servers, minus admin-removed, plus admin-added."""
    dyn = _read_dynamic()
    removed = set(dyn["removed"])
    specs = [s for s in CONFIG["servers"] if s["name"] not in removed]
    names = {s["name"] for s in specs}
    specs += [s for s in dyn["added"] if s["name"] not in names and s["name"] not in removed]
    return specs


# A server that never completes the MCP handshake must not hang the admin who added it.
START_TIMEOUT = float((CONFIG.get("gateway", {}) or {}).get("server_start_timeout_seconds", 30))

_closing: set = set()          # keep detached teardown tasks alive until they finish


def _root_cause(exc: BaseException) -> str:
    """Flatten anyio's ExceptionGroup into the message an operator actually needs."""
    inner = getattr(exc, "exceptions", None)
    if inner:
        return _root_cause(inner[0])
    return f"{type(exc).__name__}: {exc}"[:200]


def _abandon(task):
    """Cancel a task and consume whatever it raises, so a hung connect neither blocks the
    request nor surfaces as an 'exception was never retrieved' warning."""
    task.cancel()
    _closing.add(task)

    def _swallow(t):
        _closing.discard(t)
        try:
            t.exception()
        except BaseException:
            pass

    task.add_done_callback(_swallow)


def _close_detached(stack: AsyncExitStack | None):
    """Close an MCP transport's exit stack WITHOUT blocking the caller.

    Closing a stdio stack from a task other than the one that opened it either raises
    anyio's cross-task cancel-scope RuntimeError or hangs outright — and a hang here stalls
    an admin's Stop/Restart/Remove request until their client gives up. The connection is
    already being discarded, so we let the close run (and fail, loudly to nobody) on its own
    task while the request returns immediately. The child process is reaped by the OS.
    """
    if stack is None:
        return
    async def _run():
        try:
            with anyio.move_on_after(10):
                await stack.aclose()
        except Exception:
            pass                       # cross-task close; the transport is gone regardless
    try:
        task = asyncio.get_running_loop().create_task(_run())
        _closing.add(task)
        task.add_done_callback(_closing.discard)
    except RuntimeError:
        pass                           # no loop (shutdown): the process is exiting anyway


def _split_content(content) -> tuple[str, list[dict]]:
    """Split MCP content blocks into (joined_text, [non-text blocks as dicts]).
    Non-text content (images, audio, embedded resources) is preserved, not dropped."""
    text_parts, extra = [], []
    for c in content or []:
        if getattr(c, "type", None) == "text":
            text_parts.append(getattr(c, "text", "") or "")
        else:
            try:
                extra.append(c.model_dump(mode="json", exclude_none=True))
            except Exception:
                pass
    return "".join(text_parts), extra


def _expand_env(value: str) -> str:
    """Expand ${VAR} references from the gateway's environment so config.yaml can
    reference secrets (GITEA_TOKEN, POSTGRES_URL, ...) without storing them."""
    import re
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), value)


class ManagedServer:
    def __init__(self, name, command=None, args=None, transport="stdio", url=None,
                 env=None):
        self.name = name
        self.command = command
        self.args = args or []
        self.env = {k: _expand_env(str(v)) for k, v in (env or {}).items()}
        self.transport = transport
        self.url = url
        self.session: ClientSession | None = None
        self.tools: list[dict] = []
        self.resources: list[dict] = []
        self.prompts: list[dict] = []
        self._stack: AsyncExitStack | None = None
        self._lock = asyncio.Lock()
        self.state = "stopped"            # running | stopped (admin lifecycle)
        self.started_at: float | None = None
        self.server_version: str | None = None      # from the MCP initialize handshake
        self.server_name: str | None = None
        self.protocol_version: str | None = None

    async def _connect(self):
        self._stack = AsyncExitStack()
        if self.transport == "http":
            from mcp.client.streamable_http import streamablehttp_client
            read, write, _ = await self._stack.enter_async_context(streamablehttp_client(self.url))
        else:
            cmd = sys.executable if self.command == "python" else self.command
            args = [str((ROOT / a).resolve()) if a.endswith(".py") else a for a in self.args]
            env = None
            if self.env:                       # merge onto the SDK's safe default env
                from mcp.client.stdio import get_default_environment
                env = {**get_default_environment(), **self.env}
            read, write = await self._stack.enter_async_context(
                stdio_client(StdioServerParameters(command=cmd, args=args, env=env)))
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        init = await self.session.initialize()
        # The MCP handshake already tells us who the server is and what version it runs;
        # we used to throw it away, which is why the console's Version column was an
        # em-dash for every server (A16).
        try:
            info = getattr(init, "serverInfo", None)
            self.server_name = getattr(info, "name", None) or self.name
            self.server_version = getattr(info, "version", None)
            self.protocol_version = getattr(init, "protocolVersion", None)
        except Exception:
            self.server_name, self.server_version, self.protocol_version = self.name, None, None
        await self._discover()

    async def _discover(self):
        listing = await self.session.list_tools()
        self.tools = [{"server": self.name, "name": t.name, "description": t.description or "",
                       "schema": t.inputSchema or {}} for t in listing.tools]
        try:                                            # resources are an optional capability
            rl = await self.session.list_resources()
            self.resources = [{"server": self.name, "uri": str(r.uri), "name": r.name or str(r.uri),
                               "description": r.description or "", "mimeType": r.mimeType or "text/plain"}
                              for r in rl.resources]
        except Exception:
            self.resources = []
        try:                                            # prompts are an optional capability
            pl = await self.session.list_prompts()
            self.prompts = [{"server": self.name, "name": p.name, "description": p.description or "",
                             "arguments": [a.model_dump(mode="json", exclude_none=True) for a in (p.arguments or [])]}
                            for p in pl.prompts]
        except Exception:
            self.prompts = []

    async def _connect_bounded(self):
        """Connect + handshake + discover, with a hard deadline.

        A misconfigured server (wrong path, bad command, a process that dies on import)
        spawns and exits immediately — and `initialize()` then waits forever for a reply
        that will never come. An admin adding a server with a typo'd path would hang their
        request until the client gave up, holding a worker the whole time.

        The connect runs on its own task so that a timeout ABANDONS it rather than
        cancelling it in place: cancelling into the MCP client's anyio task group unwinds as
        a BaseExceptionGroup, which is not an `Exception` and so sails past the API's error
        handling as a 500. We raise a plain RuntimeError instead, which the caller turns
        into a clean 502 with a message an operator can act on.
        """
        task = asyncio.get_running_loop().create_task(self._connect())
        done, _ = await asyncio.wait({task}, timeout=START_TIMEOUT)
        if task in done:
            try:
                task.result()                      # re-raise the real failure, if any
            except BaseException as exc:           # incl. BaseExceptionGroup from anyio
                stack, self._stack, self.session = self._stack, None, None
                _close_detached(stack)
                raise RuntimeError(f"server {self.name!r} failed to start: "
                                   f"{_root_cause(exc)}") from None
            return

        _abandon(task)                             # still hanging: let it go, don't wait
        stack, self._stack, self.session = self._stack, None, None
        _close_detached(stack)
        raise RuntimeError(
            f"server {self.name!r} did not complete the MCP handshake within "
            f"{START_TIMEOUT:.0f}s — check the command, the script path, and that the "
            f"process starts cleanly")

    async def start(self):
        await self._connect_bounded()
        self.state = "running"
        self.started_at = time.time()

    async def _restart(self):
        stack, self._stack, self.session = self._stack, None, None
        _close_detached(stack)              # same detached teardown as stop(): never hang
        await self._connect_bounded()
        self.state = "running"
        self.started_at = time.time()

    async def restart(self):
        """Admin restart: reconnect + rediscover under the per-server lock."""
        async with self._lock:
            await self._restart()

    async def _op(self, factory):
        """Run one operation under the per-server lock; on failure, restart the
        server once (reconnect + rediscover) and retry. Persistent failure raises.
        An admin-stopped server fails immediately and is NOT auto-restarted."""
        async with self._lock:
            if self.state != "running":
                raise RuntimeError(f"server {self.name!r} is stopped by an administrator")
            try:
                return await factory()
            except Exception:
                await self._restart()
                return await factory()

    async def call(self, tool: str, arguments: dict) -> tuple[str, list[dict]]:
        result = await self._op(lambda: self.session.call_tool(tool, arguments))
        return _split_content(result.content)

    async def read_resource(self, uri: str) -> tuple[str, list[dict]]:
        result = await self._op(lambda: self.session.read_resource(uri))
        text_parts, blobs = [], []
        for c in result.contents or []:
            if getattr(c, "text", None) is not None:
                text_parts.append(c.text)
            else:
                try:
                    blobs.append(c.model_dump(mode="json", exclude_none=True))
                except Exception:
                    pass
        return "".join(text_parts), blobs

    async def get_prompt(self, name: str, arguments: dict) -> dict:
        result = await self._op(lambda: self.session.get_prompt(name, arguments or {}))
        return {"description": result.description or "",
                "messages": [m.model_dump(mode="json", exclude_none=True) for m in result.messages]}

    async def stop(self):
        """Tear the connection down. Never raises, and never blocks the caller.

        The stdio transport's exit stack is entered on a different task, so closing it from
        an HTTP request task raises anyio's "cancel scope in a different task" RuntimeError
        — and can BLOCK indefinitely, because a cancellation delivered from the wrong task
        never lands. An admin clicking Stop/Remove would then hang until their client timed
        out (this is what made server add/remove flaky).

        The connection is being discarded either way, so the close is detached: we drop our
        references immediately and let the teardown finish (or fail) on its own task.
        """
        self.state = "stopped"
        stack, self._stack, self.session = self._stack, None, None
        _close_detached(stack)


def _make_server(spec: dict) -> "ManagedServer":
    return ManagedServer(spec["name"], spec.get("command"), spec.get("args", []),
                         transport=spec.get("transport", "stdio"), url=spec.get("url"),
                         env=spec.get("env"))


class MCPManager:
    def __init__(self):
        self.servers: dict[str, ManagedServer] = {}

    async def start_all(self):
        for spec in effective_server_specs():
            srv = _make_server(spec)
            await srv.start()
            self.servers[srv.name] = srv

    async def stop_all(self):
        for srv in self.servers.values():
            await srv.stop()

    # ---- admin lifecycle -------------------------------------------------
    def _get(self, name: str) -> ManagedServer:
        srv = self.servers.get(name)
        if not srv:
            raise KeyError(f"unknown server {name}")
        return srv

    async def restart_server(self, name: str):
        await self._get(name).restart()

    async def stop_server(self, name: str):
        await self._get(name).stop()

    async def start_server(self, name: str):
        srv = self._get(name)
        async with srv._lock:
            if srv.state == "running":
                return
            await srv._restart()

    async def add_server(self, spec: dict) -> "ManagedServer":
        """Connect a new server and persist it to the dynamic inventory. Rolls the
        inventory back if the server fails to start, so a bad spec can't wedge boot."""
        name = spec.get("name") or ""
        if not name or "__" in name:
            raise ValueError("server name is required and must not contain '__'")
        if name in self.servers:
            raise ValueError(f"server {name!r} already exists")
        srv = _make_server(spec)
        await srv.start()                                # raises on a bad spec
        dyn = _read_dynamic()
        dyn["removed"] = [n for n in dyn["removed"] if n != name]
        dyn["added"] = [s for s in dyn["added"] if s.get("name") != name] + [spec]
        _write_dynamic(dyn)
        self.servers[name] = srv
        return srv

    async def remove_server(self, name: str):
        """Disconnect a server and persist its removal (works for config.yaml
        servers too — they stay removed across restarts until re-added)."""
        srv = self._get(name)
        await srv.stop()
        self.servers.pop(name, None)
        dyn = _read_dynamic()
        dyn["added"] = [s for s in dyn["added"] if s.get("name") != name]
        if name not in dyn["removed"]:
            dyn["removed"].append(name)
        _write_dynamic(dyn)

    def server_spec(self, name: str) -> dict:
        """The spec a server is currently running with — what the edit form loads.
        Env VALUES are redacted: config.yaml references secrets via ${VAR}, and this
        payload goes to a browser."""
        srv = self._get(name)
        return {
            "name": srv.name,
            "command": srv.command,
            "args": list(srv.args or []),
            "transport": srv.transport,
            "url": srv.url,
            "env_keys": sorted((srv.env or {}).keys()),
        }

    async def edit_server(self, name: str, spec: dict) -> "ManagedServer":
        """Change a server's command/args/env/transport in place (A16).

        Until now the only way to fix a typo'd env var was remove + re-add, which
        dropped the tool registry's pinned hashes for that server and forced every tool
        back through onboarding approval. This swaps the connection and keeps the
        registry entries — reconcile() then re-checks the definitions, so a server whose
        tools genuinely changed still quarantines on drift. The old connection is only
        torn down once the new one starts, so a bad edit leaves the server running.
        """
        old = self._get(name)
        new_spec = {**spec, "name": name}
        candidate = _make_server(new_spec)
        await candidate.start()                        # raises on a bad spec: old stays up
        try:
            await old.stop()
        except Exception:
            pass
        self.servers[name] = candidate
        dyn = _read_dynamic()
        dyn["removed"] = [n for n in dyn["removed"] if n != name]
        dyn["added"] = [s for s in dyn["added"] if s.get("name") != name] + [new_spec]
        _write_dynamic(dyn)
        return candidate

    def all_tools(self) -> list[dict]:
        return [t for srv in self.servers.values() for t in srv.tools]

    def all_resources(self) -> list[dict]:
        return [r for srv in self.servers.values() for r in srv.resources]

    def all_prompts(self) -> list[dict]:
        return [p for srv in self.servers.values() for p in srv.prompts]

    def find_tool(self, server: str, tool: str) -> dict | None:
        srv = self.servers.get(server)
        return next((t for t in srv.tools if t["name"] == tool), None) if srv else None

    async def call(self, server: str, tool: str, arguments: dict) -> tuple[str, list[dict]]:
        srv = self.servers.get(server)
        if not srv:
            raise KeyError(f"unknown server {server}")
        return await srv.call(tool, arguments)

    async def read_resource(self, server: str, uri: str) -> tuple[str, list[dict]]:
        srv = self.servers.get(server)
        if not srv:
            raise KeyError(f"unknown server {server}")
        return await srv.read_resource(uri)

    async def get_prompt(self, server: str, name: str, arguments: dict) -> dict:
        srv = self.servers.get(server)
        if not srv:
            raise KeyError(f"unknown server {server}")
        return await srv.get_prompt(name, arguments)
