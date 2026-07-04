"""MCP connection manager (spec §4.4).

Owns persistent stdio sessions to each configured MCP server, discovers their
tools, and forwards validated tool calls. Each server runs in its own task with
its own session; calls are serialized per server via an async lock.

This is deliberately transport-simple (stdio) for the dev fixtures. The
production gateway swaps in Streamable HTTP + mTLS + SPIFFE without changing the
authorization/HITL/audit layers that sit above this module.
"""
import asyncio
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import CONFIG, ROOT


class ManagedServer:
    def __init__(self, name: str, command: str, args: list[str]):
        self.name = name
        self.command = command
        self.args = args
        self.session: ClientSession | None = None
        self.tools: list[dict] = []
        self._stack: AsyncExitStack | None = None
        self._lock = asyncio.Lock()

    async def start(self):
        cmd = sys.executable if self.command == "python" else self.command
        # Resolve script paths relative to project root.
        args = [str((ROOT / a).resolve()) if a.endswith(".py") else a for a in self.args]
        params = StdioServerParameters(command=cmd, args=args)
        self._stack = AsyncExitStack()
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()
        listing = await self.session.list_tools()
        self.tools = [
            {
                "server": self.name,
                "name": t.name,
                "description": t.description or "",
                "schema": t.inputSchema or {},
            }
            for t in listing.tools
        ]

    async def call(self, tool: str, arguments: dict) -> str:
        async with self._lock:
            result = await self.session.call_tool(tool, arguments)
        parts = []
        for c in result.content:
            parts.append(getattr(c, "text", "") or "")
        return "".join(parts)

    async def stop(self):
        if self._stack:
            await self._stack.aclose()
            self._stack = None


class MCPManager:
    def __init__(self):
        self.servers: dict[str, ManagedServer] = {}

    async def start_all(self):
        for spec in CONFIG["servers"]:
            srv = ManagedServer(spec["name"], spec["command"], spec["args"])
            await srv.start()
            self.servers[srv.name] = srv

    async def stop_all(self):
        for srv in self.servers.values():
            await srv.stop()

    def all_tools(self) -> list[dict]:
        out = []
        for srv in self.servers.values():
            out.extend(srv.tools)
        return out

    def find_tool(self, server: str, tool: str) -> dict | None:
        srv = self.servers.get(server)
        if not srv:
            return None
        for t in srv.tools:
            if t["name"] == tool:
                return t
        return None

    async def call(self, server: str, tool: str, arguments: dict) -> str:
        srv = self.servers.get(server)
        if not srv:
            raise KeyError(f"unknown server {server}")
        return await srv.call(tool, arguments)
