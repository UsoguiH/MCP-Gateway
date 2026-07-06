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
import os
import sys
from contextlib import AsyncExitStack

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import CONFIG, ROOT


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
        await self.session.initialize()
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

    async def start(self):
        await self._connect()

    async def _restart(self):
        try:
            if self._stack:
                await self._stack.aclose()
        except Exception:
            pass
        self._stack = self.session = None
        await self._connect()

    async def _op(self, factory):
        """Run one operation under the per-server lock; on failure, restart the
        server once (reconnect + rediscover) and retry. Persistent failure raises."""
        async with self._lock:
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
        if self._stack:
            await self._stack.aclose()
            self._stack = None


class MCPManager:
    def __init__(self):
        self.servers: dict[str, ManagedServer] = {}

    async def start_all(self):
        for spec in CONFIG["servers"]:
            srv = ManagedServer(spec["name"], spec.get("command"), spec.get("args", []),
                                transport=spec.get("transport", "stdio"), url=spec.get("url"),
                                env=spec.get("env"))
            await srv.start()
            self.servers[srv.name] = srv

    async def stop_all(self):
        for srv in self.servers.values():
            await srv.stop()

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
