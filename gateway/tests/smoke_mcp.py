"""Standalone smoke test: spawn both reference servers over stdio, list tools, call one."""
import asyncio
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent


async def probe(script: str):
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "servers" / script)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"{script}: tools = {names}")
            if script == "docs_server.py":
                res = await session.call_tool("search_documents", {"query": "security"})
                print(f"  call result: {res.content[0].text[:120]}")


async def main():
    await probe("docs_server.py")
    await probe("actions_server.py")
    print("SMOKE OK")


if __name__ == "__main__":
    asyncio.run(main())
