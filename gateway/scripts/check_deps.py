"""Dependency allowlist check (W9.3, blueprint Layer 5 supply chain).

Fails CI if an installed top-level package is not on the reviewed allowlist, or if
a requirement is unpinned. In the air-gapped program the allowlist is the set of
packages mirrored into the private index; anything else must go through review.
"""
import re
import sys
from pathlib import Path

# Reviewed, mirrored top-level dependencies (transitive deps are pulled by these).
ALLOWLIST = {
    "fastapi", "uvicorn", "pyjwt", "cryptography", "pyyaml", "httpx", "mcp", "pytest",
    "jsonschema",   # W9.6 arg-schema enforcement — pinned explicitly, never transitive-only
    "psycopg",      # postgres-mcp server driver
    # Optional connectors — reviewed 2026-07-12. Each is loaded lazily and the connector
    # returns a clean "not installed" error when its dependency is absent, so these can be
    # omitted from a minimal deployment that does not need that connector.
    "playwright",   # browser-mcp (Chromium)
    "markitdown",   # markitdown-mcp (document → Markdown)
    "qdrant-client",  # qdrant-mcp (vector search)
    "fastembed",    # qdrant-mcp text tools (local offline embedding)
}

REQ = Path(__file__).resolve().parent.parent / "requirements.txt"


def main() -> int:
    problems = []
    for raw in REQ.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name = re.split(r"[<>=!\[ ]", line, maxsplit=1)[0].lower()
        if name not in ALLOWLIST:
            problems.append(f"not on allowlist: {name}")
        if not re.search(r"[<>=]=?", line):
            problems.append(f"unpinned requirement: {line}")
    if problems:
        print("DEPENDENCY CHECK FAILED:")
        for p in problems:
            print("  -", p)
        return 1
    print(f"dependency check OK ({len(ALLOWLIST)} allowlisted top-level packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
