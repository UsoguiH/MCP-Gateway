"""files-mcp — production internal-documents / file-share MCP server (read-only).

The third data source (PROJECT-PLAN Phase 1). Exposes allow-listed document
roots — local folders or mounted SMB shares — to the gateway. Built narrow by
design (risk register #2): read-only tools only, hard path containment, size
and time budgets, hidden/system files invisible.

Configuration (environment; never via model-visible args):

  DOCS_ROOTS   REQUIRED. JSON array of allow-listed roots:
                 [{"name": "policies", "path": "/shares/policies",
                   "classification": "restricted",
                   "description": "HR & IT policies"}, ...]
               Also accepts the compact form
                 name=path=classification[;name=path=classification...]
               `classification` is one of public|restricted|secret|top_secret
               and is stamped on every result from that root. The gateway's
               registry classification for these tools should be set to the
               HIGHEST label among configured roots (default 'secret' is safe).
  DOCS_MAX_FILE_BYTES        max bytes extracted per document (default 2_000_000)
  DOCS_MAX_RESULTS           max entries returned by list/find/search (default 50)
  DOCS_SEARCH_MAX_FILES      max files opened per content search (default 400)
  DOCS_SEARCH_TIME_BUDGET_S  wall-clock budget per content search (default 10)
  DOCS_SEARCH_SKIP_OVER_BYTES  content search skips files larger than this
                               (default 5_000_000)

Safety model:
  * Read-only: there is no write/delete/move tool at all.
  * Containment: every path is resolved (symlinks followed) and must remain
    inside its allow-listed root, or the call is refused. Absolute paths and
    drive-qualified paths in arguments are refused outright.
  * Hidden entries (dotfiles), $RECYCLE.BIN and System Volume Information are
    never listed, searched, read or stat'ed.
  * Results are capped (count + byte caps) and report truncation.
  * With DOCS_ROOTS unset the server still boots and registers its tools;
    every call returns a structured configuration error (lazy, like
    postgres-mcp / gitea-mcp), so the gateway never crashes on discovery.

Extraction: plain-text families decoded directly (UTF-8 → UTF-8-BOM → cp1256
Arabic → latin-1 fallback); .docx via stdlib zipfile (no dependency);
.pdf via pypdf and .xlsx via openpyxl when installed, otherwise a structured
hint error. Runs over stdio; the gateway spawns it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

_CLASSIFICATIONS = ("public", "restricted", "secret", "top_secret")

MAX_FILE_BYTES = int(os.environ.get("DOCS_MAX_FILE_BYTES", "2000000"))
MAX_RESULTS = int(os.environ.get("DOCS_MAX_RESULTS", "50"))
SEARCH_MAX_FILES = int(os.environ.get("DOCS_SEARCH_MAX_FILES", "400"))
SEARCH_TIME_BUDGET_S = float(os.environ.get("DOCS_SEARCH_TIME_BUDGET_S", "10"))
SEARCH_SKIP_OVER_BYTES = int(os.environ.get("DOCS_SEARCH_SKIP_OVER_BYTES", "5000000"))
MAX_RESULT_BYTES = 1_000_000            # cap serialized payloads (gateway also caps)
_LIST_CAP = 500                         # directory listing entry cap

_HIDDEN_DIRS = {"$recycle.bin", "system volume information", "__pycache__"}

# Extensions decoded as plain text.
_TEXT_EXTS = {
    ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".log", ".ini", ".cfg", ".conf", ".toml",
    ".py", ".sql", ".sh", ".ps1", ".bat", ".js", ".ts", ".css", ".java", ".go",
    ".c", ".h", ".cpp", ".rb", ".php",
}
_OFFICE_EXTS = {".docx", ".pdf", ".xlsx"}


class _ConfigError(Exception):
    pass


def _parse_roots(raw: str) -> dict[str, dict]:
    """Parse DOCS_ROOTS (JSON array or compact form) -> {name: {path, classification, description}}."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    entries: list[dict] = []
    if raw.startswith("["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise _ConfigError(f"DOCS_ROOTS is not valid JSON: {e}")
        if not isinstance(data, list):
            raise _ConfigError("DOCS_ROOTS JSON must be an array of objects")
        entries = data
    else:
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            bits = part.split("=")
            if len(bits) < 2:
                raise _ConfigError(f"DOCS_ROOTS entry '{part}' is not name=path[=classification]")
            entries.append({"name": bits[0], "path": "=".join(bits[1:-1]) if len(bits) > 2 else bits[1],
                            "classification": bits[-1] if len(bits) > 2 else "secret"})
    roots: dict[str, dict] = {}
    for e in entries:
        name = str(e.get("name", "")).strip()
        path = str(e.get("path", "")).strip()
        label = str(e.get("classification", "secret")).strip() or "secret"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise _ConfigError(f"root name '{name}' must be 1-64 chars of [A-Za-z0-9_-]")
        if name in roots:
            raise _ConfigError(f"duplicate root name '{name}'")
        if label not in _CLASSIFICATIONS:
            raise _ConfigError(f"root '{name}': classification '{label}' not in {_CLASSIFICATIONS}")
        p = Path(path)
        if not path or not p.is_absolute():
            raise _ConfigError(f"root '{name}': path must be absolute, got '{path}'")
        roots[name] = {
            "path": p,
            "classification": label,
            "description": str(e.get("description", "")).strip(),
        }
    return roots


_ROOTS: dict[str, dict] = {}
_CONFIG_ERROR: Optional[str] = None
try:
    _ROOTS = _parse_roots(os.environ.get("DOCS_ROOTS", ""))
except _ConfigError as e:
    _CONFIG_ERROR = str(e)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _dumps(obj: Any) -> str:
    out = json.dumps(obj, ensure_ascii=False)
    if len(out.encode("utf-8", "ignore")) > MAX_RESULT_BYTES:
        return json.dumps({"error": "result too large",
                           "hint": "narrow the request (smaller directory, fewer results)"})
    return out


def _config_err() -> str:
    if _CONFIG_ERROR:
        return _dumps({"error": f"files-mcp misconfigured: {_CONFIG_ERROR}"})
    return _dumps({
        "error": "files-mcp is not configured",
        "hint": "set DOCS_ROOTS to a JSON array of "
                '{"name","path","classification"} allow-listed document roots',
    })


def _hidden(name: str) -> bool:
    return name.startswith(".") or name.lower() in _HIDDEN_DIRS


def _root(share: str) -> dict:
    r = _ROOTS.get(share)
    if r is None:
        raise ValueError(f"unknown share '{share}'; call list_shares for the allow-list")
    return r


def _resolve(share: str, rel: str) -> tuple[Path, dict]:
    """Resolve rel inside the share root, refusing any escape. Returns (path, root)."""
    root = _root(share)
    rel = (rel or "").strip().replace("\\", "/")
    if rel in ("", "/", "."):
        return root["path"].resolve(), root
    p = Path(rel)
    if p.is_absolute() or (len(rel) > 1 and rel[1] == ":"):
        raise ValueError("absolute paths are not allowed; use a path relative to the share")
    base = root["path"].resolve()
    target = (base / p).resolve()          # resolves symlinks and any '..'
    if target != base and base not in target.parents:
        raise ValueError("path escapes the share root; refused")
    # No hidden/system component anywhere in the relative path.
    for part in target.relative_to(base).parts:
        if _hidden(part):
            raise ValueError("path contains a hidden or system entry; refused")
    return target, root


def _mtime_iso(st_mtime: float) -> str:
    return datetime.fromtimestamp(st_mtime, tz=timezone.utc).isoformat(timespec="seconds")


def _relpath(p: Path, root: dict) -> str:
    return p.resolve().relative_to(root["path"].resolve()).as_posix()


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1256"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


_DOCX_TAG = re.compile(rb"<[^>]+>")


def _extract_docx(path: Path, cap: int) -> str:
    """Text from a .docx via stdlib zip — no dependency."""
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml")[: cap * 4]
    # Paragraph/break tags become newlines, every other tag is stripped.
    xml = re.sub(rb"</w:p>|<w:br[^>]*/>", b"\n", xml)
    text = _DOCX_TAG.sub(b"", xml)
    return _decode(text)


def _extract_pdf(path: Path, cap: int) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        raise RuntimeError("PDF extraction requires the 'pypdf' package on the gateway host")
    reader = PdfReader(str(path))
    parts: list[str] = []
    total = 0
    for page in reader.pages:
        t = page.extract_text() or ""
        parts.append(t)
        total += len(t)
        if total >= cap:
            break
    return "\n".join(parts)


def _extract_xlsx(path: Path, cap: int) -> str:
    try:
        import openpyxl
    except ImportError:
        raise RuntimeError("XLSX extraction requires the 'openpyxl' package on the gateway host")
    wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
    lines: list[str] = []
    total = 0
    for ws in wb.worksheets:
        lines.append(f"# sheet: {ws.title}")
        for row in ws.iter_rows(values_only=True):
            line = "\t".join("" if v is None else str(v) for v in row)
            lines.append(line)
            total += len(line)
            if total >= cap:
                wb.close()
                return "\n".join(lines)
    wb.close()
    return "\n".join(lines)


def _extract(path: Path, cap: int = 0) -> str:
    ext = path.suffix.lower()
    size = path.stat().st_size
    cap = cap or MAX_FILE_BYTES
    if ext == ".docx":
        return _extract_docx(path, cap)
    if ext == ".pdf":
        return _extract_pdf(path, cap)
    if ext == ".xlsx":
        return _extract_xlsx(path, cap)
    if ext in _TEXT_EXTS or size <= cap:   # unknown small files: try text
        with open(path, "rb") as f:
            return _decode(f.read(cap + 1))
    raise RuntimeError(f"unsupported file type '{ext}' for text extraction")


def _iter_files(base: Path):
    """Walk visible files under base, skipping hidden/system dirs, deterministic order."""
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not _hidden(d))
        for fn in sorted(filenames):
            if not _hidden(fn):
                yield Path(dirpath) / fn


def _err(e: Exception) -> str:
    return _dumps({"error": str(e).strip() or type(e).__name__, "type": type(e).__name__})


# --------------------------------------------------------------------------
# tools (all read-only)
# --------------------------------------------------------------------------

@mcp.tool()
def list_shares() -> str:
    """List the allow-listed document shares (name, classification, description). Start here."""
    if not _ROOTS:
        return _config_err()
    shares = []
    for name, r in sorted(_ROOTS.items()):
        shares.append({
            "name": name,
            "classification": r["classification"],
            "description": r["description"],
            "reachable": r["path"].is_dir(),
        })
    return _dumps({"shares": shares, "read_only": True})


@mcp.tool()
def list_directory(share: str, path: str = "") -> str:
    """List one directory of a share (non-recursive). `path` is relative to the share root."""
    if not _ROOTS:
        return _config_err()
    try:
        base, root = _resolve(share, path)
        if not base.is_dir():
            return _dumps({"error": f"'{path or '/'}' is not a directory in share '{share}'"})
        entries = []
        truncated = False
        for child in sorted(base.iterdir(), key=lambda c: (c.is_file(), c.name.lower())):
            if _hidden(child.name):
                continue
            if len(entries) >= _LIST_CAP:
                truncated = True
                break
            st = child.stat()
            entries.append({
                "name": child.name,
                "type": "dir" if child.is_dir() else "file",
                "size": None if child.is_dir() else st.st_size,
                "modified": _mtime_iso(st.st_mtime),
            })
        return _dumps({"share": share, "path": path or "/", "entries": entries,
                       "truncated": truncated,
                       "classification": root["classification"]})
    except Exception as e:
        return _err(e)


@mcp.tool()
def find_files(pattern: str, share: str = "", max_results: int = 0) -> str:
    """Find files by name (case-insensitive substring or * glob) in one share, or all shares if `share` is empty."""
    if not _ROOTS:
        return _config_err()
    try:
        limit = min(max_results or MAX_RESULTS, MAX_RESULTS)
        pat = (pattern or "").strip().lower()
        if not pat:
            raise ValueError("pattern must not be empty")
        rx = re.compile(".*".join(re.escape(p) for p in pat.split("*")), re.IGNORECASE) \
            if "*" in pat else None
        targets = [share] if share else sorted(_ROOTS)
        hits = []
        truncated = False
        for name in targets:
            root = _root(name)
            if not root["path"].is_dir():
                continue
            base = root["path"].resolve()
            for f in _iter_files(base):
                if rx.search(f.name) if rx else pat in f.name.lower():
                    if len(hits) >= limit:
                        truncated = True
                        break
                    st = f.stat()
                    hits.append({"share": name, "path": _relpath(f, root),
                                 "size": st.st_size, "modified": _mtime_iso(st.st_mtime),
                                 "classification": root["classification"]})
            if truncated:
                break
        return _dumps({"pattern": pattern, "results": hits, "truncated": truncated})
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_content(query: str, share: str = "", extensions: str = "",
                   max_results: int = 0) -> str:
    """Search text content of documents for a phrase (case-insensitive). Returns file, line number and a snippet per match. `extensions` optionally narrows, e.g. ".md,.txt"."""
    if not _ROOTS:
        return _config_err()
    try:
        q = (query or "").strip()
        if len(q) < 2:
            raise ValueError("query must be at least 2 characters")
        ql = q.lower()
        limit = min(max_results or MAX_RESULTS, MAX_RESULTS)
        ext_filter = {e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
                      for e in extensions.split(",") if e.strip()} if extensions else None
        targets = [share] if share else sorted(_ROOTS)
        deadline = time.monotonic() + SEARCH_TIME_BUDGET_S
        hits: list[dict] = []
        scanned = 0
        stopped = None
        for name in targets:
            root = _root(name)
            if not root["path"].is_dir():
                continue
            base = root["path"].resolve()
            for f in _iter_files(base):
                if time.monotonic() > deadline:
                    stopped = "time budget exhausted"
                    break
                if len(hits) >= limit:
                    stopped = "result cap reached"
                    break
                if scanned >= SEARCH_MAX_FILES:
                    stopped = "file-scan cap reached"
                    break
                ext = f.suffix.lower()
                if ext_filter is not None and ext not in ext_filter:
                    continue
                if ext_filter is None and ext not in _TEXT_EXTS and ext not in _OFFICE_EXTS:
                    continue
                try:
                    if f.stat().st_size > SEARCH_SKIP_OVER_BYTES:
                        continue
                    text = _extract(f)
                except Exception:
                    continue                     # unreadable/unsupported: skip quietly
                scanned += 1
                for i, line in enumerate(text.splitlines(), 1):
                    if ql in line.lower():
                        snippet = line.strip()
                        if len(snippet) > 300:
                            pos = snippet.lower().find(ql)
                            start = max(0, pos - 120)
                            snippet = snippet[start:start + 300]
                        hits.append({"share": name, "path": _relpath(f, root),
                                     "line": i, "snippet": snippet,
                                     "classification": root["classification"]})
                        if len(hits) >= limit:
                            break
            if stopped:
                break
        return _dumps({"query": q, "results": hits, "files_scanned": scanned,
                       "stopped_early": stopped, "truncated": stopped is not None})
    except Exception as e:
        return _err(e)


@mcp.tool()
def read_document(share: str, path: str, start: int = 0) -> str:
    """Read a document's text content. `path` is relative to the share. Large files: pass `start` (character offset) to continue where the previous read stopped."""
    if not _ROOTS:
        return _config_err()
    try:
        f, root = _resolve(share, path)
        if not f.is_file():
            return _dumps({"error": f"'{path}' is not a file in share '{share}'"})
        start = max(0, int(start))
        # Extraction budget covers the requested window, so `start` can walk
        # arbitrarily far through a large file chunk by chunk.
        text = _extract(f, cap=start + MAX_FILE_BYTES + 1)
        chunk = text[start:start + MAX_FILE_BYTES]
        truncated = (start + len(chunk)) < len(text)
        return _dumps({
            "share": share, "path": _relpath(f, root),
            "classification": root["classification"],
            "size_bytes": f.stat().st_size,
            "text": chunk,
            "start": start,
            "next_start": start + len(chunk) if truncated else None,
            "truncated": truncated,
        })
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_file_info(share: str, path: str) -> str:
    """Metadata for one file: size, modified time, type, SHA-256 (files up to 50 MB)."""
    if not _ROOTS:
        return _config_err()
    try:
        f, root = _resolve(share, path)
        if not f.exists():
            return _dumps({"error": f"'{path}' not found in share '{share}'"})
        st = f.stat()
        info = {
            "share": share, "path": _relpath(f, root),
            "type": "dir" if f.is_dir() else "file",
            "size": st.st_size,
            "modified": _mtime_iso(st.st_mtime),
            "extension": f.suffix.lower(),
            "classification": root["classification"],
        }
        if f.is_file() and st.st_size <= 50_000_000:
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            info["sha256"] = h.hexdigest()
        return _dumps(info)
    except Exception as e:
        return _err(e)


@mcp.resource("files://shares")
def shares_resource() -> str:
    """Readable resource: the share allow-list with classifications."""
    return list_shares()


if __name__ == "__main__":
    mcp.run()  # stdio
