"""markitdown-mcp — convert documents to Markdown for the gateway (read-only).

Turns the formats an organization actually has — PDF, Word, Excel, PowerPoint, HTML, CSV,
EPUB, images — into clean Markdown a model can read. It is the natural companion to
files-mcp: that server finds and reads *text*; this one makes a 40-page PDF or a
spreadsheet legible.

Configuration (environment; never via model-visible args):

  DOCS_ROOTS   REQUIRED. The SAME allow-listed roots as files-mcp — deliberately, so there
               is exactly one place that decides which documents exist, and a converter
               cannot become a way around the file-share allow-list. JSON array of
                 [{"name","path","classification"[,"description"]}, ...]
               or the compact form name=path=classification[;...].
  MARKITDOWN_MAX_FILE_BYTES   refuse inputs larger than this (default 20_000_000)
  MARKITDOWN_MAX_OUTPUT_BYTES cap on returned Markdown (default 1_000_000)
  MARKITDOWN_ALLOW_URLS       "1" to permit convert_url. OFF by default: fetching a URL
                              server-side is SSRF, and browser-mcp already does browsing
                              behind an allow-list and an SSRF guard.

Safety model:
  * **Read-only.** There is no tool that writes, moves or deletes a file. Conversion output
    is returned, never saved.
  * **Containment.** Every path is resolved (symlinks followed) and must stay inside its
    allow-listed root. Absolute and drive-qualified paths in arguments are refused outright,
    as are dotfiles and Windows system folders — the same rules as files-mcp, because a
    second, subtly-different implementation is how allow-lists get bypassed.
  * **Classification is preserved.** Output carries the root's NDMO label, so the gateway's
    DLP and clearance gate treat converted text exactly like the source document. Converting
    a document must not launder its classification.
  * **Caps.** Input size, output size, and a structured error instead of an exception when
    unconfigured (the gateway must never crash on discovery).
"""
import contextlib
import io
import json
import os
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("markitdown")

MAX_IN = int(os.environ.get("MARKITDOWN_MAX_FILE_BYTES", 20_000_000))
MAX_OUT = int(os.environ.get("MARKITDOWN_MAX_OUTPUT_BYTES", 1_000_000))

_HIDDEN = {"$RECYCLE.BIN", "System Volume Information", "__pycache__"}

# Formats MarkItDown handles. Kept explicit so the tool can tell an operator what it
# supports without them having to try and fail.
SUPPORTED = {
    ".pdf": "PDF document",
    ".docx": "Word document", ".doc": "Word document (legacy)",
    ".xlsx": "Excel workbook", ".xls": "Excel workbook (legacy)", ".csv": "CSV table",
    ".pptx": "PowerPoint deck",
    ".html": "HTML page", ".htm": "HTML page",
    ".txt": "Plain text", ".md": "Markdown", ".json": "JSON", ".xml": "XML",
    ".epub": "EPUB book",
    ".png": "Image (OCR/description)", ".jpg": "Image", ".jpeg": "Image",
    ".zip": "Archive (contents converted)",
}


def _err(msg: str, **extra) -> str:
    return json.dumps({"error": msg, **extra}, ensure_ascii=False)


# --------------------------------------------------------------------------
# roots — identical rules to files_server (one allow-list, one implementation)
# --------------------------------------------------------------------------

def _roots() -> dict[str, dict]:
    raw = (os.environ.get("DOCS_ROOTS") or "").strip()
    if not raw:
        return {}
    out: dict[str, dict] = {}
    try:
        if raw.startswith("["):
            for r in json.loads(raw):
                out[r["name"]] = {
                    "path": Path(r["path"]).resolve(),
                    "classification": r.get("classification", "secret"),
                    "description": r.get("description", ""),
                }
        else:
            for chunk in raw.split(";"):
                if not chunk.strip():
                    continue
                name, path, *rest = chunk.split("=")
                out[name.strip()] = {
                    "path": Path(path.strip()).resolve(),
                    "classification": (rest[0].strip() if rest else "secret"),
                    "description": "",
                }
    except Exception as e:
        raise ValueError(f"DOCS_ROOTS is malformed: {e}") from e
    return out


def _resolve(share: str, rel: str) -> tuple[Optional[Path], Optional[dict], Optional[str]]:
    """Resolve (share, relative path) to a real file inside its root, or explain the refusal.

    Containment is checked AFTER resolution, so a symlink that points outside the root is
    caught — checking the string before resolving is the classic way this is got wrong.
    """
    try:
        roots = _roots()
    except ValueError as e:
        return None, None, str(e)
    if not roots:
        return None, None, ("markitdown-mcp is not configured: set DOCS_ROOTS (the same "
                            "allow-listed roots as files-mcp)")
    root = roots.get(share)
    if not root:
        return None, None, f"unknown share '{share}'. Available: {sorted(roots)}"

    rel = (rel or "").strip().replace("\\", "/")
    if not rel:
        return None, None, "path is required"
    p = Path(rel)
    if p.is_absolute() or p.drive or rel.startswith("/"):
        return None, None, ("absolute paths are refused — give a path relative to the share")
    # Say plainly WHY. ".." is caught by the dotfile rule below too, but reporting a
    # traversal attempt as "hidden path" would send an operator debugging the wrong thing.
    if ".." in p.parts:
        return None, None, (f"'..' is not allowed in a path — a document must stay inside "
                            f"the '{share}' share")
    if any(part in _HIDDEN or part.startswith(".") for part in p.parts):
        return None, None, "hidden and system paths are not accessible"

    target = (root["path"] / p).resolve()
    try:
        target.relative_to(root["path"])          # containment, post-resolution
    except ValueError:
        return None, None, (f"path escapes the '{share}' share — refused")
    if not target.exists() or not target.is_file():
        return None, None, f"no such file in '{share}': {rel}"
    return target, root, None


_md = None


def _engine():
    """Build the MarkItDown engine once, with stdout muzzled.

    Two hard-won reasons this is not simply constructed per call:

    1. THIS SERVER SPEAKS MCP OVER STDOUT. A document parser that prints — a PDF library
       grumbling about a malformed xref, an audio converter warning that ffmpeg is missing —
       writes those bytes straight into the JSON-RPC stream and desynchronises the
       transport. The connection then dies with an opaque `OSError: [Errno 22] Invalid
       argument` on the next flush. Nothing but MCP frames may ever reach stdout.

    2. Construction is EXPENSIVE and does hostile things: it lazily loads every converter,
       and the audio one probes for ffmpeg by spawning a subprocess. Doing that inside a
       request — in a process whose stdin/stdout are the MCP pipes — can deadlock outright.
       We pay the cost once, off the request path.
    """
    global _md
    if _md is None:
        from markitdown import MarkItDown
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            _md = MarkItDown(enable_plugins=False)   # plugins are third-party code: off
    return _md


def _convert_blocking(path_or_url: str) -> tuple[Optional[str], Optional[str]]:
    """The actual conversion. BLOCKING — must only ever be called on a worker thread."""
    try:
        from markitdown import MarkItDown  # noqa: F401  (import check)
    except ImportError:
        return None, ("markitdown is not installed on the gateway host "
                      "(pip install markitdown[all])")
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = _engine().convert(path_or_url)
            text = result.text_content or ""
        return text, None
    except Exception as e:
        return None, f"conversion failed: {type(e).__name__}: {str(e)[:200]}"


async def _convert(path_or_url: str) -> tuple[Optional[str], Optional[str]]:
    """Convert OFF the event loop.

    Document parsing is CPU-bound and, worse, some parsers block on I/O or spawn
    subprocesses. Running that inline in an MCP server's event loop freezes the entire
    server: it stops answering, the client times out, and it looks like a hang with no
    error. A worker thread keeps the protocol responsive no matter how badly a parser
    behaves.
    """
    import anyio
    return await anyio.to_thread.run_sync(_convert_blocking, path_or_url)


def _cap(text: str) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= MAX_OUT:
        return text, False
    return raw[:MAX_OUT].decode("utf-8", "ignore"), True


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

@mcp.tool()
def list_supported_formats() -> str:
    """Which document formats this server can turn into Markdown, and which shares it may
    read from. Call this when a conversion is refused, before guessing."""
    try:
        roots = _roots()
    except ValueError as e:
        return _err(str(e))
    return json.dumps({
        "formats": [{"extension": k, "description": v} for k, v in sorted(SUPPORTED.items())],
        "shares": [{"name": n, "classification": r["classification"],
                    "description": r["description"]} for n, r in sorted(roots.items())],
        "configured": bool(roots),
        "max_input_bytes": MAX_IN,
        "urls_enabled": os.environ.get("MARKITDOWN_ALLOW_URLS", "") in ("1", "true", "yes"),
    }, ensure_ascii=False)


@mcp.tool()
async def convert_document(share: str, path: str) -> str:
    """Convert a document in an allow-listed share to Markdown.

    Handles PDF, Word, Excel, PowerPoint, HTML, CSV, EPUB and images. The output carries the
    share's classification, so a converted document is governed exactly like the original —
    conversion never launders a document's sensitivity.
    """
    target, root, why = _resolve(share, path)
    if why:
        return _err(why, share=share, path=path)

    size = target.stat().st_size
    if size > MAX_IN:
        return _err(f"file is {size} bytes, over the {MAX_IN} limit", share=share, path=path)
    ext = target.suffix.lower()
    if ext not in SUPPORTED:
        return _err(f"unsupported format '{ext}'", share=share, path=path,
                    supported=sorted(SUPPORTED))

    text, err = await _convert(str(target))
    if err:
        return _err(err, share=share, path=path)
    text, truncated = _cap(text)
    return json.dumps({
        "share": share, "path": path,
        "classification": root["classification"],     # governed like the source
        "source_format": SUPPORTED[ext],
        "source_bytes": size,
        "markdown": text,
        "markdown_bytes": len(text.encode("utf-8")),
        "truncated": truncated,
    }, ensure_ascii=False)


@mcp.tool()
async def describe_document(share: str, path: str) -> str:
    """Metadata and a short preview of a document, without converting the whole thing —
    use it to decide whether a large PDF is worth converting at all."""
    target, root, why = _resolve(share, path)
    if why:
        return _err(why, share=share, path=path)

    ext = target.suffix.lower()
    stat = target.stat()
    info = {
        "share": share, "path": path,
        "classification": root["classification"],
        "size_bytes": stat.st_size,
        "modified": int(stat.st_mtime),
        "extension": ext,
        "format": SUPPORTED.get(ext, "unsupported"),
        "convertible": ext in SUPPORTED and stat.st_size <= MAX_IN,
    }
    if info["convertible"]:
        text, err = await _convert(str(target))
        if err:
            info["preview_error"] = err
        else:
            preview = (text or "")[:800]
            info["preview"] = preview
            info["estimated_markdown_bytes"] = len((text or "").encode("utf-8"))
    return json.dumps(info, ensure_ascii=False)


@mcp.tool()
async def convert_url(url: str) -> str:
    """Fetch a URL and convert it to Markdown.

    OFF by default (MARKITDOWN_ALLOW_URLS=1 to enable): fetching a URL server-side, from
    inside the network, is a server-side request forgery primitive. browser-mcp already does
    web content behind a host allow-list and a DNS-resolution SSRF guard — prefer it.
    """
    if os.environ.get("MARKITDOWN_ALLOW_URLS", "") not in ("1", "true", "yes"):
        return _err("URL conversion is disabled on this gateway "
                    "(set MARKITDOWN_ALLOW_URLS=1 to enable). "
                    "Use browser-mcp's read_page, which enforces a host allow-list and an "
                    "SSRF guard.")
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        return _err(f"scheme '{u.scheme or 'none'}' is refused — only http and https")
    raw, err = await _convert(url)          # off the event loop, stdout muzzled
    if err:
        return _err(err, url=url)
    text, truncated = _cap(raw or "")
    return json.dumps({"url": url, "markdown": text, "truncated": truncated,
                       "classification": "restricted"}, ensure_ascii=False)


if __name__ == "__main__":
    # Warm the engine BEFORE the MCP transport takes over stdout. Building it lazily inside
    # the first request meant loading every converter — including one that probes for ffmpeg
    # by spawning a subprocess — while stdin/stdout were the MCP pipes. That deadlocked the
    # first conversion and looked like a hang with no error anywhere.
    try:
        _engine()
    except Exception:
        pass                    # unavailable engine is reported per call, not at boot
    mcp.run()   # stdio
