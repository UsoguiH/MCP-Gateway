"""Tests for files-mcp (servers/files_server.py) — the production internal-docs
/ file-share server. No external backend needed: shares are temp directories,
so the whole suite runs everywhere.

Covers the Phase-1 safety contract:
  * read-only tool surface
  * path containment (traversal / absolute-path / hidden-entry refusal)
  * classification labels stamped on every result
  * caps + truncation reporting
  * lazy config error when DOCS_ROOTS is unset/invalid
"""
import asyncio
import json
import sys
import zipfile
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client, get_default_environment

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_TOOLS = {"list_shares", "list_directory", "find_files",
                  "search_content", "read_document", "get_file_info"}


class Server:
    """Drive the stdio server synchronously (same pattern as test_mcp_servers)."""

    def __init__(self, env: dict):
        self.params = StdioServerParameters(
            command=sys.executable,
            args=[str(ROOT / "servers" / "files_server.py")],
            env={**get_default_environment(), **env},
        )

    async def _call(self, calls):
        results = []
        async with stdio_client(self.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                results.append([t.name for t in listing.tools])
                for name, args in calls:
                    res = await session.call_tool(name, args)
                    text = "".join(c.text for c in res.content
                                   if getattr(c, "text", None))
                    try:
                        results.append(json.loads(text))
                    except (json.JSONDecodeError, ValueError):
                        results.append({"_raw": text})
        return results

    def run(self, calls):
        return asyncio.run(self._call(calls))


# --------------------------------------------------------------------------
# fixture: two shares on disk
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def shares(tmp_path_factory):
    base = tmp_path_factory.mktemp("shares")
    pub = base / "public_docs"
    hr = base / "hr_docs"
    (pub / "sub").mkdir(parents=True)
    hr.mkdir()

    (pub / "handbook.txt").write_text(
        "Employee Handbook\nWorking hours are 8:00-16:00 Sunday to Thursday.\n"
        "Annual leave is 30 days.\n", encoding="utf-8")
    (pub / "guide.md").write_text(
        "# Guide\nThe vacation policy allows carry-over of 5 days.\n", encoding="utf-8")
    (pub / "sub" / "notes.txt").write_text("meeting notes: budget review\n", encoding="utf-8")
    (pub / ".hidden.txt").write_text("should never be visible\n", encoding="utf-8")
    (pub / "big.log").write_text("x" * 5000 + "\nNEEDLE at the end\n", encoding="utf-8")

    # Minimal valid .docx (a zip with word/document.xml)
    with zipfile.ZipFile(pub / "report.docx", "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document><w:body>'
                   "<w:p><w:r><w:t>Quarterly report: revenue grew 12 percent.</w:t></w:r></w:p>"
                   "<w:p><w:r><w:t>Second paragraph here.</w:t></w:r></w:p>"
                   "</w:body></w:document>")

    (hr / "salary.txt").write_text(
        "Employee Ahmed A., salary 18,500 SAR, IBAN SA4420000001234567891234\n",
        encoding="utf-8")

    # A file OUTSIDE any share — traversal target that must stay unreachable.
    (base / "outside_secret.txt").write_text("out of bounds\n", encoding="utf-8")
    return {"base": base, "pub": pub, "hr": hr}


@pytest.fixture(scope="module")
def env(shares):
    roots = json.dumps([
        {"name": "public", "path": str(shares["pub"]),
         "classification": "public", "description": "public docs"},
        {"name": "hr", "path": str(shares["hr"]), "classification": "secret"},
    ])
    return {"DOCS_ROOTS": roots}


# --------------------------------------------------------------------------
# happy paths
# --------------------------------------------------------------------------

def test_tool_surface_is_read_only(env):
    out = Server(env).run([("list_shares", {})])
    names = set(out[0])
    assert names == EXPECTED_TOOLS
    forbidden = ("write", "delete", "move", "copy", "create", "update", "upload")
    assert not [n for n in names for w in forbidden if w in n]


def test_list_shares(env):
    out = Server(env).run([("list_shares", {})])
    payload = out[1]
    assert payload["read_only"] is True
    by_name = {s["name"]: s for s in payload["shares"]}
    assert by_name["public"]["classification"] == "public"
    assert by_name["public"]["reachable"] is True
    assert by_name["hr"]["classification"] == "secret"
    # Real filesystem paths are never disclosed to the model.
    assert "path" not in by_name["public"]


def test_list_directory_and_hidden_exclusion(env):
    out = Server(env).run([("list_directory", {"share": "public"})])
    entries = out[1]["entries"]
    names = [e["name"] for e in entries]
    assert "handbook.txt" in names and "sub" in names
    assert ".hidden.txt" not in names
    assert out[1]["classification"] == "public"
    kinds = {e["name"]: e["type"] for e in entries}
    assert kinds["sub"] == "dir" and kinds["handbook.txt"] == "file"


def test_find_files_across_shares(env):
    out = Server(env).run([
        ("find_files", {"pattern": "*.txt"}),
        ("find_files", {"pattern": "handbook", "share": "public"}),
    ])
    all_hits = out[1]["results"]
    assert {h["share"] for h in all_hits} == {"public", "hr"}
    assert all("classification" in h for h in all_hits)
    assert not [h for h in all_hits if ".hidden" in h["path"]]
    assert [h["path"] for h in out[2]["results"]] == ["handbook.txt"]


def test_search_content(env):
    out = Server(env).run([
        ("search_content", {"query": "working hours"}),
        ("search_content", {"query": "vacation", "extensions": ".md"}),
        ("search_content", {"query": "revenue"}),          # inside the .docx
    ])
    hit = out[1]["results"][0]
    assert hit["path"] == "handbook.txt" and hit["line"] == 2
    assert "Working hours" in hit["snippet"]
    assert [h["path"] for h in out[2]["results"]] == ["guide.md"]
    docx_hits = [h for h in out[3]["results"] if h["path"] == "report.docx"]
    assert docx_hits, "search must reach .docx content"


def test_read_document_text_and_docx(env):
    out = Server(env).run([
        ("read_document", {"share": "public", "path": "handbook.txt"}),
        ("read_document", {"share": "public", "path": "report.docx"}),
        ("read_document", {"share": "hr", "path": "salary.txt"}),
    ])
    assert "Annual leave" in out[1]["text"]
    assert out[1]["classification"] == "public" and out[1]["truncated"] is False
    assert "Quarterly report" in out[2]["text"] and "Second paragraph" in out[2]["text"]
    assert out[3]["classification"] == "secret"


def test_get_file_info_hash(env, shares):
    out = Server(env).run([("get_file_info", {"share": "public", "path": "handbook.txt"})])
    info = out[1]
    assert info["type"] == "file" and info["extension"] == ".txt"
    assert len(info["sha256"]) == 64
    assert info["size"] == (shares["pub"] / "handbook.txt").stat().st_size


def test_truncation_and_continuation(shares):
    env_small = {
        "DOCS_ROOTS": json.dumps([{"name": "public", "path": str(shares["pub"]),
                                   "classification": "public"}]),
        "DOCS_MAX_FILE_BYTES": "1000",
    }
    out = Server(env_small).run([
        ("read_document", {"share": "public", "path": "big.log"}),
    ])
    first = out[1]
    assert first["truncated"] is True and first["next_start"] == 1000

    # Walk the continuation chain to the end; the tail must be reachable.
    text, start, hops = first["text"], first["next_start"], 0
    while start is not None and hops < 10:
        page = Server(env_small).run([
            ("read_document", {"share": "public", "path": "big.log", "start": start}),
        ])[1]
        text += page["text"]
        start = page["next_start"]
        hops += 1
    assert start is None, "continuation chain must terminate"
    assert "NEEDLE at the end" in text


# --------------------------------------------------------------------------
# containment: the attacks the server MUST refuse
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad_path", [
    "..",
    "../outside_secret.txt",
    "..\\outside_secret.txt",
    "sub/../../outside_secret.txt",
    "sub\\..\\..\\outside_secret.txt",
    "/etc/passwd",
    "C:/Windows/win.ini",
    "C:\\Windows\\win.ini",
])
def test_traversal_refused(env, bad_path):
    out = Server(env).run([
        ("read_document", {"share": "public", "path": bad_path}),
        ("list_directory", {"share": "public", "path": bad_path}),
        ("get_file_info", {"share": "public", "path": bad_path}),
    ])
    for payload in out[1:]:
        assert "error" in payload, f"{bad_path} must be refused, got {payload}"
        assert "out of bounds" not in json.dumps(payload)


def test_hidden_file_unreachable_directly(env):
    out = Server(env).run([
        ("read_document", {"share": "public", "path": ".hidden.txt"}),
        ("get_file_info", {"share": "public", "path": ".hidden.txt"}),
    ])
    assert "error" in out[1] and "error" in out[2]
    assert "never be visible" not in json.dumps(out[1])


def test_unknown_share_refused(env):
    out = Server(env).run([
        ("read_document", {"share": "finance", "path": "x.txt"}),
        ("list_directory", {"share": "../public", "path": ""}),
    ])
    assert "unknown share" in out[1]["error"]
    assert "error" in out[2]


# --------------------------------------------------------------------------
# configuration behavior
# --------------------------------------------------------------------------

def test_unconfigured_is_lazy_not_fatal():
    out = Server({"DOCS_ROOTS": ""}).run([
        ("list_shares", {}),
        ("read_document", {"share": "x", "path": "y"}),
    ])
    assert set(out[0]) == EXPECTED_TOOLS          # tools still register
    assert "not configured" in out[1]["error"]
    assert "not configured" in out[2]["error"]


def test_invalid_config_reports_cleanly(shares):
    bad = json.dumps([{"name": "ok", "path": str(shares["pub"]),
                       "classification": "ultra"}])      # bad label
    out = Server({"DOCS_ROOTS": bad}).run([("list_shares", {})])
    assert "misconfigured" in out[1]["error"]


def test_relative_root_path_refused(tmp_path):
    bad = json.dumps([{"name": "rel", "path": "relative/dir", "classification": "public"}])
    out = Server({"DOCS_ROOTS": bad}).run([("list_shares", {})])
    assert "misconfigured" in out[1]["error"] and "absolute" in out[1]["error"]
