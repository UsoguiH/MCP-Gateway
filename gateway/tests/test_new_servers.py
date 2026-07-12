"""Security + behaviour tests for the three new connectors (browser, markitdown, qdrant).

These three are the most dangerous tools in the catalogue, and the tests are written around
the ways each one could be turned against the organization:

  browser    — an unconstrained browser is an SSRF and exfiltration primitive. It could
               reach internal admin panels the gateway itself cannot, read the cloud
               metadata endpoint, or POST documents to any host. The guard must hold even
               when the attacker controls DNS.
  markitdown — a second file reader is a second chance to escape the document allow-list.
               It must obey exactly the same containment as files-mcp.
  qdrant     — a vector store is where organizational knowledge accumulates OUTSIDE the
               document controls. Retrieved passages must stay classified, and a
               read-only collection must be read-only.
"""
import json
import sys
from pathlib import Path

import pytest

SERVERS = Path(__file__).resolve().parents[1] / "servers"
sys.path.insert(0, str(SERVERS))

import browser_server as bs        # noqa: E402
import markitdown_server as ms     # noqa: E402
import qdrant_server as qs         # noqa: E402


def j(raw: str) -> dict:
    return json.loads(raw)


def run(coro):
    """Await an async tool from a sync test. The connector tools are async because they run
    blocking work (Chromium, document parsing, embedding) off the event loop."""
    import asyncio
    return asyncio.run(coro)


# ══════════════════════════════════════════════════════════════════════════
# risk tiering — the gateway's own judgement, not the server's claim
# ══════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("server,tool,tier", [
    # browser: reading the web is safe. Acting on it, or running code in it, is not.
    ("browser", "read_page", 0),
    ("browser", "extract_tables", 0),
    ("browser", "screenshot_page", 0),
    ("browser", "search_page_text", 0),
    ("browser", "fill_and_submit", 2),        # submits a form in the user's name
    ("browser", "evaluate_javascript", 3),    # arbitrary JS in the page's origin
    # markitdown: pure read-only conversion of already-exposed documents.
    ("markitdown", "convert_document", 0),
    ("markitdown", "describe_document", 0),
    ("markitdown", "convert_url", 2),         # reaches OUT of the network
    # qdrant: search reads, store is reversible, deletion is not.
    ("qdrant", "search", 0),
    ("qdrant", "count_points", 0),
    ("qdrant", "store", 1),
    ("qdrant", "upsert_vectors", 1),
    ("qdrant", "delete_points", 3),
    ("qdrant", "delete_collection", 3),
])
def test_new_connectors_are_tiered_correctly(server, tool, tier):
    """Two failure modes, both dangerous:

    Too LOW and a destructive tool auto-executes — `evaluate_javascript` is arbitrary code
    execution, and the name heuristic alone rated it 2 (one approver), not 3.

    Too HIGH and every harmless read demands a human. That is not "extra safe": it trains
    approvers to click yes without reading, and a rubber-stamped tier-2 gate is worth
    nothing on the day it matters. The heuristic rated `screenshot_page` and
    `convert_document` at 2 for exactly this reason.
    """
    from app.registry import _default_tier
    assert _default_tier(tool, server) == tier


def test_a_hostile_server_cannot_inherit_a_safe_tier_by_naming(monkeypatch):
    """The curated tiers are keyed on (server, tool), and the server name comes from OUR
    config — never from the server's own claims. A rogue server that names its tool
    `read_page` gets the heuristic, not browser's curated tier-0."""
    from app.registry import _default_tier
    assert _default_tier("read_page", "browser") == 0
    assert _default_tier("read_page", "rogue-server") == 0     # heuristic agrees here...
    # ...but it cannot inherit a curated LOW tier for a dangerous name:
    assert _default_tier("evaluate_javascript", "rogue-server") == 3
    assert _default_tier("delete_collection", "rogue-server") == 3


# ══════════════════════════════════════════════════════════════════════════
# browser — the allow-list and the SSRF guard
# ══════════════════════════════════════════════════════════════════════════
@pytest.fixture
def browser(monkeypatch):
    monkeypatch.setenv("BROWSER_ALLOWED_DOMAINS", "example.com,.gov.sa")
    monkeypatch.delenv("BROWSER_ALLOW_PRIVATE_IPS", raising=False)
    monkeypatch.delenv("BROWSER_ALLOW_EVAL", raising=False)
    monkeypatch.delenv("BROWSER_ALLOW_INTERACTION", raising=False)
    return bs


def test_browser_refuses_everything_when_unconfigured(monkeypatch):
    """There is deliberately no allow-everything value. Unconfigured must mean inert."""
    monkeypatch.setenv("BROWSER_ALLOWED_DOMAINS", "")
    ok, why = bs._admit("https://example.com/")
    assert ok is False and "not configured" in why


def test_browser_host_allow_list(browser, monkeypatch):
    # Pin DNS to a public address so this test exercises the ALLOW-LIST, not the network.
    monkeypatch.setattr(bs.socket, "getaddrinfo",
                        lambda h, p, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert bs._admit("https://example.com/page")[0] is True
    assert bs._admit("https://open.data.gov.sa/x")[0] is True     # .gov.sa ⇒ subdomains
    assert bs._admit("https://gov.sa/x")[0] is True               # ...and the apex
    ok, why = bs._admit("https://evil.example/x")
    assert ok is False and "not in BROWSER_ALLOWED_DOMAINS" in why
    # Lookalikes must not slip through a naive endswith() — these are the bypasses that
    # matter: "notexample.com".endswith("example.com") is True.
    assert bs._admit("https://notexample.com/x")[0] is False
    assert bs._admit("https://example.com.evil.net/x")[0] is False
    assert bs._admit("https://evilgov.sa/x")[0] is False


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
    "ftp://example.com/x",
])
def test_browser_refuses_non_http_schemes(browser, url):
    """file:// would turn the browser into a local-file reader that bypasses every
    document allow-list in the system."""
    ok, why = bs._admit(url)
    assert ok is False
    assert "refused" in why or "scheme" in why


@pytest.mark.parametrize("host,addr", [
    ("metadata.evil.test", "169.254.169.254"),   # cloud metadata — the classic SSRF pivot
    ("intranet.evil.test", "10.1.2.3"),          # RFC1918
    ("local.evil.test", "127.0.0.1"),            # loopback
    ("private.evil.test", "192.168.1.1"),
])
def test_browser_ssrf_guard_blocks_names_that_resolve_internally(browser, monkeypatch,
                                                                 host, addr):
    """The check is on the RESOLVED ADDRESS, not the string. A public-looking name that
    points at 169.254.169.254 is exactly how cloud credentials get stolen — and an
    allow-listed domain is not a defence if its DNS is attacker-controlled."""
    monkeypatch.setenv("BROWSER_ALLOWED_DOMAINS", host)
    monkeypatch.setattr(bs.socket, "getaddrinfo",
                        lambda h, p, *a, **k: [(2, 1, 6, "", (addr, 0))])
    ok, why = bs._admit(f"https://{host}/")
    assert ok is False, f"{host} -> {addr} must be refused"
    assert "non-public address" in why and "SSRF" in why


def test_browser_ssrf_guard_can_be_deliberately_disabled(browser, monkeypatch):
    """It is an explicit, reviewed decision — not an accident."""
    monkeypatch.setenv("BROWSER_ALLOWED_DOMAINS", "internal.test")
    monkeypatch.setenv("BROWSER_ALLOW_PRIVATE_IPS", "1")
    monkeypatch.setattr(bs.socket, "getaddrinfo",
                        lambda h, p, *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    assert bs._admit("https://internal.test/")[0] is True


def test_browser_unresolvable_host_is_refused(browser, monkeypatch):
    import socket as real_socket

    def boom(*a, **k):
        raise real_socket.gaierror("nope")

    monkeypatch.setattr(bs.socket, "getaddrinfo", boom)
    ok, why = bs._admit("https://example.com/")
    assert ok is False and "does not resolve" in why


def test_browser_dangerous_tools_are_off_by_default(browser):
    """JS evaluation is remote code execution in the page's origin; form submission acts in
    the user's name. Both must be opt-in."""
    r = j(run(bs.evaluate_javascript("https://example.com", "1+1")))
    assert "disabled" in r["error"]
    r = j(run(bs.fill_and_submit("https://example.com", {"#q": "x"})))
    assert "disabled" in r["error"]


def test_browser_reports_its_own_posture(browser):
    r = j(bs.list_allowed_domains())
    assert r["configured"] is True
    assert r["allowed_domains"] == ["example.com", ".gov.sa"]
    assert r["javascript_evaluation_enabled"] is False
    assert r["private_ips_allowed"] is False


def test_browser_redirect_landing_is_rechecked(browser):
    """An allow-listed host that 302s to an attacker's domain must not be followed."""
    class FakePage:
        url = "https://example.com/start"
        final_url = "https://evil.example/landed"
    out = bs._check_landing(FakePage())
    assert out is not None
    assert "not permitted" in j(out)["error"]
    FakePage.final_url = "https://example.com/ok"
    assert bs._check_landing(FakePage()) is None


# ══════════════════════════════════════════════════════════════════════════
# markitdown — containment (a converter must not be a way around the allow-list)
# ══════════════════════════════════════════════════════════════════════════
@pytest.fixture
def docs(tmp_path, monkeypatch):
    root = tmp_path / "public"
    (root / "sub").mkdir(parents=True)
    (root / "hello.md").write_text("# Title\n\nBody text here.", encoding="utf-8")
    (root / "sub" / "nested.txt").write_text("nested content", encoding="utf-8")
    (root / ".hidden.md").write_text("secret", encoding="utf-8")
    (tmp_path / "outside.md").write_text("MUST NOT BE READABLE", encoding="utf-8")
    monkeypatch.setenv("DOCS_ROOTS", json.dumps(
        [{"name": "public", "path": str(root), "classification": "restricted"}]))
    return tmp_path


def test_markitdown_unconfigured_is_a_clean_error_not_a_crash(monkeypatch):
    monkeypatch.setenv("DOCS_ROOTS", "")
    r = j(run(ms.convert_document("public", "x.md")))
    assert "not configured" in r["error"]


@pytest.mark.parametrize("evil", [
    "../outside.md",
    "../../outside.md",
    "sub/../../outside.md",
    "/etc/passwd",
    "C:/Windows/win.ini",
    "..\\outside.md",
    ".hidden.md",
])
def test_markitdown_path_traversal_is_refused(docs, evil):
    """The same containment as files-mcp. A second, subtly-different implementation is
    exactly how allow-lists get bypassed."""
    r = j(run(ms.convert_document("public", evil)))
    assert "error" in r, f"{evil!r} must be refused"
    assert "MUST NOT BE READABLE" not in json.dumps(r)


def test_markitdown_symlink_escape_is_refused(docs, monkeypatch):
    """Containment is checked AFTER resolution, so a symlink pointing out of the root is
    caught — checking the string before resolving is the classic way this is got wrong."""
    link = docs / "public" / "escape.md"
    try:
        link.symlink_to(docs / "outside.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    r = j(run(ms.convert_document("public", "escape.md")))
    assert "error" in r and "escapes" in r["error"]


def test_markitdown_unknown_share_is_refused(docs):
    r = j(run(ms.convert_document("hr", "anything.md")))
    assert "unknown share" in r["error"]


def test_markitdown_converts_and_preserves_classification(docs):
    r = j(run(ms.convert_document("public", "hello.md")))
    assert "error" not in r, r
    assert "Title" in r["markdown"]
    # A converted document must NOT launder its sensitivity.
    assert r["classification"] == "restricted"
    assert r["source_format"] == "Markdown"


def test_markitdown_describe_previews_without_full_conversion(docs):
    r = j(run(ms.describe_document("public", "hello.md")))
    assert r["convertible"] is True
    assert r["classification"] == "restricted"
    assert "Title" in r["preview"]


def test_markitdown_oversized_input_is_refused(docs, monkeypatch):
    monkeypatch.setattr(ms, "MAX_IN", 5)
    r = j(run(ms.convert_document("public", "hello.md")))
    assert "over the" in r["error"]


def test_markitdown_url_conversion_is_off_by_default(monkeypatch):
    """Fetching a URL server-side is SSRF; browser-mcp does it properly, behind a guard."""
    monkeypatch.delenv("MARKITDOWN_ALLOW_URLS", raising=False)
    r = j(run(ms.convert_url("https://example.com")))
    assert "disabled" in r["error"] and "browser-mcp" in r["error"]


def test_markitdown_lists_formats_and_shares(docs):
    r = j(ms.list_supported_formats())
    assert r["configured"] is True
    assert any(f["extension"] == ".pdf" for f in r["formats"])
    assert r["shares"][0]["classification"] == "restricted"


# ══════════════════════════════════════════════════════════════════════════
# qdrant — the collection allow-list and classification
# ══════════════════════════════════════════════════════════════════════════
@pytest.fixture
def qcfg(monkeypatch):
    monkeypatch.setenv("QDRANT_COLLECTIONS", "notes:restricted, kb:public:ro, hr:secret")
    monkeypatch.setenv("QDRANT_URL", "http://127.0.0.1:1")     # unreachable on purpose
    monkeypatch.delenv("QDRANT_ALLOW_DELETE_COLLECTION", raising=False)
    qs._client = None
    return qs


def test_qdrant_collection_allow_list(qcfg):
    spec, why = qs._admit("notes")
    assert why is None and spec["classification"] == "restricted"

    spec, why = qs._admit("secrets-i-invented")
    assert spec is None and "not allow-listed" in why


def test_qdrant_readonly_collection_refuses_writes(qcfg):
    """`:ro` holds at this layer, independently of the caller's role."""
    assert qs._admit("kb")[0] is not None                    # readable
    spec, why = qs._admit("kb", write=True)
    assert spec is None and "read-only" in why


def test_qdrant_unconfigured_is_a_clean_error(monkeypatch):
    monkeypatch.setenv("QDRANT_COLLECTIONS", "")
    qs._client = None
    r = j(qs.list_collections())
    assert "not configured" in r["error"]


def test_qdrant_delete_collection_is_off_by_default(qcfg):
    r = j(qs.delete_collection("notes", confirm=True))
    assert "disabled" in r["error"]


def test_qdrant_delete_collection_needs_explicit_confirmation(qcfg, monkeypatch):
    monkeypatch.setenv("QDRANT_ALLOW_DELETE_COLLECTION", "1")
    r = j(qs.delete_collection("notes"))            # confirm defaults to False
    assert "confirm=true" in r["error"] and "irreversible" in r["error"]


def test_qdrant_delete_points_requires_explicit_ids(qcfg):
    """There is deliberately no 'delete everything matching' form."""
    r = j(qs.delete_points("notes", []))
    assert "non-empty" in r["error"]


def test_qdrant_unreachable_server_is_reported_not_crashed(qcfg):
    r = j(qs.count_points("notes"))
    assert "cannot reach Qdrant" in r["error"]


def test_qdrant_text_is_capped(qcfg, monkeypatch):
    monkeypatch.setattr(qs, "MAX_TEXT", 10)
    assert qs._cap_text("x" * 500) == "x" * 10


def test_qdrant_point_output_carries_classification(qcfg):
    class P:
        id = "abc"
        score = 0.9123456
        payload = {"text": "hello", "source": "manual"}
    out = qs._point_out(P(), "secret")
    assert out["classification"] == "secret"     # governed like any other document
    assert out["text"] == "hello"
    assert out["metadata"] == {"source": "manual"}
    assert out["score"] == 0.91235
