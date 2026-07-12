"""browser-mcp — governed web browsing for the gateway (Playwright/Chromium).

A browser is the most dangerous tool in this catalogue. Handed to an AI without
constraints it is a general-purpose **SSRF and exfiltration primitive**: it can reach
internal admin panels the gateway itself cannot, read cloud-metadata endpoints, and POST
your documents to any host on the internet. Every design decision below exists because of
that, and the defaults are deliberately hostile.

Configuration (environment; never via model-visible args):

  BROWSER_ALLOWED_DOMAINS  REQUIRED. Comma-separated host allow-list. There is no
                           wildcard-everything value: with this unset, every call is
                           refused. A leading dot allows subdomains
                           (".gov.sa" allows "open.data.gov.sa").
  BROWSER_ALLOW_PRIVATE_IPS  "1" to permit RFC1918 / loopback / link-local targets.
                           OFF by default. Leave it off unless you have a specific,
                           reviewed reason: this is the switch that turns the browser
                           into an SSRF tool against your own network.
  BROWSER_ALLOW_EVAL       "1" to enable evaluate_javascript. OFF by default — arbitrary
                           JS in a page context is remote code execution against whatever
                           that page can reach.
  BROWSER_ALLOW_INTERACTION "1" to enable fill_and_submit. OFF by default (it writes).
  BROWSER_MAX_TEXT_BYTES   cap on extracted text (default 200_000)
  BROWSER_MAX_LINKS        cap on returned links (default 200)
  BROWSER_TIMEOUT_MS       per-navigation timeout (default 20_000)
  BROWSER_SCREENSHOT_MAX_BYTES  cap on a returned screenshot (default 3_000_000)

Safety model:
  * **Allow-list first.** The URL is parsed and the host checked BEFORE a browser is
    launched. No allow-list ⇒ nothing works.
  * **SSRF guard.** The host is DNS-resolved and every resulting address is checked; a
    name that resolves to a private, loopback, link-local, or reserved address is refused
    even if its domain is allow-listed. This is what stops `evil.com A 169.254.169.254`
    (DNS rebinding to the cloud metadata service).
  * **Redirects are re-checked.** The final URL after redirects must ALSO satisfy the
    allow-list — an allow-listed host that 302s to an attacker's domain gets refused.
  * **No local files.** `file://`, `data:` and every non-http(s) scheme are refused.
  * **No shared state between calls or users.** Each call gets a fresh browser context:
    no cookies, storage or logins survive, so one operator's authenticated session can
    never leak into another's.
  * **Downloads are refused**; the browser never writes to disk.
  * Read-only by default. Interaction and JS evaluation are separate opt-in flags, and the
    gateway tiers them for human approval regardless.
  * Caps on text, links, screenshot bytes and wall-clock, and a structured error rather
    than an exception when unconfigured (the gateway must never crash on discovery).
"""
import ipaddress
import json
import os
import socket
from typing import Optional
from urllib.parse import urlparse, urljoin

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("browser")

MAX_TEXT = int(os.environ.get("BROWSER_MAX_TEXT_BYTES", 200_000))
MAX_LINKS = int(os.environ.get("BROWSER_MAX_LINKS", 200))
TIMEOUT_MS = int(os.environ.get("BROWSER_TIMEOUT_MS", 20_000))
MAX_SHOT = int(os.environ.get("BROWSER_SCREENSHOT_MAX_BYTES", 3_000_000))


def _allowed_domains() -> list[str]:
    raw = os.environ.get("BROWSER_ALLOWED_DOMAINS", "").strip()
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def _err(msg: str, **extra) -> str:
    return json.dumps({"error": msg, **extra}, ensure_ascii=False)


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip() in ("1", "true", "yes")


# --------------------------------------------------------------------------
# URL admission: allow-list + SSRF guard. Everything goes through here.
# --------------------------------------------------------------------------

def _host_allowed(host: str, allowed: list[str]) -> bool:
    host = (host or "").lower()
    for d in allowed:
        if d.startswith("."):
            if host == d[1:] or host.endswith(d):     # ".gov.sa" ⇒ open.data.gov.sa
                return True
        elif host == d:
            return True
    return False


def _resolves_to_private(host: str) -> tuple[bool, str]:
    """True if ANY address the host resolves to is private/loopback/link-local/reserved.

    Checked per call, on the resolved addresses — not on the string — because
    `evil.example A 169.254.169.254` is a public-looking name pointing at the cloud
    metadata service, and that is the classic SSRF pivot.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return True, f"host does not resolve: {e}"
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return True, f"{host} resolves to a non-public address ({addr})"
    return False, ""


def _admit(url: str) -> tuple[bool, str]:
    """Gate a URL. Returns (ok, reason_if_refused)."""
    allowed = _allowed_domains()
    if not allowed:
        return False, ("browser-mcp is not configured: set BROWSER_ALLOWED_DOMAINS to a "
                       "comma-separated host allow-list. There is deliberately no "
                       "allow-everything value.")
    try:
        u = urlparse(url)
    except ValueError:
        return False, "malformed url"
    if u.scheme not in ("http", "https"):
        return False, (f"scheme '{u.scheme or 'none'}' is refused — only http and https. "
                       "file:// and data: can read local disk and are never permitted.")
    if not u.hostname:
        return False, "url has no host"
    if not _host_allowed(u.hostname, allowed):
        return False, f"host '{u.hostname}' is not in BROWSER_ALLOWED_DOMAINS"
    if not _flag("BROWSER_ALLOW_PRIVATE_IPS"):
        private, why = _resolves_to_private(u.hostname)
        if private:
            return False, (f"refused: {why}. Reaching internal addresses from the browser is "
                           "SSRF; set BROWSER_ALLOW_PRIVATE_IPS=1 only after review.")
    return True, ""


# --------------------------------------------------------------------------
# browser plumbing — a FRESH context per call, no state carried between users
# --------------------------------------------------------------------------

class _Page:
    """Async context manager: launch → fresh context → page → always tear down.

    The ASYNC Playwright API, deliberately: an MCP server runs inside an asyncio event loop,
    and Playwright's sync API refuses to run there ("It looks like you are using Playwright
    Sync API inside the asyncio loop"). A sync implementation passes a standalone script and
    then fails on every real call — which is exactly what happened here before this was
    caught in an end-to-end test through the gateway.
    """

    def __init__(self, url: str):
        self.url = url
        self._pw = self._browser = self._ctx = None
        self.page = None
        self.final_url = ""
        self.status = None

    async def __aenter__(self):
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=True, args=["--no-sandbox"])
        # A fresh, isolated context per call: no cookies, no storage, no logins survive, so
        # one operator's authenticated session can never leak into another's.
        self._ctx = await self._browser.new_context(accept_downloads=False,
                                                    java_script_enabled=True)
        self._ctx.set_default_timeout(TIMEOUT_MS)
        self.page = await self._ctx.new_page()
        self.page.on("download", lambda d: d.cancel())      # never write to disk
        resp = await self.page.goto(self.url, wait_until="domcontentloaded",
                                    timeout=TIMEOUT_MS)
        self.status = resp.status if resp else None
        self.final_url = self.page.url
        return self

    async def __aexit__(self, *exc):
        for closer in (self._ctx, self._browser):
            try:
                if closer:
                    await closer.close()
            except Exception:
                pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        return False


def _check_landing(p: "_Page") -> Optional[str]:
    """Re-check the URL we ACTUALLY landed on. An allow-listed host that redirects to an
    attacker-controlled domain must not be followed."""
    ok, why = _admit(p.final_url)
    if not ok:
        return _err(f"navigation ended on a URL that is not permitted: {why}",
                    requested=p.url, landed_on=p.final_url)
    return None


def _truncate(text: str) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= MAX_TEXT:
        return text, False
    return raw[:MAX_TEXT].decode("utf-8", "ignore"), True


async def _run(url: str, fn):
    """Admit the URL, open a page, re-check the landing URL, then await `fn(page_ctx)`."""
    ok, why = _admit(url)
    if not ok:
        return _err(why, url=url)
    try:
        async with _Page(url) as p:
            bad = _check_landing(p)
            if bad:
                return bad
            return await fn(p)
    except ImportError:
        return _err("playwright is not installed on the gateway host "
                    "(pip install playwright && playwright install chromium)")
    except Exception as e:
        name = type(e).__name__
        return _err(f"browser error: {name}: {str(e)[:200]}", url=url)


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

@mcp.tool()
def list_allowed_domains() -> str:
    """Show which hosts this gateway permits the browser to reach, and which risky
    capabilities are enabled. Call this first if a URL is being refused."""
    allowed = _allowed_domains()
    return json.dumps({
        "allowed_domains": allowed,
        "configured": bool(allowed),
        "private_ips_allowed": _flag("BROWSER_ALLOW_PRIVATE_IPS"),
        "javascript_evaluation_enabled": _flag("BROWSER_ALLOW_EVAL"),
        "interaction_enabled": _flag("BROWSER_ALLOW_INTERACTION"),
        "note": ("Only http/https to allow-listed hosts. Hosts resolving to private or "
                 "link-local addresses are refused (SSRF guard) unless explicitly enabled."),
    }, ensure_ascii=False)


@mcp.tool()
async def read_page(url: str) -> str:
    """Open a web page and return its visible text. Read-only: nothing is clicked, typed,
    or downloaded. The URL must be on the allow-list and must not resolve to an internal
    address."""
    async def go(p: _Page):
        title = await p.page.title()
        text = await p.page.inner_text("body")
        text, truncated = _truncate(text)
        return json.dumps({
            "url": p.final_url, "title": title, "status": p.status,
            "text": text, "truncated": truncated,
        }, ensure_ascii=False)
    return await _run(url, go)


@mcp.tool()
async def get_page_links(url: str, same_host_only: bool = True) -> str:
    """List the links on a page (absolute URLs + their anchor text). Useful for crawling an
    allow-listed site. `same_host_only` keeps the results on the page's own host."""
    async def go(p: _Page):
        raw = await p.page.eval_on_selector_all(
            "a[href]", "els => els.map(e => ({href: e.getAttribute('href'), text: e.innerText.trim()}))")
        host = urlparse(p.final_url).hostname
        out, seen = [], set()
        for item in raw:
            href = urljoin(p.final_url, item.get("href") or "")
            u = urlparse(href)
            if u.scheme not in ("http", "https"):
                continue
            if same_host_only and u.hostname != host:
                continue
            if href in seen:
                continue
            seen.add(href)
            out.append({"url": href, "text": (item.get("text") or "")[:120]})
            if len(out) >= MAX_LINKS:
                break
        return json.dumps({"url": p.final_url, "links": out, "count": len(out),
                           "truncated": len(out) >= MAX_LINKS}, ensure_ascii=False)
    return await _run(url, go)


@mcp.tool()
async def extract_tables(url: str) -> str:
    """Extract every HTML table on a page as structured rows — the reliable way to get
    figures out of a report page without asking a model to parse HTML."""
    async def go(p: _Page):
        tables = await p.page.eval_on_selector_all("table", """
            els => els.map(t => Array.from(t.rows).map(
                r => Array.from(r.cells).map(c => c.innerText.trim())))
        """)
        cleaned = [t for t in tables if t and any(any(c for c in row) for row in t)]
        payload = json.dumps({"url": p.final_url, "tables": cleaned,
                              "count": len(cleaned)}, ensure_ascii=False)
        if len(payload.encode()) > MAX_TEXT:
            return _err("tables exceed the size cap", url=p.final_url,
                        hint="fetch a narrower page")
        return payload
    return await _run(url, go)


@mcp.tool()
async def screenshot_page(url: str, full_page: bool = False) -> str:
    """Capture a PNG screenshot of a page, returned base64-encoded. Useful when the layout
    matters (a dashboard, a chart) and the text alone is not enough."""
    import base64

    async def go(p: _Page):
        png = await p.page.screenshot(full_page=full_page, type="png")
        if len(png) > MAX_SHOT:
            return _err(f"screenshot is {len(png)} bytes, over the {MAX_SHOT} cap",
                        url=p.final_url, hint="set full_page=false")
        return json.dumps({"url": p.final_url, "title": await p.page.title(),
                           "format": "png", "bytes": len(png),
                           "base64": base64.b64encode(png).decode()}, ensure_ascii=False)
    return await _run(url, go)


@mcp.tool()
async def search_page_text(url: str, query: str, context_chars: int = 160) -> str:
    """Open a page and return only the passages matching `query`, with surrounding context.
    Cheaper and far less injection-prone than pulling a whole page into the model."""
    if not query.strip():
        return _err("query is required")

    async def go(p: _Page):
        text = await p.page.inner_text("body")
        needle, hay = query.lower(), text.lower()
        hits, start = [], 0
        while len(hits) < 20:
            i = hay.find(needle, start)
            if i < 0:
                break
            a, b = max(0, i - context_chars), min(len(text), i + len(query) + context_chars)
            hits.append(text[a:b].replace("\n", " ").strip())
            start = i + len(needle)
        return json.dumps({"url": p.final_url, "query": query, "matches": hits,
                           "match_count": len(hits)}, ensure_ascii=False)
    return await _run(url, go)


@mcp.tool()
async def fill_and_submit(url: str, fields: dict, submit_selector: str = "") -> str:
    """Fill form fields and submit — a WRITE against a remote site.

    `fields` maps a CSS selector to the text to type. Disabled unless
    BROWSER_ALLOW_INTERACTION=1, and the gateway holds it for human approval regardless:
    submitting a form on someone else's site is an action taken in your name.
    """
    if not _flag("BROWSER_ALLOW_INTERACTION"):
        return _err("form interaction is disabled on this gateway "
                    "(set BROWSER_ALLOW_INTERACTION=1 to enable)")
    if not isinstance(fields, dict) or not fields:
        return _err("fields must be a non-empty object of {css_selector: text}")

    async def go(p: _Page):
        filled = []
        for selector, value in fields.items():
            await p.page.fill(selector, str(value))
            filled.append(selector)
        if submit_selector:
            await p.page.click(submit_selector)
        else:
            await p.page.keyboard.press("Enter")
        await p.page.wait_for_load_state("domcontentloaded", timeout=TIMEOUT_MS)
        bad = _check_landing(p)          # submission may navigate — re-check where we land
        if bad:
            return bad
        text, truncated = _truncate(await p.page.inner_text("body"))
        return json.dumps({"url": p.final_url, "filled": filled,
                           "title": await p.page.title(), "text": text,
                           "truncated": truncated}, ensure_ascii=False)
    return await _run(url, go)


@mcp.tool()
async def evaluate_javascript(url: str, expression: str) -> str:
    """Run a JavaScript expression in the page and return its result.

    This is arbitrary code execution in the page's origin — it can read anything that page
    can read and call anything it can call. Disabled unless BROWSER_ALLOW_EVAL=1, and the
    gateway tiers it for two-person approval. Prefer read_page / extract_tables.
    """
    if not _flag("BROWSER_ALLOW_EVAL"):
        return _err("javascript evaluation is disabled on this gateway "
                    "(set BROWSER_ALLOW_EVAL=1 to enable). Use read_page or extract_tables.")
    if not expression.strip():
        return _err("expression is required")

    async def go(p: _Page):
        result = await p.page.evaluate(expression)
        payload = json.dumps({"url": p.final_url, "expression": expression[:200],
                              "result": result}, ensure_ascii=False, default=str)
        if len(payload.encode()) > MAX_TEXT:
            return _err("result exceeds the size cap", url=p.final_url)
        return payload
    return await _run(url, go)


if __name__ == "__main__":
    mcp.run()   # stdio
