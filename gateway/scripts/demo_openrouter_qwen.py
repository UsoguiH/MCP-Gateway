"""Stakeholder demo: an EXTERNAL model (Qwen via OpenRouter) drives the gateway's
inbound MCP endpoint — proving any client-side LLM can use the org's tools while
every call is authenticated, tier-checked, masked and audited by the gateway.

    set OPENROUTER_API_KEY=sk-or-...
    python scripts/demo_openrouter_qwen.py --user sara "ابحث في المستندات عن سياسة الرواتب"
    python scripts/demo_openrouter_qwen.py --user sara --list-only     # just show the tool surface
    python scripts/demo_openrouter_qwen.py --user sara --login-only    # print headers for MCP Inspector

The script logs in with username+password (+TOTP when enforced), opens an MCP
session, hands the gateway's tool list to Qwen in OpenAI function-calling form,
and loops: model proposes a call -> gateway enforces policy -> result feeds back.
A tier-2 write pauses on the gateway's human-approval queue; the script polls the
approval resource so the audience can approve it live in the admin console.
"""
import argparse, getpass, json, os, sys, time
from pathlib import Path

import httpx


def _load_env():
    """Load KEY=value lines from gateway/.env (real env vars win)."""
    env = Path(__file__).resolve().parent.parent / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


_load_env()

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8800")
OPENROUTER = "https://openrouter.ai/api/v1/chat/completions"
MODEL = os.environ.get("QWEN_MODEL", "qwen/qwen3-235b-a22b-2507")
MAX_TURNS = 10

SYSTEM = ("You are an assistant for a government entity. You can ONLY act through the "
          "provided tools, which run behind a secure MCP gateway: every call is "
          "authorization-checked, PII-masked and audited under the signed-in user. "
          "If a tool answers 'pending approval', the call awaits a human approver — "
          "say so and continue when the result arrives. Answer in the user's language.")


def die(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


# ---------- gateway auth (username + password [+ TOTP]) ----------
def login(user: str) -> dict:
    pw = os.environ.get("GATEWAY_PASSWORD") or getpass.getpass(f"password for {user}: ")
    r = httpx.post(f"{GATEWAY}/api/auth/login", json={"username": user, "password": pw}, timeout=15)
    if r.status_code != 200:
        die(f"login failed: {r.status_code} {r.text[:200]}")
    body = r.json()
    if body.get("mfa_required"):
        otp = input("authenticator code (TOTP): ").strip()
        r = httpx.post(f"{GATEWAY}/api/auth/mfa",
                       json={"mfa_ticket": body["mfa_ticket"], "otp": otp}, timeout=15)
        if r.status_code != 200:
            die(f"MFA failed: {r.status_code} {r.text[:200]}")
        body = r.json()
    print(f"[gateway] signed in as {body['user']['sub']} ({body['user']['role']})")
    return {"Authorization": f"Bearer {body['token']}",
            "X-Client-Cert-Thumbprint": body["thumbprint"]}


# ---------- minimal MCP client over Streamable HTTP ----------
class Mcp:
    def __init__(self, headers: dict):
        self.h = {**headers, "Accept": "application/json, text/event-stream"}
        r = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                    "clientInfo": {"name": "openrouter-qwen-demo", "version": "1"}})
        self.sid = r.headers.get("Mcp-Session-Id")
        httpx.post(f"{GATEWAY}/mcp", headers=self._hdr(),
                   json={"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout=15)

    def _hdr(self):
        return {**self.h, **({"Mcp-Session-Id": self.sid} if getattr(self, "sid", None) else {})}

    def rpc(self, method: str, params=None, id_=1):
        body = {"jsonrpc": "2.0", "id": id_, "method": method}
        if params is not None:
            body["params"] = params
        r = httpx.post(f"{GATEWAY}/mcp", headers=self._hdr(), json=body, timeout=60)
        r.raise_for_status()
        return r

    def tools(self) -> list[dict]:
        return self.rpc("tools/list", {}, id_=2).json()["result"]["tools"]

    def call(self, name: str, arguments: dict) -> dict:
        return self.rpc("tools/call", {"name": name, "arguments": arguments}, id_=3).json()["result"]

    def approval_result(self, aid: str) -> dict:
        r = self.rpc("resources/read", {"uri": f"gateway://approval/{aid}"}, id_=4).json()
        txt = r["result"]["contents"][0].get("text", "{}")
        return json.loads(txt)


def result_text(res: dict) -> str:
    return "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")


def wait_for_approval(mcp: Mcp, aid: str, timeout_s: int = 120) -> str:
    print(f"    [gateway] tier-2 write PAUSED -> approval {aid} — approve it in the admin console…")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(3)
        a = mcp.approval_result(aid)
        status = a.get("status")
        if status == "approved":
            print("    [gateway] approved by a human — executing")
            return json.dumps(a.get("result") or a, ensure_ascii=False)[:4000]
        if status in ("denied", "expired"):
            return f"the human approver {status} this action"
    return "approval still pending after timeout — the action did not run"


# ---------- OpenRouter (OpenAI-compatible) ----------
def qwen(messages: list, tools: list, api_key: str) -> dict:
    r = httpx.post(OPENROUTER, timeout=120,
                   headers={"Authorization": f"Bearer {api_key}"},
                   json={"model": MODEL, "messages": messages, "tools": tools})
    if r.status_code != 200:
        die(f"OpenRouter error: {r.status_code} {r.text[:300]}")
    return r.json()["choices"][0]["message"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("prompt", nargs="?", default="What documents can you search? Give one example result.")
    ap.add_argument("--user", default="sara")
    ap.add_argument("--list-only", action="store_true", help="show the gateway tool surface and exit")
    ap.add_argument("--login-only", action="store_true", help="print auth headers (for MCP Inspector) and exit")
    args = ap.parse_args()

    headers = login(args.user)
    if args.login_only:
        print("\nPaste these headers into MCP Inspector (Streamable HTTP, "
              f"URL {GATEWAY}/mcp):")
        for k, v in headers.items():
            print(f"  {k}: {v}")
        return

    mcp = Mcp(headers)
    gw_tools = mcp.tools()
    print(f"[gateway] {len(gw_tools)} tools visible to '{args.user}' "
          f"(role-entitled servers only): "
          + ", ".join(sorted({t['name'].split('__')[0] for t in gw_tools})))
    if args.list_only:
        for t in gw_tools:
            tier = (t.get("_meta", {}).get("gateway", {}) or {}).get("tier")
            print(f"  [tier {tier}] {t['name']} — {t.get('description','')[:80]}")
        return

    api_key = os.environ.get("OPENROUTER_API_KEY") or die("set OPENROUTER_API_KEY")
    oa_tools = [{"type": "function",
                 "function": {"name": t["name"], "description": t.get("description", ""),
                              "parameters": t.get("inputSchema") or {"type": "object", "properties": {}}}}
                for t in gw_tools]

    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": args.prompt}]
    print(f"\n[qwen] model: {MODEL}\n[user] {args.prompt}\n")

    for _ in range(MAX_TURNS):
        msg = qwen(messages, oa_tools, api_key)
        calls = msg.get("tool_calls") or []
        if not calls:
            print(f"\n=== Qwen's answer ===\n{msg.get('content', '')}")
            return
        messages.append(msg)
        for tc in calls:
            name = tc["function"]["name"]
            try:
                tc_args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                tc_args = {}
            print(f"[qwen -> gateway] tools/call {name} {json.dumps(tc_args, ensure_ascii=False)[:120]}")
            res = mcp.call(name, tc_args)
            g = res.get("_meta", {}).get("gateway", {})
            print(f"    [gateway] status={g.get('status')} tier={g.get('tier')} "
                  f"masked={g.get('pii_masked')}")
            if g.get("status") == "pending_approval" and g.get("approval_id"):
                out = wait_for_approval(mcp, g["approval_id"])
            else:
                out = result_text(res)[:4000] or json.dumps(res.get("structuredContent", {}))[:4000]
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": out})
    print("[!] stopped after max turns")


if __name__ == "__main__":
    main()
