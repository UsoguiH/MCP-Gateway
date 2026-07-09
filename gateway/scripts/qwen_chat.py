"""Qwen Chat — plain Qwen assistant with FULL access to all MCP gateway servers.

TEST/DEV build: no login screen, no OAuth, no system prompt. On startup the app
signs itself into the gateway as `admin` (dev demo credentials; TOTP computed
locally from the gateway's own enrolled secret) and exposes every registered
server's tools to the model. The gateway still enforces its own controls
(tiers/HITL, masking, audit) on each call — this client just skips client-side
ceremony. Do NOT ship this build to real users.

    python scripts/qwen_chat.py            # then open http://127.0.0.1:8900
    (reads OPENROUTER_API_KEY / QWEN_MODEL from gateway/.env)
"""
import json, os, sys, threading, time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

GATEWAY_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GATEWAY_DIR))


def _load_env():
    env = GATEWAY_DIR / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


_load_env()

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8800")
OPENROUTER = "https://openrouter.ai/api/v1/chat/completions"
MODEL = os.environ.get("QWEN_MODEL", "qwen/qwen3-235b-a22b-2507")
PORT = int(os.environ.get("QWEN_CHAT_PORT", "8900"))
ADMIN_USER = os.environ.get("GATEWAY_ADMIN_USER", "admin")
# candidate dev passwords, first match wins (or set GATEWAY_ADMIN_PASSWORD in .env)
ADMIN_PWS = [p for p in [os.environ.get("GATEWAY_ADMIN_PASSWORD"),
                         "Gateway#Test2026!", "!Gateway#Test2026", "fn27pwKxev%hKm"] if p]
MAX_TURNS = 10

app = FastAPI()
S: dict = {"headers": None, "sid": None, "tools": [], "messages": []}
_lock = threading.Lock()


# ---------- automatic gateway sign-in (dev/test convenience) ----------
def _auto_login() -> dict:
    """Sign in as admin without user interaction. Tries the dev quick-login first;
    falls back to password + TOTP computed from the gateway's own enrolled secret
    (works because this test client runs on the same machine as the gateway)."""
    r = httpx.post(f"{GATEWAY}/api/dev/quicklogin", timeout=10)
    if r.status_code == 200:
        b = r.json()
        return {"Authorization": f"Bearer {b['token']}", "X-Client-Cert-Thumbprint": b["thumbprint"]}
    b = None
    for pw in ADMIN_PWS:
        r = httpx.post(f"{GATEWAY}/api/auth/login", timeout=15,
                       json={"username": ADMIN_USER, "password": pw})
        if r.status_code == 200:
            b = r.json()
            break
    if b is None:
        raise RuntimeError("admin login failed — set GATEWAY_ADMIN_PASSWORD in gateway/.env")
    if b.get("mfa_required"):
        from app import auth as gw_auth               # local import: same box as the gateway
        if gw_auth.totp_remaining() < 3:
            time.sleep(gw_auth.totp_remaining() + 1)
        r = httpx.post(f"{GATEWAY}/api/auth/mfa", timeout=15,
                       json={"mfa_ticket": b["mfa_ticket"], "otp": gw_auth.totp_code(ADMIN_USER)})
        r.raise_for_status()
        b = r.json()
    return {"Authorization": f"Bearer {b['token']}", "X-Client-Cert-Thumbprint": b["thumbprint"]}


def _mh():
    h = {**S["headers"], "Accept": "application/json, text/event-stream"}
    if S["sid"]:
        h["Mcp-Session-Id"] = S["sid"]
    return h


def _rpc(method: str, params=None, id_=1) -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    r = httpx.post(f"{GATEWAY}/mcp", headers=_mh(), json=body, timeout=60)
    r.raise_for_status()
    return r


def _connect():
    S["headers"] = _auto_login()
    S["sid"] = None
    r = _rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                            "clientInfo": {"name": "qwen-chat", "version": "2"}})
    S["sid"] = r.headers.get("Mcp-Session-Id")
    httpx.post(f"{GATEWAY}/mcp", headers=_mh(),
               json={"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout=15)
    S["tools"] = _rpc("tools/list", {}, id_=2).json()["result"]["tools"]
    servers = sorted({t["name"].split("__")[0] for t in S["tools"]})
    print(f"[qwen-chat] connected as {ADMIN_USER}: {len(S['tools'])} tools "
          f"from {len(servers)} servers: {', '.join(servers)}", flush=True)


def _ensure_connected():
    with _lock:
        if not S["headers"]:
            _connect()


def _tool_call(name: str, arguments: dict) -> dict:
    return _rpc("tools/call", {"name": name, "arguments": arguments}, id_=3).json()["result"]


def _approval_wait(aid: str, timeout_s: int = 180) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(3)
        r = _rpc("resources/read", {"uri": f"gateway://approval/{aid}"}, id_=4).json()
        a = json.loads(r["result"]["contents"][0].get("text", "{}"))
        if a.get("status") == "approved":
            return json.dumps(a.get("result") or a, ensure_ascii=False)[:4000]
        if a.get("status") in ("denied", "expired"):
            return f"the human approver {a['status']} this action"
    return "approval still pending — the action has not run"


# ---------- Qwen via OpenRouter (no system prompt — stock assistant) ----------
def _qwen(messages: list, tools: list) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY missing — put it in gateway/.env")
    r = httpx.post(OPENROUTER, timeout=180, headers={"Authorization": f"Bearer {key}"},
                   json={"model": MODEL, "messages": messages, "tools": tools})
    if r.status_code != 200:
        raise RuntimeError(f"OpenRouter {r.status_code}: {r.text[:300]}")
    return r.json()["choices"][0]["message"]


class ChatReq(BaseModel):
    message: str


@app.post("/api/chat")
def chat(req: ChatReq):
    try:
        _ensure_connected()
    except Exception as e:
        return JSONResponse({"error": f"gateway connection failed: {e}"}, status_code=502)
    with _lock:
        oa_tools = [{"type": "function",
                     "function": {"name": t["name"], "description": t.get("description", ""),
                                  "parameters": t.get("inputSchema") or {"type": "object", "properties": {}}}}
                    for t in S["tools"]]
        S["messages"].append({"role": "user", "content": req.message})
        trace = []
        try:
            for _ in range(MAX_TURNS):
                msg = _qwen(S["messages"], oa_tools)
                calls = msg.get("tool_calls") or []
                if not calls:
                    S["messages"].append({"role": "assistant", "content": msg.get("content", "")})
                    return {"reply": msg.get("content", ""), "trace": trace}
                S["messages"].append(msg)
                for tc in calls:
                    name = tc["function"]["name"]
                    try:
                        args = json.loads(tc["function"].get("arguments") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    res = _tool_call(name, args)
                    g = res.get("_meta", {}).get("gateway", {})
                    trace.append({"tool": name, "status": g.get("status"), "tier": g.get("tier"),
                                  "masked": bool(g.get("pii_masked"))})
                    if g.get("status") == "pending_approval" and g.get("approval_id"):
                        out = _approval_wait(g["approval_id"])
                    else:
                        out = "".join(c.get("text", "") for c in res.get("content", [])
                                      if c.get("type") == "text")[:4000]
                    S["messages"].append({"role": "tool", "tool_call_id": tc["id"], "content": out})
            return {"reply": "(stopped after max tool turns)", "trace": trace}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                S["headers"] = None            # token expired -> auto reconnect next turn
                return JSONResponse({"error": "session expired — send again"}, status_code=401)
            raise
        except RuntimeError as e:
            return JSONResponse({"error": str(e)}, status_code=502)


@app.post("/api/reset")
def reset():
    S["messages"] = []
    return {"ok": True}


@app.get("/api/status")
def status():
    try:
        _ensure_connected()
    except Exception as e:
        return {"connected": False, "error": str(e)[:200], "model": MODEL, "tools": 0, "servers": []}
    servers = sorted({t["name"].split("__")[0] for t in S["tools"]})
    return {"connected": True, "model": MODEL, "tools": len(S["tools"]), "servers": servers}


# ---------- UI: ChatGPT-style ----------
@app.get("/")
def index():
    return HTMLResponse("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Qwen</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--sb:#171717;--sb-hover:#2f2f2f;--txt:#0d0d0d;--muted:#8e8ea0;--line:#e3e3e3;
 --bubble:#f4f4f4}
body{height:100vh;display:flex;font-family:"Söhne","Segoe UI",system-ui,-apple-system,sans-serif;
 color:var(--txt);background:#fff;overflow:hidden}
/* sidebar */
aside{width:260px;background:var(--sb);color:#ececec;display:flex;flex-direction:column;
 padding:.75rem;gap:.5rem;flex-shrink:0}
aside .new{display:flex;align-items:center;gap:.6rem;padding:.65rem .75rem;border-radius:.75rem;
 cursor:pointer;font-size:.875rem;border:1px solid #ffffff26;background:none;color:#ececec;
 font-family:inherit;width:100%;text-align:left}
aside .new:hover{background:var(--sb-hover)}
aside .hist{flex:1;overflow-y:auto;margin-top:.5rem}
aside .item{padding:.6rem .75rem;border-radius:.75rem;font-size:.85rem;color:#ececec;
 white-space:nowrap;overflow:hidden;text-overflow:ellipsis;background:var(--sb-hover)}
aside .foot{font-size:.7rem;color:#9b9b9b;padding:.5rem .75rem;line-height:1.5}
/* main */
.main{flex:1;display:flex;flex-direction:column;min-width:0}
header{display:flex;align-items:center;padding:.75rem 1.25rem;font-size:1.05rem;font-weight:600;
 color:#5d5d5d}
header .caret{font-size:.7rem;color:var(--muted);margin-left:.35rem}
#scroll{flex:1;overflow-y:auto}
.thread{max-width:48rem;margin:0 auto;padding:1rem 1.5rem 2rem;display:flex;
 flex-direction:column;gap:1.5rem}
.row{display:flex;flex-direction:column;gap:.4rem}
.row .u{align-self:flex-end;max-width:70%;background:var(--bubble);border-radius:1.5rem;
 padding:.7rem 1.1rem;font-size:.95rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.row .a{align-self:stretch;display:flex;gap:.9rem}
.row .a .av{width:2rem;height:2rem;border-radius:50%;border:1px solid var(--line);flex-shrink:0;
 display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700}
.row .a .body{flex:1;font-size:.95rem;line-height:1.7;white-space:pre-wrap;word-break:break-word;
 padding-top:.3rem}
.tools{display:flex;flex-wrap:wrap;gap:.35rem;margin:0 0 .2rem 2.9rem}
.tools span{font-size:.72rem;color:var(--muted);border:1px solid var(--line);
 border-radius:999px;padding:.15rem .6rem}
.hello{margin:auto;text-align:center;padding:2rem;display:flex;flex-direction:column;gap:.75rem;
 align-items:center}
.hello h2{font-size:1.85rem;font-weight:600}
.hello p{color:var(--muted);font-size:.9rem}
/* composer */
.composer{padding:.75rem 1.5rem 1.5rem;display:flex;flex-direction:column;align-items:center;gap:.5rem}
.cbox{width:100%;max-width:48rem;display:flex;align-items:flex-end;gap:.5rem;
 border:1px solid var(--line);border-radius:1.75rem;padding:.55rem .55rem .55rem 1.25rem;
 box-shadow:0 2px 12px rgba(0,0,0,.06);background:#fff}
.cbox textarea{flex:1;border:0;outline:none;resize:none;font:inherit;font-size:.95rem;
 line-height:1.5;max-height:10rem;padding:.35rem 0;background:none}
.cbox .up{width:2.25rem;height:2.25rem;border-radius:50%;border:0;background:#0d0d0d;color:#fff;
 font-size:1rem;cursor:pointer;flex-shrink:0;display:flex;align-items:center;justify-content:center}
.cbox .up:disabled{background:#e3e3e3;color:#8e8ea0;cursor:default}
.fine{font-size:.72rem;color:var(--muted)}
.err{color:#ef4444;font-size:.85rem;margin-left:2.9rem}
</style></head><body>
<aside>
  <button class="new" onclick="resetChat()">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
    New chat</button>
  <div class="hist"><div class="item" id="histItem">New conversation</div></div>
  <div class="foot" id="foot">connecting…</div>
</aside>
<div class="main">
  <header>Qwen 3<span class="caret">▼</span></header>
  <div id="scroll"><div class="thread" id="thread">
    <div class="hello" id="hello"><h2>What can I help with?</h2>
      <p id="helloSub">Connected to the MCP gateway…</p></div>
  </div></div>
  <div class="composer">
    <div class="cbox">
      <textarea id="inp" rows="1" placeholder="Message Qwen"></textarea>
      <button class="up" id="send" disabled title="Send">↑</button>
    </div>
    <div class="fine">Qwen can make mistakes. Tool calls run through the MCP gateway.</div>
  </div>
</div>
<script>
const thread=document.getElementById('thread'),scroll=document.getElementById('scroll'),
      inp=document.getElementById('inp'),sendBtn=document.getElementById('send');
let busy=false;
inp.addEventListener('input',()=>{sendBtn.disabled=!inp.value.trim()||busy;
  inp.style.height='auto';inp.style.height=Math.min(inp.scrollHeight,160)+'px'});
function row(){const r=document.createElement('div');r.className='row';thread.appendChild(r);return r}
function userMsg(t){const r=row();const d=document.createElement('div');d.className='u';
  d.dir='auto';d.textContent=t;r.appendChild(d);scrollDown()}
function botMsg(t){const r=row();const a=document.createElement('div');a.className='a';
  a.innerHTML='<div class="av">Q</div>';const b=document.createElement('div');b.className='body';
  b.dir='auto';b.textContent=t;a.appendChild(b);r.appendChild(a);scrollDown();return b}
function toolChips(trace){if(!trace||!trace.length)return;
  const w=document.createElement('div');w.className='tools';
  for(const t of trace){const s=document.createElement('span');
    s.textContent=`${t.tool} · ${t.status}${t.masked?' · masked':''}`;w.appendChild(s)}
  thread.appendChild(w);scrollDown()}
function errMsg(t){const d=document.createElement('div');d.className='err';d.textContent='⚠ '+t;
  thread.appendChild(d);scrollDown()}
function scrollDown(){scroll.scrollTop=scroll.scrollHeight}
async function refresh(){try{
  const s=await (await fetch('/api/status')).json();
  if(s.connected){
    document.getElementById('foot').textContent=
      `${s.model} · ${s.tools} tools · ${s.servers.length} servers (${s.servers.join(', ')})`;
    document.getElementById('helloSub').textContent=
      `Full access: ${s.tools} tools from ${s.servers.join(', ')}`;
    sendBtn.disabled=!inp.value.trim()}
  else{document.getElementById('foot').textContent='gateway unreachable';
    document.getElementById('helloSub').textContent=s.error||'gateway connection failed'}}
  catch(e){document.getElementById('foot').textContent='backend unreachable'}}
async function send(){const text=inp.value.trim();if(!text||busy)return;
  busy=true;sendBtn.disabled=true;
  document.getElementById('hello')&&document.getElementById('hello').remove();
  document.getElementById('histItem').textContent=text.slice(0,40);
  inp.value='';inp.style.height='auto';userMsg(text);
  const b=botMsg('…');
  try{const r=await fetch('/api/chat',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text})});
    const d=await r.json();b.parentElement.parentElement.remove();
    if(d.error){errMsg(d.error)}else{toolChips(d.trace);botMsg(d.reply)}}
  catch(e){b.parentElement.parentElement.remove();errMsg(String(e))}
  busy=false;sendBtn.disabled=!inp.value.trim();inp.focus()}
sendBtn.addEventListener('click',send);
inp.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});
async function resetChat(){await fetch('/api/reset',{method:'POST'});location.reload()}
refresh();inp.focus();
</script></body></html>""")


if __name__ == "__main__":
    print(f"Qwen Chat (full-access test build) -> http://127.0.0.1:{PORT}   "
          f"(gateway: {GATEWAY}, model: {MODEL})")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
