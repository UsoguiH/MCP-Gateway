"use strict";
const state = { token: null, thumbprint: null, user: null, mcpSession: null };

const $ = (s) => document.querySelector(s);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  // Certificate-bound token (RFC 8705): every call presents the cert thumbprint.
  // In production the mTLS-terminating sidecar sets this from the verified peer cert.
  if (state.thumbprint) headers["X-Client-Cert-Thumbprint"] = state.thumbprint;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
  return data;
}

/* ---------- inbound MCP client (Streamable HTTP) ----------
   The gateway runs no model. This console connects to the /mcp endpoint exactly
   as a colleague's own local-LLM MCP client would, and drives one tool call at a
   time through the full control pipeline. */
function mcpHeaders() {
  const h = { "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
              "Authorization": "Bearer " + state.token, "X-Client-Cert-Thumbprint": state.thumbprint };
  if (state.mcpSession) h["Mcp-Session-Id"] = state.mcpSession;
  return h;
}
async function mcpInitialize() {
  const r = await fetch("/mcp", { method: "POST", headers: mcpHeaders(),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "gateway-ui", version: "1" } } }) });
  if (!r.ok) throw new Error("MCP initialize failed (HTTP " + r.status + ")");
  state.mcpSession = r.headers.get("Mcp-Session-Id");
  await fetch("/mcp", { method: "POST", headers: mcpHeaders(),         // initialized notification
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
}
async function mcpCall(name, args) {
  const r = await fetch("/mcp", { method: "POST", headers: mcpHeaders(),
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } }) });
  const data = await r.json().catch(() => ({}));
  if (data.error) throw new Error(data.error.message || ("MCP error " + r.status));
  if (!r.ok) throw new Error("HTTP " + r.status);
  return data.result;
}

/* ---------- login (TPM-bound certificate) ----------
   A browser cannot reach the workstation TPM directly, so the demo uses the
   dev-login helper, which runs the real challenge/response server-side with the
   user's dev key. Production: mTLS + TPM signing via the OS crypto provider. */
$("#login-btn").onclick = async () => {
  $("#login-error").textContent = "";
  try {
    const res = await api("/api/dev/login", {
      method: "POST",
      body: JSON.stringify({ username: $("#login-user").value.trim(), pin: $("#login-pin").value.trim() }),
    });
    state.token = res.token; state.thumbprint = res.thumbprint; state.user = res.user;
    enterApp();
  } catch (e) { $("#login-error").textContent = e.message; }
};
$("#login-user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#login-pin").focus(); });
$("#login-pin").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#login-btn").click(); });

/* Arabic-first RTL toggle (W9.5): flips document direction + language */
$("#lang-toggle").onclick = () => {
  const rtl = document.documentElement.dir !== "rtl";
  document.documentElement.dir = rtl ? "rtl" : "ltr";
  document.documentElement.lang = rtl ? "ar" : "en";
};

$("#logout-btn").onclick = () => {
  state.token = null; state.thumbprint = null; state.user = null; state.mcpSession = null;
  $("#main-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
};

function enterApp() {
  $("#login-view").classList.add("hidden");
  $("#main-view").classList.remove("hidden");
  $("#user-name").textContent = state.user.name;
  $("#user-clear").textContent = state.user.clearance.replace("_", " ");
  const isAdmin = state.user.role === "admin";
  const canApprove = ["approver", "admin"].includes(state.user.role);
  $("#tab-admin").classList.toggle("hidden", !isAdmin);
  $("#tab-approvals").classList.toggle("hidden", !canApprove);
  state.mcpSession = null;                    // fresh MCP session on each login
  showTab("chat");
  $("#chat-log").innerHTML = "";
  addMsg("system", `Signed in as ${state.user.name}. Role: ${state.user.role}, clearance: ${state.user.clearance.replace("_"," ")}. This console calls tools straight through the MCP endpoint — the gateway runs no model.`);
  if (canApprove) pollApprovals();
}

/* ---------- tabs ---------- */
document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => showTab(t.dataset.tab);
});
function showTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tabpanel").forEach((p) => p.classList.add("hidden"));
  $("#panel-" + name).classList.remove("hidden");
  if (name === "tools") loadTools();
  if (name === "approvals") loadApprovals();
  if (name === "admin") loadAdmin();
}

/* ---------- console: drive one tool call through the MCP endpoint ---------- */
$("#chat-send").onclick = sendConsole;
$("#chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter") sendConsole(); });

async function sendConsole() {
  const raw = $("#chat-input").value.trim();
  if (!raw) return;
  $("#chat-input").value = "";
  addMsg("user", raw);
  // Accept "server.tool {json}" (the leading #call is optional, kept for muscle memory).
  const m = raw.replace(/^#call\s+/i, "").match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*([\s\S]*)$/);
  if (!m) { addMsg("system", 'Format: server.tool {"arg":"value"} — e.g. docs.search_documents {"query":"security"}'); return; }
  const server = m[1], tool = m[2], argstr = m[3].trim();
  let args = {};
  if (argstr) { try { args = JSON.parse(argstr); } catch (e) { addMsg("system", "Invalid JSON arguments: " + e.message); return; } }
  try {
    if (!state.mcpSession) await mcpInitialize();
    const result = await mcpCall(server + "__" + tool, args);
    renderMcpResult(server, tool, result);
  } catch (e) { addMsg("system", "Error: " + e.message); }
  if (["approver", "admin"].includes(state.user.role)) pollApprovals();
}

// Map an MCP tools/call result (+ gateway _meta) into the step card renderer.
function renderMcpResult(server, tool, result) {
  const g = (result && result._meta && result._meta.gateway) || {};
  const step = {
    server, tool,
    status: g.status || (result.isError ? "error" : "executed"),
    tier: g.tier, pii_masked: g.pii_masked, pii_detected: g.pii_detected,
    taint: g.taint, approvals_required: g.approvals_required,
    approval_id: g.approval_id, reason: g.reason,
    result: (result.structuredContent != null) ? result.structuredContent
            : (result.content || []).map((c) => c.text || "").join(""),
  };
  addMsg("bot", server + "." + tool + ":").appendChild(renderStep(step));
}

function addMsg(kind, text) {
  const m = el("div", "msg " + kind, text);
  $("#chat-log").appendChild(m);
  $("#chat-log").scrollTop = $("#chat-log").scrollHeight;
  return m;
}

function tierBadge(t) {
  const b = el("span", "tierbadge t" + t, "Tier " + t);
  return b;
}

function renderStep(s) {
  const wrap = el("div", "step");
  const head = el("div", "step-head");
  head.appendChild(el("strong", null, s.server + "." + s.tool));
  if (s.tier != null) head.appendChild(tierBadge(s.tier));
  head.appendChild(el("span", "status " + s.status, s.status.replace("_", " ")));
  if (s.pii_masked) head.appendChild(el("span", "pii", "PII masked"));
  if (s.pii_detected && s.pii_detected.length && !s.pii_masked)
    head.appendChild(el("span", "pii", "PII: " + s.pii_detected.join(",")));
  if (s.taint && s.taint.length) head.appendChild(el("span", "taint", "TAINTED"));
  wrap.appendChild(head);

  const body = el("div", "step-body");
  if (s.status === "executed") body.textContent = typeof s.result === "string" ? s.result : JSON.stringify(s.result, null, 2);
  else if (s.status === "pending_approval") {
    body.textContent = "Held for human approval — id " + (s.approval_id || "?") + ", tier " + s.tier +
      ", needs " + s.approvals_required + " approver(s). Open the Approvals tab to release it.";
  } else body.textContent = s.reason || "";
  wrap.appendChild(body);
  return wrap;
}

/* ---------- tools ---------- */
async function loadTools() {
  const res = await api("/api/tools");
  const list = $("#tools-list"); list.innerHTML = "";
  res.tools.forEach((t) => {
    const c = el("div", "card");
    const h = el("h3"); h.appendChild(el("span", null, t.name)); h.appendChild(tierBadge(t.tier));
    c.appendChild(h);
    c.appendChild(el("div", "desc", t.description));
    c.appendChild(el("div", "muted", "server: " + t.server));
    list.appendChild(c);
  });
  if (!res.tools.length) list.appendChild(el("p", "muted", "No tools visible at your clearance."));
}

/* ---------- approvals ---------- */
async function loadApprovals() {
  let res;
  try { res = await api("/api/approvals"); } catch (e) { return; }
  const list = $("#approvals-list"); list.innerHTML = "";
  if (!res.pending.length) { list.appendChild(el("p", "muted", "No pending approvals.")); return; }
  res.pending.forEach((a) => list.appendChild(renderApproval(a)));
}

function renderApproval(a) {
  const c = el("div", "card");
  const h = el("h3");
  h.appendChild(el("span", null, a.server + "." + a.tool));
  h.appendChild(tierBadge(a.tier));
  c.appendChild(h);
  c.appendChild(el("div", "muted", "Requested by " + a.requester + " · needs " + a.approvals_required +
    " approval(s) · have " + a.approvals.length));
  if (a.taint && a.taint.length) {
    c.appendChild(el("div", "taint-warn", "⚠ Tainted arguments from untrusted content: " +
      a.taint.map((t) => t.arg + " ← " + t.source).join(", ")));
  }
  c.appendChild(el("div", "preview", a.preview));
  const actions = el("div", "actions");
  const ok = el("button", null, "Approve"); ok.onclick = () => voteApproval(a.id, "approve");
  const no = el("button", "danger", "Reject"); no.onclick = () => voteApproval(a.id, "reject");
  const mine = a.requester === state.user.name || a.requester === userSub();
  if (mine) { ok.disabled = true; ok.title = "Cannot approve your own request"; ok.style.opacity = .4; }
  actions.appendChild(ok); actions.appendChild(no);
  c.appendChild(actions);
  return c;
}

function userSub() { return state.user ? (state.user.sub || "") : ""; }

async function voteApproval(id, action) {
  try {
    const res = await api("/api/approvals/" + id + "/" + action, { method: "POST" });
    if (res.status === "approved_and_executed") {
      addMsg("system", "Approval " + id + " executed. Result recorded.");
    }
    loadApprovals(); pollApprovals();
  } catch (e) { alert(e.message); }
}

async function pollApprovals() {
  try {
    const res = await api("/api/approvals");
    const badge = $("#appr-badge");
    if (res.pending.length) { badge.textContent = res.pending.length; badge.classList.remove("hidden"); }
    else badge.classList.add("hidden");
  } catch (e) {}
}

/* ---------- admin ---------- */
async function loadAdmin() {
  await refreshKill();
  await loadRegistry();
  await loadAudit();
}
$("#kill-engage").onclick = async () => {
  const scope = $("#kill-scope").value.trim(); if (!scope) return;
  await api("/api/admin/killswitch/engage", { method: "POST", body: JSON.stringify({ scope }) });
  refreshKill();
};
$("#kill-release").onclick = async () => {
  const scope = $("#kill-scope").value.trim(); if (!scope) return;
  await api("/api/admin/killswitch/release", { method: "POST", body: JSON.stringify({ scope }) });
  refreshKill();
};
async function refreshKill() {
  const res = await api("/api/admin/killswitch");
  $("#kill-active").textContent = res.active.length ? "Active kills: " + res.active.join(", ") : "No active kills.";
}
async function loadRegistry() {
  const res = await api("/api/admin/registry");
  const list = $("#registry-list"); list.innerHTML = "";
  res.entries.forEach((e) => {
    const c = el("div", "card");
    const h = el("h3"); h.appendChild(el("span", null, e.server + "." + e.tool)); h.appendChild(tierBadge(e.tier));
    c.appendChild(h);
    c.appendChild(el("div", "muted", "status: " + e.status + (e.quarantine_reason ? " (" + e.quarantine_reason + ")" : "")));
    if (e.status === "quarantined") {
      const b = el("button", null, "Approve drift & re-pin");
      b.onclick = async () => { await api(`/api/admin/registry/${e.server}/${e.tool}/approve_drift`, { method: "POST" }); loadRegistry(); };
      c.appendChild(b);
    }
    list.appendChild(c);
  });
}
$("#audit-refresh").onclick = loadAudit;
async function loadAudit() {
  const res = await api("/api/admin/audit");
  const cs = $("#chain-status");
  cs.textContent = res.chain_status;
  cs.className = "chain " + (res.chain_ok ? "ok" : "bad");
  const log = $("#audit-log"); log.innerHTML = "";
  res.records.slice().reverse().forEach((r) => {
    const row = el("div", "a-row");
    const t = new Date(r.ts * 1000).toLocaleTimeString();
    row.appendChild(el("span", "a-ev", "[" + r.event + "] "));
    const detail = Object.entries(r).filter(([k]) => !["ts","event","prev","hash"].includes(k))
      .map(([k, v]) => k + "=" + JSON.stringify(v)).join(" ");
    row.appendChild(document.createTextNode(t + "  " + detail));
    log.appendChild(row);
  });
}
