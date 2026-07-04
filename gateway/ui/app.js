"use strict";
const state = { token: null, thumbprint: null, user: null };

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
  state.token = null; state.thumbprint = null; state.user = null;
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
  showTab("chat");
  $("#chat-log").innerHTML = "";
  addMsg("system", `Signed in as ${state.user.name}. Role: ${state.user.role}, clearance: ${state.user.clearance.replace("_"," ")}.`);
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

/* ---------- chat ---------- */
$("#chat-send").onclick = sendChat;
$("#chat-input").addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });

async function sendChat() {
  const msg = $("#chat-input").value.trim();
  if (!msg) return;
  $("#chat-input").value = "";
  addMsg("user", msg);
  try {
    const res = await api("/api/chat", { method: "POST", body: JSON.stringify({ message: msg }) });
    if (res.assistant_text) addMsg("bot", res.assistant_text);
    if (res.message_unicode_flags && res.message_unicode_flags.length)
      addMsg("system", "⚠ Your message was Unicode-sanitized: " + res.message_unicode_flags.join(", "));
    const botWrap = res.steps.length ? addMsg("bot", res.steps.length + " tool step(s):") : null;
    res.steps.forEach((s) => botWrap.appendChild(renderStep(s)));
  } catch (e) { addMsg("system", "Error: " + e.message); }
  if (["approver", "admin"].includes(state.user.role)) pollApprovals();
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
    body.textContent = "Awaiting human approval (tier " + s.tier + ", needs " + s.approvals_required + ").\n\n" + s.preview;
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
