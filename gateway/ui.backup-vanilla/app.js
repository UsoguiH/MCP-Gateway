"use strict";
/* Secure MCP Gateway — control-plane UI. The gateway runs no model; the Console
   drives tools through the inbound /mcp endpoint exactly as a client LLM would. */
const state = { token:null, thumbprint:null, user:null, mcpSession:null };
let CURRENT = "overview", APPR_COUNT = 0;

const $ = (s)=>document.querySelector(s);
const esc = (s)=>String(s==null?"":s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const jsq = (s)=>String(s).replace(/['\\]/g,"\\$&");     // safe inside inline on* handlers

/* ---------------- inline icons ---------------- */
const I = {
  shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/></svg>',
  grid:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  term:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></svg>',
  check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z"/></svg>',
  tools:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0 5 5l-8.4 8.4a2.1 2.1 0 0 1-3-3z"/><path d="m9 9-6 6"/></svg>',
  reg:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
  users:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13A4 4 0 0 1 16 11"/></svg>',
  power:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>',
  key:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.3-8.3M17 6l2 2M15 8l1.5 1.5"/></svg>',
  audit:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4v16a1 1 0 0 0 1 1h15M8 16l3-3 3 2 4-5"/></svg>',
  server:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
  lease:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  pending:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
  bolt:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h7l-1 8 10-12h-7z"/></svg>',
  activity:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
  link:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>',
  badge:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M15 9h3M15 13h3M6 16h12"/></svg>',
  userx:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M17 11h5"/></svg>',
  cert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="9" r="6"/><path d="M9 14l-2 7 5-3 5 3-2-7"/></svg>',
  scroll:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M9 13h6M9 17h4"/></svg>',
  layers:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 9 4.5-9 4.5L3 6.5z"/><path d="m3 12 9 4.5 9-4.5M3 17l9 4.5 9-4.5"/></svg>',
  gauge:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 3a9 9 0 1 0 8 8"/><path d="M12 12 16 8"/><path d="M20.5 4.5 21 3"/></svg>',
  eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
  chart:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><rect x="7" y="10" width="3" height="7"/><rect x="12" y="6" width="3" height="11"/><rect x="17" y="13" width="3" height="4"/></svg>',
  sliders:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M2 14h4M10 8h4M18 16h4"/></svg>',
  info:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>',
};

/* ---------------- HTTP + MCP ---------------- */
async function api(path, opts={}){
  const headers = Object.assign({"Content-Type":"application/json"}, opts.headers||{});
  if(state.token) headers["Authorization"] = "Bearer "+state.token;
  if(state.thumbprint) headers["X-Client-Cert-Thumbprint"] = state.thumbprint;
  const r = await fetch(path, Object.assign({}, opts, {headers}));
  const data = await r.json().catch(()=>({}));
  if(!r.ok){ const e=new Error(data.detail||("HTTP "+r.status)); e.status=r.status;
    if(r.status===401 && state.token && !path.startsWith("/api/login") && !path.startsWith("/api/auth/login")) handleExpiry();
    throw e; }
  return data;
}
const tryApi = (p)=>api(p).catch(()=>null);          // for role-gated fetches (swallow 403)

function mcpHeaders(){
  const h={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
    "Authorization":"Bearer "+state.token,"X-Client-Cert-Thumbprint":state.thumbprint};
  if(state.mcpSession) h["Mcp-Session-Id"]=state.mcpSession;
  return h;
}
async function mcpInitialize(){
  const r=await fetch("/mcp",{method:"POST",headers:mcpHeaders(),body:JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",
    params:{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"gateway-ui",version:"1"}}})});
  if(!r.ok) throw new Error("MCP initialize failed (HTTP "+r.status+")");
  state.mcpSession=r.headers.get("Mcp-Session-Id");
  await fetch("/mcp",{method:"POST",headers:mcpHeaders(),body:JSON.stringify({jsonrpc:"2.0",method:"notifications/initialized"})});
}
async function mcpCall(name,args){
  const r=await fetch("/mcp",{method:"POST",headers:mcpHeaders(),body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",params:{name,arguments:args}})});
  const data=await r.json().catch(()=>({}));
  if(data.error) throw new Error(data.error.message||("MCP error "+r.status));
  if(!r.ok) throw new Error("HTTP "+r.status);
  return data.result;
}

/* ---------------- login / session (production: username + password [+ MFA]) ---------------- */
let AUTHINFO={password_login:true, mfa_required:false, dev_login:false, assurance:"aal2"};
const ICON_EYE='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
const ICON_EYEOFF='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9.1 9.1 0 0 1 12 4c6.5 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68M6.6 6.6A13.5 13.5 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/><path d="M1 1l22 22"/></svg>';
async function loadAuthInfo(){
  try{ AUTHINFO=await api("/api/auth/info"); }catch(e){}
}
function replayAuthAnim(){
  document.querySelectorAll("#login-view .animate-element, #login-view .animate-testimonial").forEach(el=>{
    el.style.animation="none"; void el.offsetWidth; el.style.animation="";
  });
}
function showLogin(){
  $("#step-credentials").classList.remove("hidden"); $("#step-mfa").classList.add("hidden");
  $("#ac-title").textContent="مرحباً"; $("#ac-sub").textContent="أدخل بيانات الدخول للوصول إلى لوحة التحكم.";
  $("#login-error").textContent=""; replayAuthAnim();
}
function togglePw(){
  const i=$("#login-pass"); const reveal=i.type==="password"; i.type=reveal?"text":"password";
  const lbl=reveal?"إخفاء كلمة المرور":"إظهار كلمة المرور";
  const b=$("#pw-toggle"); b.setAttribute("aria-label",lbl); b.setAttribute("title",lbl); b.innerHTML=reveal?ICON_EYEOFF:ICON_EYE;
}
function loginErrAr(e){
  const m=(e&&e.message)||"";
  if(/lock|too many/i.test(m)) return "تم قفل الحساب مؤقتاً بعد عدة محاولات. يُرجى المحاولة بعد قليل.";
  if(/authenticator|otp|mfa|code/i.test(m)) return "رمز المصادقة غير صحيح.";
  if(/incorrect|invalid|password|credential/i.test(m)) return "اسم المستخدم أو كلمة المرور غير صحيحة.";
  return "تعذّر تسجيل الدخول. حاول مرة أخرى.";
}
let _loginUser="";
async function doSignin(){
  const err=$("#login-error"); err.textContent="";
  const u=$("#login-user").value.trim(), p=$("#login-pass").value;
  if(!u){ err.textContent="أدخل اسم المستخدم."; $("#login-user").focus(); return; }
  if(!p){ err.textContent="أدخل كلمة المرور."; $("#login-pass").focus(); return; }
  _loginUser=u;
  if(AUTHINFO.mfa_required){
    $("#step-credentials").classList.add("hidden"); $("#step-mfa").classList.remove("hidden");
    $("#mfa-user").textContent=u;
    $("#ac-title").textContent="تحقّق من هويتك"; $("#ac-sub").textContent="أدخل الرمز المكوّن من 6 أرقام من تطبيق المصادقة.";
    replayAuthAnim(); setTimeout(()=>$("#login-otp").focus(),40);
    return;
  }
  await submitLogin("");
}
function mfaBack(){
  $("#step-mfa").classList.add("hidden"); $("#step-credentials").classList.remove("hidden");
  $("#ac-title").textContent="مرحباً"; $("#ac-sub").textContent="أدخل بيانات الدخول للوصول إلى لوحة التحكم.";
  $("#login-error").textContent=""; $("#login-otp").value=""; replayAuthAnim(); setTimeout(()=>$("#login-pass").focus(),40);
}
async function doMfa(){
  const err=$("#login-error"); err.textContent="";
  if($("#login-otp").value.trim().length<6){ err.textContent="أدخل الرمز المكوّن من 6 أرقام."; return; }
  await submitLogin($("#login-otp").value.trim());
}
async function submitLogin(otp){
  const err=$("#login-error"); const onMfa=!$("#step-mfa").classList.contains("hidden");
  const btn=onMfa?$("#mfa-btn"):$("#signin-btn"); const label=btn.textContent;
  btn.disabled=true; btn.textContent="جارٍ تسجيل الدخول…";
  try{
    const res=await api("/api/auth/login",{method:"POST",
      body:JSON.stringify({username:_loginUser,password:$("#login-pass").value,otp})});
    state.token=res.token; state.thumbprint=res.thumbprint; state.user=res.user;
    await enterApp();
  }catch(e){ err.textContent=loginErrAr(e); btn.disabled=false; btn.textContent=label; }
}

async function enterApp(){
  const u=state.user;
  $("#login-view").classList.add("hidden"); $("#app-view").classList.remove("hidden");
  $("#u-name").textContent=u.name; $("#u-role").textContent=u.role;
  $("#u-clear").textContent=u.clearance.replace(/_/g," "); $("#u-clear").className="clear-tag "+u.clearance;
  $("#u-avatar").textContent=(u.name||"?").trim().charAt(0).toUpperCase();
  state.mcpSession=null; resetIdle();
  if(canApprove()) await refreshApprCount();
  go("overview"); updateChainChip();
}
function logout(){
  state.token=state.thumbprint=state.user=state.mcpSession=null;
  stopLive(); stopIdle();
  $("#app-view").classList.add("hidden"); $("#login-view").classList.remove("hidden");
  showLogin(); $("#login-user").value=""; $("#login-pass").value=""; $("#login-otp").value=""; $("#login-error").textContent="";
}
const isAdmin = ()=>state.user && state.user.role==="admin";
const canApprove = ()=>state.user && ["approver","admin"].includes(state.user.role);

/* idle auto-logout + session-expiry handling */
let _idleTimer=null; const IDLE_MS=15*60*1000;
function resetIdle(){ if(!state.token) return; clearTimeout(_idleTimer); _idleTimer=setTimeout(()=>{ toast("Signed out after 15 minutes of inactivity."); logout(); }, IDLE_MS); }
function stopIdle(){ clearTimeout(_idleTimer); }
function handleExpiry(){ if(state.token){ toast("Session expired — please sign in again."); logout(); } }

async function refreshApprCount(){
  if(!canApprove()){ APPR_COUNT=0; return; }
  const r=await tryApi("/api/approvals"); APPR_COUNT=r?r.pending.length:0; buildSidebar();
}
async function updateChainChip(){
  const h=await tryApi("/api/health"); if(!h) return;
  const ok=h.audit_chain_ok;
  $("#chain-chip").innerHTML=`<span class="dot ${ok?"ok":"crit"}"></span> Audit chain ${ok?"verified":"BROKEN"}`;
}

/* ---------------- navigation ---------------- */
const NAV=[
  {id:"operations",t:"Operations",ic:"grid",items:[
    {id:"overview",ic:"grid",t:"Overview"},
    {id:"monitor",ic:"activity",t:"Live monitor",admin:true},
    {id:"console",ic:"term",t:"Console"},
    {id:"approvals",ic:"check",t:"Approvals",approver:true,count:true},
    {id:"sessions",ic:"link",t:"Sessions",admin:true},
  ]},
  {id:"identity",t:"Identity",ic:"users",items:[
    {id:"operators",ic:"users",t:"Operators",admin:true},
    {id:"roles",ic:"badge",t:"Roles",admin:true},
    {id:"identities",ic:"userx",t:"Revocations",admin:true},
    {id:"certificates",ic:"cert",t:"Certificates",admin:true},
  ]},
  {id:"governance",t:"Governance",ic:"layers",items:[
    {id:"servers",ic:"server",t:"Servers",admin:true},
    {id:"tools",ic:"tools",t:"Tools"},
    {id:"registry",ic:"reg",t:"Registry",admin:true},
    {id:"policies",ic:"scroll",t:"Policies",admin:true},
    {id:"classification",ic:"layers",t:"Classification",admin:true},
  ]},
  {id:"security",t:"Security",ic:"shield",items:[
    {id:"killswitch",ic:"power",t:"Kill switch",admin:true},
    {id:"credentials",ic:"key",t:"Credentials",admin:true},
    {id:"ratelimits",ic:"gauge",t:"Rate limits",admin:true},
    {id:"dlp",ic:"eye",t:"DLP",admin:true},
  ]},
  {id:"system",t:"System",ic:"sliders",items:[
    {id:"audit",ic:"audit",t:"Audit log",admin:true},
    {id:"metrics",ic:"chart",t:"Metrics",admin:true},
    {id:"diagnostics",ic:"activity",t:"Diagnostics",admin:true},
    {id:"configuration",ic:"sliders",t:"Configuration",admin:true},
    {id:"about",ic:"info",t:"About"},
  ]},
];
const allowed = (it)=> !(it.admin&&!isAdmin()) && !(it.approver&&!canApprove());
function meta(id){ for(const g of NAV) for(const it of g.items) if(it.id===id) return it; }
const COLLAPSED=new Set(["identity","governance","security","system"]);   // sections collapsed by default; the active section auto-expands so the nav fits without scrolling
function snavItem(it){
  const c=it.count?APPR_COUNT:0;
  return `<button class="snav ${it.id===CURRENT?"active":""}" onclick="go('${it.id}')">${I[it.ic]}<span>${it.t}</span>${c?`<span class="snav-count">${c}</span>`:""}</button>`;
}
const _chev='<svg class="sec-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';
function buildSidebar(){
  const [ops,...secs]=NAV;
  let html=ops.items.filter(allowed).map(snavItem).join("");
  html+=secs.filter(g=>g.items.some(allowed)).map(g=>{
    const col=COLLAPSED.has(g.id) && !g.items.some(it=>it.id===CURRENT);
    return `<div class="snav-sec"><button class="snav-sec-h ${col?"collapsed":""}" onclick="toggleSec('${g.id}')"><span class="sec-lab">${g.t}</span>${_chev}</button>`
      +`<div class="snav-sec-items"${col?' style="display:none"':""}>${g.items.filter(allowed).map(snavItem).join("")}</div></div>`;
  }).join("");
  $("#side-nav").innerHTML=html;
}
function toggleSec(id){ COLLAPSED.has(id)?COLLAPSED.delete(id):COLLAPSED.add(id); buildSidebar(); }
function go(id){
  stopLive();
  CURRENT=id; const m=meta(id);
  if(m) $("#pg-title").textContent=m.t;
  $("#app-view").classList.remove("side-open");
  buildSidebar(); renderView(id);
}
async function renderView(id){
  const view=$("#view"); view.innerHTML=`<div class="panel"><div class="empty">Loading…</div></div>`;
  try{ await VIEWS[id](view); }
  catch(e){ view.innerHTML=`<div class="panel"><div class="empty">${e.status===403?"You do not have access to this section.":"Could not load — "+esc(e.message)}</div></div>`; }
}

/* ---- live monitor (auto-refresh, stops when you navigate away) ---- */
let _liveTimer=null;
function stopLive(){ if(_liveTimer){ clearInterval(_liveTimer); _liveTimer=null; } }
function startLive(){ stopLive(); _liveTimer=setInterval(updateLive,4000); }
async function updateLive(){
  if(CURRENT!=="monitor"){ stopLive(); return; }
  const a=await tryApi("/api/admin/audit"); if(!a) return;
  const recs=a.records.slice().reverse();
  const c={ok:0,info:0,warn:0,crit:0}; recs.forEach(r=>{ c[sevFor(r.event)]++; });
  const lc=$("#live-counts");
  if(lc) lc.innerHTML=[["Total",recs.length,"var(--text)"],["Normal",c.ok,"var(--ok)"],["Info",c.info,"var(--info)"],["Warnings",c.warn,"var(--warn)"],["Critical",c.crit,"var(--crit)"]]
    .map(([l,n,col])=>`<div class="s"><span class="n" style="color:${col}">${n}</span><span class="l">${l}</span></div>`).join("");
  const lf=$("#live-feed");
  if(lf) lf.innerHTML=recs.slice(0,45).map(feedRow).join("")||'<div class="empty">No events.</div>';
}

/* ---------------- shared render helpers ---------------- */
const tierPill = (t)=>`<span class="tier t${t}">TIER ${t}</span>`;
const OK=["login","tool_call","authz_decision","gateway_startup","identity_unrevoked","identity_unlocked","killswitch_release","approval_vote"];
const WARN=["approval_requested","step_up_required","registry_drift_approved","tool_onboarded","registry_event"];
const CRIT=["login_failed","blocked","circuit_open","identity_revoked","killswitch_engage","login_locked_out","tool_error","drift_quarantine"];
function sevFor(ev){ const e=(ev||"").toLowerCase();
  if(CRIT.includes(e)) return "crit"; if(WARN.includes(e)) return "warn"; if(OK.includes(e)) return "ok"; return "info"; }
const SEVVAR={ok:"var(--ok)",warn:"var(--warn)",crit:"var(--crit)",info:"var(--info)"};
const barColor=(ev)=>SEVVAR[sevFor(ev)]||"var(--accent)";
const HIDE_KEYS=["ts","event","seq","sequence_number","hash","entry_hash","prev","prev_hash","prev_entry_hash"];
function fullKv(r){ return Object.entries(r).filter(([k])=>!HIDE_KEYS.includes(k))
  .map(([k,v])=>`${k}=${v&&typeof v==="object"?JSON.stringify(v):v}`).join(" · "); }
function feedRest(r){ const what=r.server&&r.tool?`${r.server}.${r.tool}`:(r.scope||r.server||"");
  const why=r.reason||r.outcome||(r.approval_id?`id=${r.approval_id}`:""); return [what,why].filter(Boolean).join(" · "); }
const fmtTime = (ts)=>{ try{ return new Date((ts||0)*1000).toLocaleTimeString(); }catch(e){ return ""; } };
function feedRow(r){ const who=esc(r.user||r.sub||r.by||""), rest=esc(feedRest(r));
  return `<div class="feed-row"><span class="feed-ev ${sevFor(r.event)}">${esc(r.event)}</span>
    <span class="feed-txt">${who?`<b>${who}</b>`:""}${who&&rest?" · ":""}${rest}</span>
    <span class="feed-time">${fmtTime(r.ts)}</span></div>`; }
function healthNode(name,brk,counts){ const up=!(brk[name]&&brk[name].open), n=counts[name];
  return `<div class="h-node"><span class="dot ${up?"ok":"crit"} ${up?"":"pulse"}"></span>
    <div class="n-tt"><div class="n-name">${esc(name)}</div>
      <div class="n-meta">${up?(n!=null?`${n} tools`:"reachable"):"circuit open · cooldown"}</div></div></div>`; }
function kpi(ic,lab,val,sub,cls){ return `<div class="tile ${cls||""}"><div class="k-lab">${I[ic]}${lab}</div>
  <div class="k-val">${val}</div><div class="k-sub">${sub}</div></div>`; }
/* Activity hero: real audit timestamps bucketed over time -> headline + trend + bars */
function activityChart(records, total){
  const recs=(records||[]).filter(r=>r&&r.ts);
  if(recs.length<2) return "";
  const times=recs.map(r=>r.ts), min=Math.min(...times); let max=Math.max(...times);
  if(max<=min) max=min+1;
  const N=10, span=(max-min)/N;
  const buckets=Array.from({length:N},(_,i)=>({t0:min+i*span,n:0}));
  recs.forEach(r=>{ const idx=Math.min(N-1,Math.max(0,Math.floor((r.ts-min)/span))); buckets[idx].n++; });
  const peak=buckets.reduce((mi,b,i,a)=>b.n>a[mi].n?i:mi,0), maxN=buckets[peak].n||1;
  const w=Math.max(1,Math.floor(N/3));                 // recent trend, robust to old spikes
  const recentW=buckets.slice(N-w).reduce((a,b)=>a+b.n,0);
  const priorW=buckets.slice(N-2*w,N-w).reduce((a,b)=>a+b.n,0);
  const delta=priorW>0?Math.round((recentW-priorW)/priorW*100):(recentW>0?100:0);
  const up=delta>=0;
  const hm=(t)=>{ const d=new Date(t*1000); return String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0"); };
  const bars=buckets.map((b,i)=>{ const h=b.n?Math.max(10,Math.round(Math.pow(b.n/maxN,0.55)*100)):4, hot=i===peak;
    return `<div class="ac-col" title="${hm(b.t0)} · ${b.n} event${b.n===1?"":"s"}">`
      +`<div class="ac-bar grow${hot?" hot":""}" style="height:${h}%;animation-delay:${(i*0.04).toFixed(2)}s"></div>`
      +`<span class="ac-x${hot?" hot":""}">${hm(b.t0)}</span></div>`; }).join("");
  const num=(total!=null?total:recs.length);
  return `<div class="card chartcard clickcard chart-in" onclick="go('audit')" role="button" tabindex="0" title="Open audit log">`
    +`<div class="cc-head"><span class="cc-ic">${I.chart}</span><span class="cc-title">Activity</span>`
    +`<span class="cc-eyebrow">events over time · last ${recs.length}</span>`
    +`<span class="cc-view">Open audit log →</span></div>`
    +`<div class="cc-hero"><span class="cc-num" data-count="${num}">0</span>`
    +`<span class="cc-delta ${up?"up":"down"}">${up?"▲":"▼"} ${Math.abs(delta)}%</span></div>`
    +`<div class="ac-plot">${bars}</div></div>`;
}
/* Donut (part-to-whole): clickable → related page, spring-in ring + count-up center. */
function donutChart(o){
  const segs=o.segments||[], total=segs.reduce((a,s)=>a+s.val,0), C=100; let cum=0;
  const rings=[`<circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--surface-3)" stroke-width="4" opacity=".5"></circle>`];
  if(total>0) segs.filter(s=>s.val>0).forEach(s=>{ const len=s.val/total*C;
    rings.push(`<circle cx="18" cy="18" r="15.915" fill="none" stroke="${s.color}" stroke-width="4" stroke-dasharray="${Math.max(0,len-0.8).toFixed(2)} ${(C-len+0.8).toFixed(2)}" stroke-dashoffset="${(-cum).toFixed(2)}"></circle>`);
    cum+=len; });
  const legend=segs.map(s=>`<div class="dl-row"><span class="dl-dot" style="background:${s.color}"></span><span class="dl-lab">${s.label}</span><span class="dl-val num">${s.val}</span></div>`).join("");
  return `<div class="card donutcard clickcard chart-in" style="animation-delay:${o.delay||0}s" onclick="go('${o.target}')" role="button" tabindex="0" title="${o.viewLab||""}">
    <div class="cc-head"><span class="cc-ic">${I.chart}</span><span class="cc-title">${o.title}</span><span class="cc-eyebrow">${o.eyebrow||""}</span></div>
    <div class="donutwrap">
      <div class="donut donut-pop"><svg viewBox="0 0 36 36" class="donut-svg">${rings.join("")}</svg>
        <div class="donut-center"><span class="donut-num" data-count="${o.centerNum||0}">0</span><span class="donut-lab">${o.centerLab||""}</span></div></div>
      <div class="donut-legend">${legend}<div class="dl-view">${o.viewLab||"View →"}</div></div>
    </div></div>`;
}
function countUp(el){ const to=parseFloat(el.getAttribute("data-count"))||0, dur=850, t0=performance.now();
  (function tick(now){ const p=Math.min(1,(now-t0)/dur), e=1-Math.pow(1-p,3);
    el.textContent=Math.round(to*e).toLocaleString(); if(p<1) requestAnimationFrame(tick); })(t0);
}
function runCountUps(root){ (root||document).querySelectorAll("[data-count]").forEach(countUp); }
function logRow(r){ return `<div class="log-row" data-ev="${esc(r.event)}"><span class="log-time">${fmtTime(r.ts)}</span>
  <span class="log-ev ${sevFor(r.event)}">${esc(r.event)}</span>
  <span class="log-kv">${esc(fullKv(r)).replace(/(\w+)=/g,"<b>$1</b>=")}</span></div>`; }
function killList(active){ return active.length?active.map(s=>`<div class="feed-row">
  <span class="pill crit"><span class="dot crit"></span>Engaged</span><span class="feed-txt"><b class="mono">${esc(s)}</b></span>
  <button class="btn btn-ghost btn-sm" style="margin-inline-start:auto" onclick="releaseKill('${jsq(s)}')">Release</button></div>`).join("")
  :'<div class="empty">No active kill switches.</div>'; }
function apprCard(a){ const need=a.approvals_required, have=(a.approvals||[]).length, taint=a.taint||[];
  return `<div class="appr-card ${a.tier===3?"t3":""}">
    <div class="a-h"><span class="a-name mono">${esc(a.server+"."+a.tool)}</span>${tierPill(a.tier)}</div>
    <div class="appr-meta"><span>Requested by <b>${esc(a.requester)}</b></span><span>·</span><span><b>${have}/${need}</b> approvals</span></div>
    <div class="progress">${Array.from({length:need},(_,i)=>`<i class="${i<have?"on":""}"></i>`).join("")}</div>
    ${taint.length?`<div class="taint-warn"><b>⚠ Tainted argument.</b> ${taint.map(t=>`<span class="mono">${esc(t.arg)}</span> ← <span class="mono">${esc(t.source)}</span>`).join(", ")}. Verify this was intended by you, not injected.</div>`:""}
    <div class="preview">${esc(a.preview||"")}</div>
    <div class="appr-actions"><button class="btn btn-danger" onclick="vote('${jsq(a.id)}','reject')">Reject</button>
      <button class="btn btn-primary" onclick="vote('${jsq(a.id)}','approve')">Approve</button></div></div>`; }

/* ---------------- dense-page helpers ---------------- */
const kpiSm=(ic,label,val)=>`<div class="kpi-sm"><div class="l">${ic?I[ic]:""}${label}</div><div class="n">${val}</div></div>`;
const sectionH=(title,desc,act)=>`<div class="section-h"><h3>${esc(title)}</h3>${desc?`<span class="s-desc">${esc(desc)}</span>`:""}${act?`<span class="s-act">${act}</span>`:""}</div>`;
const kvRows=(pairs,plainAll)=>`<div class="kv">${pairs.map(([k,v,plain])=>`<div class="kv-row"><span class="k">${esc(k)}</span><span class="v${(plain||plainAll)?" plain":""}">${v}</span></div>`).join("")}</div>`;
function meterBar(label,val,max,color){ const pct=Math.min(100,Math.round((val/(max||1))*100));
  return `<div class="meter"><div class="m-top"><span class="m-lab">${esc(label)}</span><span class="m-val">${val}${max?" / "+max:""}</span></div><div class="m-track"><div class="m-fill" style="width:${pct}%;background:${color||"var(--accent)"}"></div></div></div>`; }
function tierbars(tiers){ const g=(t)=>tiers[t]||tiers[String(t)]||0; if(![0,1,2,3].some(t=>g(t)>0)) return "";
  return `<div class="tierbars">${[0,1,2,3].map(t=>g(t)?`<i class="s${t}" style="flex:${g(t)}" title="Tier ${t}: ${g(t)}"></i>`:"").join("")}</div>`; }
const CK='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="yes"><path d="M20 6 9 17l-5-5"/></svg>';
const CX='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="no"><path d="M18 6 6 18M6 6l12 12"/></svg>';
const cap=(label,on)=>`<div class="cap">${on?CK:CX}<span>${esc(label)}</span></div>`;
const clearPill=(c)=>`<span class="clear-tag ${c}">${esc((c||"").replace(/_/g," "))}</span>`;
const yn=(b,cls)=>b?`<span class="pill ${cls||"ok"}">Yes</span>`:'<span style="color:var(--text-3)">—</span>';

/* ---------------- views ---------------- */
const VIEWS = {
  async overview(view){
    const admin=isAdmin();
    const [health,metrics,toolsRes,apprRes,auditRes,killRes,revRes]=await Promise.all([
      api("/api/health"), admin?tryApi("/api/metrics"):null, tryApi("/api/tools"),
      canApprove()?tryApi("/api/approvals"):null, admin?tryApi("/api/admin/audit"):null,
      admin?tryApi("/api/admin/killswitch"):null, admin?tryApi("/api/admin/revocations"):null ]);
    const servers=health.servers||[], breaker=(metrics&&metrics.circuit_breaker)||{};
    const brkOpen=Object.values(breaker).filter(b=>b&&b.open).length;
    const counts={}; if(toolsRes&&toolsRes.tools) toolsRes.tools.forEach(t=>counts[t.server]=(counts[t.server]||0)+1);
    const pendingAppr=apprRes?apprRes.pending.length:null, leases=metrics?metrics.active_credential_leases:null;
    const kills=killRes?killRes.active.length:null, revoked=revRes?revRes.revoked.length:null;
    const locked=revRes?Object.keys(revRes.lockouts||{}).length:null;
    const events=metrics?Object.values(metrics.event_counts||{}).reduce((a,b)=>a+b,0):null;
    const ecEntries=metrics&&metrics.event_counts?Object.entries(metrics.event_counts).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]).slice(0,8):[];
    const ecMax=ecEntries.length?Math.max(...ecEntries.map(e=>e[1])):1;
    const bars=ecEntries.length?`<div class="bars">${ecEntries.map(([k,v])=>`<div class="bar-row"><span class="b-lab">${esc(k)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(4,Math.round(v/ecMax*100))}%;background:${barColor(k)}"></div></div><span class="b-val num">${v}</span></div>`).join("")}</div>`:'<div class="empty">Metrics require admin.</div>';
    const d=(v)=>v==null?"—":v;
    const kpis=[
      kpi("server","Servers online",`${servers.length-brkOpen}<small> / ${servers.length}</small>`, brkOpen?`<span class="dot warn"></span> ${brkOpen} circuit open`:`<span class="dot ok"></span> all reachable`, brkOpen?"attn":""),
      kpi("tools","Tools available",`${d(health.tools)}`, health.pending_tools?`<span class="pill warn" style="padding:1px 7px">${health.pending_tools} pending</span> onboarding`:"all active",""),
      kpi("pending","Pending approvals",`${d(pendingAppr)}`,"human-in-the-loop", pendingAppr?"attn":""),
      kpi("lease","Active leases",`${d(leases)}`,`<span class="dot ok"></span> short-lived, per-call`,""),
      kpi("audit","Audit chain",`${health.audit_chain_ok?"Verified":"BROKEN"}`,"WORM · tamper-evident", health.audit_chain_ok?"":"crit-attn"),
      kpi("bolt","Events (session)",`${events==null?"—":events.toLocaleString()}`,"since last restart",""),
      kpi("power","Kill switches",`${d(kills)}`,"scoped containment", kills?"crit-attn":""),
      kpi("users","Revoked · Locked",`${d(revoked)} · ${d(locked)}`,"identity containment",(revoked||locked)?"attn":""),
    ];
    const feed = auditRes&&auditRes.records ? (auditRes.records.slice(-7).reverse().map(feedRow).join("")||'<div class="empty">No activity yet.</div>')
      : '<div class="empty">Audit feed requires admin.</div>';
    const apprMini = apprRes ? (apprRes.pending.length?apprRes.pending.map(a=>`<div class="feed-row" style="cursor:pointer" onclick="go('approvals')">
        <span class="tier t${a.tier}">T${a.tier}</span><span class="feed-txt"><b class="mono">${esc(a.server+"."+a.tool)}</b> · ${esc(a.requester)}</span>
        <span class="feed-time">${(a.approvals||[]).length}/${a.approvals_required}</span></div>`).join("")
      :'<div class="empty">Queue clear.</div>') : '<div class="empty">Approver access required.</div>';
    const hero=(admin&&auditRes&&auditRes.records)?activityChart(auditRes.records,events):"";
    let donuts="";
    if(admin){
      const sev={ok:0,info:0,warn:0,crit:0};
      ((auditRes&&auditRes.records)||[]).forEach(r=>sev[sevFor(r.event)]++);
      const sevSegs=[{label:"Normal",val:sev.ok,color:"var(--ok)"},{label:"Info",val:sev.info,color:"var(--info)"},{label:"Warning",val:sev.warn,color:"var(--warn)"},{label:"Critical",val:sev.crit,color:"var(--crit)"}];
      const TC={0:"var(--ok)",1:"var(--info)",2:"var(--warn)",3:"var(--crit)"}, tc={0:0,1:0,2:0,3:0};
      ((apprRes&&apprRes.pending)||[]).forEach(a=>{ const t=(a.tier in tc)?a.tier:3; tc[t]++; });
      const tierSegs=[0,1,2,3].map(t=>({label:"Tier "+t,val:tc[t],color:TC[t]}));
      const d1=donutChart({title:"Event severity",eyebrow:"audit · last "+(((auditRes&&auditRes.records)||[]).length),segments:sevSegs,centerNum:sevSegs.reduce((a,s)=>a+s.val,0),centerLab:"events",target:"audit",delay:.08,viewLab:"Open audit log →"});
      const d2=donutChart({title:"Approvals by risk tier",eyebrow:"pending · human-in-the-loop",segments:tierSegs,centerNum:tierSegs.reduce((a,s)=>a+s.val,0),centerLab:"pending",target:"approvals",delay:.16,viewLab:"Review approvals →"});
      donuts=`<div class="donutrow">${d1}${d2}</div>`;
    }
    view.innerHTML=`<div class="panel">
      ${hero}
      <div class="grid kpis">${kpis.join("")}</div>
      ${donuts}
      <div class="cols">
        <div class="card"><div class="card-head">${I.audit}<h3>Recent activity</h3><div class="h-r">${admin?`<button class="btn btn-ghost btn-sm" onclick="go('audit')">Open audit log</button>`:""}</div></div>
          <div class="card-body"><div class="feed">${feed}</div></div></div>
        <div class="card"><div class="card-head">${I.check}<h3>Approvals queue</h3><div class="h-r"><span class="pill ${pendingAppr?"warn":"ok"}">${pendingAppr==null?"—":pendingAppr+" waiting"}</span></div></div>
          <div class="card-body">${apprMini}</div></div>
      </div>
      <div class="cols" style="grid-template-columns:1.4fr 1fr;margin-top:16px">
        <div class="card"><div class="card-head">${I.server}<h3>Server health</h3><div class="h-r eyebrow">${servers.length} MCP servers · dynamic</div></div>
          <div class="card-body pad"><div class="health">${servers.map(s=>healthNode(s,breaker,counts)).join("")||'<div class="empty">No servers.</div>'}</div></div>
        <div class="card"><div class="card-head">${I.bolt}<h3>Event breakdown</h3><div class="h-r eyebrow">by type · session</div></div>
          <div class="card-body pad">${bars}</div></div>
      </div>
    </div>`;
    runCountUps(view);
  },

  console(view){
    view.innerHTML=`<div class="panel" style="max-width:960px"><div class="console">
      <div class="con-log" id="con-log"><div class="con-empty">${I.term}
        <div>The gateway runs no model. Call a tool the way your own local LLM would — e.g.
        <code>docs.search_documents {"query":"security"}</code></div></div></div>
      <div class="con-input"><input class="inp mono" id="con-in" placeholder='server.tool {"arg":"value"}'
        onkeydown="if(event.key==='Enter')conSend()"><button class="btn btn-primary" onclick="conSend()">${I.bolt} Call</button></div>
    </div></div>`;
  },

  async tools(view){
    const {tools}=await api("/api/tools");
    const appr=(t)=>t===0?'<span class="pill ok">Auto</span>':t===1?'<span class="pill info">Auto · write</span>':t===2?'<span class="pill warn">1 approver</span>':'<span class="pill crit">Two-person</span>';
    const rows=tools.map(t=>`<tr class="r-strip t${t.tier}" data-k="${esc((t.server+" "+t.name+" "+(t.description||"")).toLowerCase())}">
      <td><div class="t-title">${esc(t.name)}</div><div class="t-desc">${esc(t.description||"")}</div></td>
      <td><span class="mono">${esc(t.server)}</span></td><td>${tierPill(t.tier)}</td><td>${appr(t.tier)}</td></tr>`).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Tool catalog</h2>
      <p>Dynamically discovered from every registered MCP server and filtered by your role and clearance. Tier badges come from the gateway registry — never the servers themselves.</p></div>
      <div class="h-actions"><input class="inp" placeholder="Filter tools…" style="width:200px" oninput="filterTools(this.value)"></div></div>
      <div class="tbl-wrap"><table class="tbl" id="tools-tbl"><thead><tr><th>Tool</th><th>Server</th><th>Risk tier</th><th>Approval</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="4"><div class="empty">No tools visible at your clearance.</div></td></tr>'}</tbody></table></div></div>`;
  },

  async approvals(view){
    const {pending}=await api("/api/approvals"); APPR_COUNT=pending.length; buildSidebar();
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Authorization queue</h2>
      <p>Every write or destructive action is held here with its full, unsummarized parameters. Tier 2 needs one approver; Tier 3 needs two distinct approvers (segregation of duties). You cannot approve your own request.</p></div></div>
      <div class="appr">${pending.length?pending.map(apprCard).join(""):'<div class="empty" style="grid-column:1/-1">Queue clear — no actions awaiting approval.</div>'}</div></div>`;
  },

  async registry(view){
    const {entries}=await api("/api/admin/registry");
    const rows=entries.map(e=>{
      const hash=e.fingerprint?e.fingerprint.slice(0,4)+"…"+e.fingerprint.slice(-4):"—";
      const status=e.status==="active"?'<span class="pill ok"><span class="dot ok"></span>Active</span>'
        :e.status==="pending"?'<span class="pill warn">Pending</span>':'<span class="pill crit">Quarantined</span>';
      const act=e.status==="pending"?`<button class="btn btn-primary btn-sm" onclick="approveTool('${jsq(e.server)}','${jsq(e.tool)}')">Approve onboarding</button>`
        :e.status==="quarantined"?`<button class="btn btn-ghost btn-sm" onclick="approveDrift('${jsq(e.server)}','${jsq(e.tool)}')">Review drift · re-pin</button>`
        :'<span style="color:var(--text-3)">—</span>';
      return `<tr><td><span class="t-title">${esc(e.server+"."+e.tool)}</span>${e.quarantine_reason?`<div class="t-desc">${esc(e.quarantine_reason)}</div>`:""}</td>
        <td>${tierPill(e.tier)} <button class="btn btn-ghost btn-sm" title="Risk-Board tier override" onclick="setTier('${jsq(e.server)}','${jsq(e.tool)}',${e.tier})">Re-tier</button></td>
        <td>${status}</td><td><span class="mono">${esc(hash)}</span></td><td class="num">${act}</td></tr>`;
    }).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Tool registry</h2>
      <p>The authoritative inventory. New tools land <b>pending</b> until the Risk-Board approves them; every definition is SHA-256 hash-pinned and auto-quarantined on drift (rug-pull defense).</p></div></div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Tool</th><th>Tier</th><th>Status</th><th>Pinned digest</th><th class="num">Action</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="5"><div class="empty">No tools registered.</div></td></tr>'}</tbody></table></div></div>`;
  },

  async identities(view){
    const {revoked,lockouts}=await api("/api/admin/revocations");
    const lk=Object.entries(lockouts||{});
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Identity containment</h2>
      <p>Revoke a compromised agent or operator in under a second — blocking in-flight tokens independent of their lifetime — and clear anti-hammering lockouts after out-of-band verification.</p></div></div>
      <div class="split2">
        <div class="card"><div class="card-head">${I.users}<h3>Revoked identities</h3><div class="h-r"><button class="btn btn-danger btn-sm" onclick="revokePrompt()">Revoke identity</button></div></div>
          <div class="card-body">${revoked.length?revoked.map(s=>`<div class="feed-row"><span class="pill crit">Revoked</span>
            <span class="feed-txt"><b class="mono">${esc(s)}</b></span>
            <button class="btn btn-ghost btn-sm" style="margin-inline-start:auto" onclick="unrevoke('${jsq(s)}')">Restore</button></div>`).join(""):'<div class="empty">No revoked identities.</div>'}</div></div>
        <div class="card"><div class="card-head">${I.power}<h3>Locked out (anti-hammering)</h3></div>
          <div class="card-body">${lk.length?lk.map(([s,v])=>`<div class="feed-row"><span class="pill warn">Locked</span>
            <span class="feed-txt"><b class="mono">${esc(s)}</b> · ${v.fails} fails</span>
            <span class="feed-time">${v.locked_for}s</span>
            <button class="btn btn-ghost btn-sm" onclick="unlock('${jsq(s)}')">Clear</button></div>`).join(""):'<div class="empty">No active lockouts.</div>'}</div></div>
      </div></div>`;
  },

  async killswitch(view){
    const {active}=await api("/api/admin/killswitch");
    view.innerHTML=`<div class="panel" style="max-width:900px"><div class="page-head"><div class="h-tt"><h2>Kill switch</h2>
      <p>Instant, scoped containment — the first move in any incident. Engage globally, or per server, per tool, or per user. Survives restart.</p></div></div>
      <div class="card"><div class="card-body pad"><label class="fld">Scope</label>
        <div style="display:flex;gap:9px;margin-top:4px"><input class="inp mono" id="kill-scope" placeholder="global · server:actions · tool:actions:delete_record · user:sara">
        <button class="btn btn-danger" onclick="engageKill()">${I.power} Engage</button></div>
        <div style="margin-top:8px;font-size:11.5px;color:var(--text-3)">Examples: <span class="mono">global</span>, <span class="mono">server:finance</span>, <span class="mono">user:ghost</span></div></div></div>
      <div class="card" style="margin-top:16px"><div class="card-head">${I.power}<h3>Active kill switches</h3></div>
        <div class="card-body" id="kill-list">${killList(active)}</div></div></div>`;
  },

  async credentials(view){
    const {active_leases}=await api("/api/admin/vault");
    const rows=active_leases.map(l=>`<tr><td><span class="mono">${esc(l.lease)}</span></td><td><span class="mono">${esc(l.server)}</span></td>
      <td><span class="mono">${esc(l.user)}</span></td><td class="num mono">${l.expires_in}s</td>
      <td class="num"><span class="pill ok"><span class="dot ok pulse"></span>Live</span></td></tr>`).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Credential leases</h2>
      <p>The vault mints a short-lived, per-(server, user) credential and injects it at dispatch — the secret is never in the model's context and never in the audit payload, only a lease id and a digest.</p></div></div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Lease</th><th>Backend server</th><th>On behalf of</th><th class="num">Expires in</th><th class="num">Status</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="5"><div class="empty">No live leases right now.</div></td></tr>'}</tbody></table></div>
      <p style="color:var(--text-3);font-size:12px;margin-top:12px">Leases auto-revoke immediately after each call — this lists only what is live right now.</p></div>`;
  },

  async audit(view){
    const {chain_ok,chain_status,records}=await api("/api/admin/audit");
    const recs=records.slice().reverse(), evs=[...new Set(recs.map(r=>r.event))];
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Audit log</h2>
      <p>Append-only and hash-chained (HMAC-SHA256). Each entry links to the previous — any tampering breaks the chain and is caught on verification.</p></div>
      <div class="h-actions"><span class="sys-chip"><span class="dot ${chain_ok?"ok":"crit"}"></span> ${esc(chain_status||(chain_ok?"chain verified":"BROKEN"))}</span></div></div>
      <div class="filterbar"><span class="chipf on" onclick="auditFilter(this,'*')">All events</span>
        ${evs.map(e=>`<span class="chipf" onclick="auditFilter(this,'${jsq(e)}')">${esc(e)}</span>`).join("")}</div>
      <div class="log" id="audit-log">${recs.map(logRow).join("")||'<div class="empty">No audit records.</div>'}</div></div>`;
  },

  async monitor(view){
    view.innerHTML=`<div class="panel">
      <div class="card"><div class="card-head">${I.activity}<h3>Event severity</h3><div class="h-r"><span class="live-dot"><span class="dot ok pulse"></span> live · 4s</span></div></div>
        <div class="stat-strip" id="live-counts"><div class="empty">Loading…</div></div></div>
      <div class="card" style="margin-top:16px"><div class="card-head">${I.audit}<h3>Live event stream</h3><div class="h-r eyebrow">most recent first</div></div>
        <div class="card-body"><div class="feed" id="live-feed"><div class="empty">Loading…</div></div></div></div></div>`;
    await updateLive(); startLive();
  },

  async sessions(view){
    const {sessions}=await api("/api/admin/sessions");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Client sessions</h2>
      <p>Every colleague's local LLM connects as an MCP client. Each session carries a CSPRNG id bound to the authenticated operator — a stolen token cannot ride another operator's session.</p></div>
      <div class="h-actions"><span class="sys-chip"><span class="dot ${sessions.length?"ok pulse":""}"></span> ${sessions.length} active</span></div></div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Session id</th><th>Operator</th><th class="num">Age</th><th class="num">Status</th></tr></thead>
      <tbody>${sessions.length?sessions.map(s=>`<tr><td><span class="mono">${esc(s.id)}…</span></td><td><span class="mono">${esc(s.sub)}</span></td><td class="num mono">${s.age_seconds}s</td><td class="num"><span class="pill ok"><span class="dot ok pulse"></span>Live</span></td></tr>`).join(""):'<tr><td colspan="4"><div class="empty">No active client sessions right now.</div></td></tr>'}</tbody></table></div>
      <p class="note">Sessions are ephemeral and in-memory — they end on the client's DELETE, on token expiry, or on a gateway restart (clients simply re-initialize).</p></div>`;
  },

  async operators(view){
    const {operators,count}=await api("/api/admin/operators");
    const admins=operators.filter(o=>o.admin).length, approvers=operators.filter(o=>o.can_approve).length;
    const rows=operators.map(o=>{
      const status=o.revoked?'<span class="pill crit">Revoked</span>':o.locked?`<span class="pill warn">Locked (${o.fails})</span>`:'<span class="pill ok"><span class="dot ok"></span>Active</span>';
      const caps=[o.admin?'<span class="tag">Admin</span>':"",o.can_approve?'<span class="tag">Approver</span>':""].filter(Boolean).join(" ")||'<span class="tag">Standard</span>';
      const act=o.revoked?`<button class="btn btn-ghost btn-sm" onclick="unrevoke('${jsq(o.sub)}')">Restore</button>`
        :o.admin?'<span style="color:var(--text-3)">—</span>':`<button class="btn btn-danger btn-sm" onclick="revoke('${jsq(o.sub)}')">Revoke</button>`;
      return `<tr><td><div class="opname"><span class="avatar-sm">${esc(o.name.trim().charAt(0))}</span><div><div style="font-weight:600">${esc(o.name)}</div><div class="mono" style="font-size:11px;color:var(--text-3)">${esc(o.sub)}</div></div></div></td>
        <td style="text-transform:capitalize">${esc(o.role)}</td><td>${clearPill(o.clearance)}</td><td>${tierPill(o.max_tool_tier)}</td><td>${caps}</td><td>${status}</td><td class="num">${act}</td></tr>`;
    }).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Operator directory</h2>
      <p>Every identity the gateway recognizes — each a named entity with a role, an NDMO clearance, and a tool-tier ceiling. A session always inherits the human's own clearance, never a shared account.</p></div></div>
      <div class="grid kpis-3" style="margin-bottom:16px">${kpiSm("users","Operators",count)}${kpiSm("badge","Administrators",admins)}${kpiSm("check","Approvers",approvers)}</div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Operator</th><th>Role</th><th>Clearance</th><th>Tier ceiling</th><th>Capabilities</th><th>Status</th><th class="num">Action</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  },

  async roles(view){
    const {roles}=await api("/api/admin/policy");
    const cards=Object.entries(roles).map(([name,rc])=>`<div class="rolecard"><div class="rc-h"><span class="avatar-sm">${esc(name.charAt(0).toUpperCase())}</span><h4>${esc(name)}</h4><span style="margin-inline-start:auto">${tierPill(rc.max_tool_tier)}</span></div>
      <div class="rc-caps">${cap("Call up to Tier "+rc.max_tool_tier,true)}${cap("Approve actions (HITL)",!!rc.can_approve)}${cap("Administer the gateway",!!rc.admin)}</div></div>`).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Roles &amp; permissions</h2>
      <p>Role capabilities are enforced mechanically at the gateway (default-deny). A role sets the maximum tool tier a member may even request; higher tiers still require human approval on top.</p></div></div>
      <div class="grid grid3">${cards}</div>
      ${sectionH("Capability matrix","Which role may do what")}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Role</th><th class="num">Max tool tier</th><th>Can approve</th><th>Admin</th></tr></thead>
      <tbody>${Object.entries(roles).map(([n,rc])=>`<tr><td style="text-transform:capitalize;font-weight:600">${esc(n)}</td><td class="num">${tierPill(rc.max_tool_tier)}</td><td>${yn(rc.can_approve)}</td><td>${yn(rc.admin,"accent")}</td></tr>`).join("")}</tbody></table></div>
      <p class="note">Tiers: 0 read (auto) · 1 reversible write (auto) · 2 outbound (one approver) · 3 destructive (two-person). Tainted arguments escalate a tier and never auto-execute.</p></div>`;
  },

  async certificates(view){
    const [{operators},cfg]=await Promise.all([api("/api/admin/operators"),tryApi("/api/admin/config")]);
    const a=(cfg&&cfg.auth)||{};
    const rows=operators.map(o=>`<tr><td><div class="opname"><span class="avatar-sm">${esc(o.name.trim().charAt(0))}</span><span class="mono">CN=${esc(o.sub)}</span></div></td>
      <td><span class="tag">TPM-sealed</span></td><td class="mono">ES256 · P-256</td><td>${o.revoked?'<span class="pill crit">Revoked</span>':'<span class="pill ok"><span class="dot ok"></span>Valid</span>'}</td></tr>`).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Certificates &amp; PKI</h2>
      <p>Operators sign in with a username and strong password (salted PBKDF2), with optional TOTP MFA. This layer manages the PKI that underpins token integrity: session tokens are ES256-signed and cryptographically bound to the session (RFC 8705). TPM-sealed X.509 certificate login is a supported production upgrade.</p></div></div>
      <div class="grid2"><div class="card"><div class="card-head">${I.cert}<h3>Certificate authority</h3></div>${kvRows([["Signature algorithm",(a.alg||"ES256")+" (ECDSA P-256)"],["Token issuer",a.issuer||"—"],["Audience",a.audience||"—"],["Assurance level",(a.aal||"aal2").toUpperCase()],["Session TTL",(a.access_ttl_seconds||600)+"s"],["Mode",a.mode||"builtin"]])}</div>
        <div class="card"><div class="card-head">${I.shield}<h3>Issuance model</h3></div><div class="card-body pad" style="font-size:12.5px;color:var(--text-2);line-height:1.7">Each operator holds a short-lived certificate (prod: 24–72h, auto-rotated) from the internal CA. Production swap points: signing key → OpenBao Transit / HSM · CA → step-ca / OpenBao PKI · thumbprint header set by the mTLS-terminating sidecar.</div></div></div>
      ${sectionH("Issued certificates","One TPM-sealed certificate per operator")}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Subject</th><th>Key custody</th><th>Algorithm</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  },

  async servers(view){
    const {servers}=await api("/api/admin/servers");
    const totalTools=servers.reduce((a,s)=>a+s.tools,0), open=servers.filter(s=>s.breaker_open).length;
    const cards=servers.map(s=>`<div class="card"><div class="card-head">${I.server}<h3 class="mono">${esc(s.name)}</h3>
      <div class="h-r">${s.breaker_open?'<span class="pill crit"><span class="dot crit pulse"></span>Circuit open</span>':'<span class="pill ok"><span class="dot ok"></span>Healthy</span>'}</div></div>
      <div class="card-body pad">
        <div class="stat-strip" style="padding:0 0 12px;gap:22px"><div class="s"><span class="n">${s.tools}</span><span class="l">Tools</span></div><div class="s"><span class="n">${s.active}</span><span class="l">Active</span></div><div class="s"><span class="n">${s.pending}</span><span class="l">Pending</span></div><div class="s"><span class="n">${s.quarantined}</span><span class="l">Quarantined</span></div></div>
        ${tierbars(s.tiers)}
        <div style="display:flex;gap:7px;margin-top:12px;flex-wrap:wrap">${[0,1,2,3].map(t=>`<span class="tier t${t}">T${t}: ${s.tiers[String(t)]||0}</span>`).join("")}</div>
        <div style="margin-top:12px;display:flex;gap:7px;flex-wrap:wrap"><span class="tag">stdio · isolated</span>${s.managed_credentials?'<span class="tag">Vault-managed creds</span>':""}${s.fails?`<span class="tag" style="color:var(--warn)">${s.fails} recent failures</span>`:""}</div>
        <button class="btn btn-primary btn-sm" style="margin-top:14px" onclick="manageServer('${jsq(s.name)}')">Manage server</button>
      </div></div>`).join("");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>MCP server inventory</h2>
      <p>Each backend domain (HR, Finance, Correspondence…) is a separate MCP server behind the gateway — its own isolation zone, least-privilege credentials, default-deny egress. The count is fully dynamic.</p></div></div>
      <div class="grid kpis-3" style="margin-bottom:16px">${kpiSm("server","Servers",servers.length)}${kpiSm("tools","Total tools",totalTools)}${kpiSm("power","Circuits open",open)}</div>
      <div class="grid grid2">${cards||'<div class="empty">No servers.</div>'}</div></div>`;
  },

  async policies(view){
    const {roles,clearance_order}=await api("/api/admin/policy");
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Policy-as-code (ABAC)</h2>
      <p>The decision is <span class="mono">role × clearance × data-classification × tool-tier</span>, deny-by-default, versioned and testable. The gateway enforces it in code — the model's good behavior is never trusted.</p></div></div>
      <div class="grid2">
        <div class="card"><div class="card-head">${I.layers}<h3>Clearance ladder</h3></div><div class="card-body pad"><div class="ladder">${clearance_order.map((c,i)=>`<div class="lv l${i}"><span class="lv-n">${esc(c.replace(/_/g," "))}</span><span class="lv-d">rank ${i} — visible only if the caller's clearance dominates it</span></div>`).join("")}</div></div></div>
        <div class="card"><div class="card-head">${I.badge}<h3>Role capabilities</h3></div><div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Role</th><th class="num">Max tier</th><th>Approve</th><th>Admin</th></tr></thead><tbody>${Object.entries(roles).map(([n,rc])=>`<tr><td style="text-transform:capitalize">${esc(n)}</td><td class="num">${tierPill(rc.max_tool_tier)}</td><td>${yn(rc.can_approve)}</td><td>${yn(rc.admin,"accent")}</td></tr>`).join("")}</tbody></table></div></div>
      </div>
      ${sectionH("Tool-risk tiers","The four tiers and how each is handled")}
      <div class="tbl-wrap"><table class="matrix"><thead><tr><th>Tier</th><th>Meaning</th><th>Handling</th></tr></thead><tbody>
        <tr><td>${tierPill(0)}</td><td class="fw">Read-only</td><td class="md">Auto-approved. No state change.</td></tr>
        <tr><td>${tierPill(1)}</td><td class="fw">Reversible write</td><td class="md">Policy auto-approved. Undoable.</td></tr>
        <tr><td>${tierPill(2)}</td><td class="fw">Outbound / sensitive write</td><td class="md">One human approver, full unsummarized parameters shown.</td></tr>
        <tr><td>${tierPill(3)}</td><td class="fw">Destructive</td><td class="md">Two distinct approvers (segregation of duties) + fresh step-up re-auth.</td></tr>
      </tbody></table></div>
      <p class="note">Taint rule: an argument derived from untrusted content (a document, a tool result) escalates the tier and is flagged for the approver — a prompt-injected value can never silently execute a write.</p></div>`;
  },

  async classification(view){
    const {clearance_order}=await api("/api/admin/policy");
    const H={public:"Read + write autonomous. Shareable.",restricted:"Internal only. Writes need confirmation.",secret:"Read autonomous for cleared callers; DLP-masked otherwise. Writes gated.",top_secret:"Broker-mediated, purpose-bound, named approver, network-isolated."};
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Data classification</h2>
      <p>Every MCP server and tool is tagged with a maximum classification. The gateway masks fields a caller is not cleared to see, and the session inherits the human's clearance — never a shared high-privilege identity. Aligned to NDMO.</p></div></div>
      <div class="ladder">${clearance_order.map((c,i)=>`<div class="lv l${i}"><span class="lv-n">${esc(c.replace(/_/g," "))}</span><span class="lv-d">${esc(H[c]||"handled per policy")}</span></div>`).join("")}</div>
      ${sectionH("Inline DLP","Detectors run on tool arguments (pre-call) and results (post-call)")}
      <div class="grid grid3">${["Saudi National ID","Iqama (residency)","IBAN"].map(d=>`<div class="kpi-sm"><div class="l">${I.eye} ${esc(d)}</div><div class="n" style="font-size:15px;margin-top:8px;color:var(--ok)">Active</div></div>`).join("")}</div>
      <p class="note">Detection is two-layer — regex (national IDs, Iqama, IBAN, cards, keys) plus a self-hosted NER model for unstructured PII in production. Fail-closed on scanner error; warn-mode first, then block/redact.</p></div>`;
  },

  async ratelimits(view){
    const cfg=await api("/api/admin/config"); const g=cfg.gateway||{}, a=cfg.auth||{};
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Rate limits</h2>
      <p>Token-bucket throttles on three independent keys contain a runaway agent, a costly tool, and a compromised server. Every 429 is fed to the SIEM as an anomaly signal — never a silent empty result.</p></div></div>
      <div class="grid2"><div class="card"><div class="card-head">${I.gauge}<h3>Tool-call throttles (per minute)</h3></div><div class="card-body pad">
        ${meterBar("Per user",g.rate_limit_calls_per_minute||0,60,"var(--info)")}${meterBar("Per (user, tool)",g.rate_limit_per_tool_per_minute||0,60,"var(--warn)")}${meterBar("Per server",g.rate_limit_per_server_per_minute||0,120,"var(--accent)")}</div></div>
        <div class="card"><div class="card-head">${I.shield}<h3>Auth &amp; protocol limits</h3></div>${kvRows([["Login attempts / min / IP",a.login_rate_per_minute||"—"],["Lockout threshold",(a.lockout_threshold||"—")+" fails"],["Lockout cooldown",(a.lockout_seconds||"—")+"s"],["Max request body",((a.max_request_bytes||0)/1024|0)+" KB"],["Max tool result",((g.max_tool_result_bytes||0)/1024|0)+" KB"],["Max argument length",(g.max_arg_string_len||"—")+" chars"]])}</div></div>
      ${sectionH("Circuit breaker","Contains a failing or compromised server")}
      <div class="grid grid3">${kpiSm("power","Failure threshold",(g.breaker_failure_threshold||"—")+" fails")}${kpiSm("lease","Cooldown",(g.breaker_cooldown_seconds||"—")+"s")}${kpiSm("bolt","Taint min length",(g.taint_min_len||"—")+" chars")}</div></div>`;
  },

  async dlp(view){
    const audit=await tryApi("/api/admin/audit");
    const masks=audit?audit.records.filter(r=>r.pii_masked).length:0;
    const detected=audit?audit.records.filter(r=>Array.isArray(r.pii_detected)&&r.pii_detected.length).length:0;
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Data-loss prevention</h2>
      <p>An inline DLP layer inspects the payload at two points — tool arguments before they reach a backend, and tool results before they re-enter model context — and masks PII the caller is not cleared to see. Fail-closed.</p></div></div>
      <div class="grid kpis-3" style="margin-bottom:16px">${kpiSm("eye","Detectors",4)}${kpiSm("shield","Results masked (recent)",masks)}${kpiSm("audit","PII detections (recent)",detected)}</div>
      ${sectionH("Detectors")}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Detector</th><th>Covers</th><th>Method</th><th class="num">Status</th></tr></thead><tbody>
        <tr><td class="t-title">saudi_national_id</td><td>National identity (10-digit, Luhn)</td><td>Regex + checksum</td><td class="num"><span class="pill ok">Active</span></td></tr>
        <tr><td class="t-title">iqama</td><td>Residency permit number</td><td>Regex + checksum</td><td class="num"><span class="pill ok">Active</span></td></tr>
        <tr><td class="t-title">iban</td><td>Bank account (SA, mod-97)</td><td>Regex + mod-97</td><td class="num"><span class="pill ok">Active</span></td></tr>
        <tr><td class="t-title">unstructured_pii</td><td>Names, addresses in free text</td><td>Self-hosted NER</td><td class="num"><span class="pill warn">Production</span></td></tr>
      </tbody></table></div>
      <p class="note">Roll out in warn/log-only mode first to tune false positives, then switch to block/redact. Reversible tokenization keeps a per-session token↔value map inside the trust boundary for outputs that must be rehydrated (e.g. drafting a reply to a named citizen).</p></div>`;
  },

  async metrics(view){
    const m=await api("/api/metrics");
    const ec=Object.entries(m.event_counts||{}).sort((x,y)=>y[1]-x[1]);
    const mx=ec.length?Math.max(...ec.map(e=>e[1])):1, brk=Object.entries(m.circuit_breaker||{});
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Operational metrics</h2>
      <p>Counters since the last restart. In production these stream to the SIEM at agent volume for anomaly detection (impossible-travel, identity saturation, off-hours tool chains).</p></div></div>
      <div class="grid kpis-3" style="margin-bottom:16px">${kpiSm("bolt","Total events",ec.reduce((a,e)=>a+e[1],0).toLocaleString())}${kpiSm("lease","Active leases",m.active_credential_leases)}${kpiSm("pending","Pending onboarding",m.pending_tool_onboarding)}</div>
      <div class="grid2">
        <div class="card"><div class="card-head">${I.chart}<h3>Events by type</h3></div><div class="card-body pad"><div class="bars">${ec.map(([k,v])=>`<div class="bar-row"><span class="b-lab">${esc(k)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(4,Math.round(v/mx*100))}%;background:${barColor(k)}"></div></div><span class="b-val">${v}</span></div>`).join("")||'<div class="empty">No events.</div>'}</div></div></div>
        <div class="card"><div class="card-head">${I.power}<h3>Circuit breakers</h3></div><div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Server</th><th class="num">Failures</th><th class="num">State</th></tr></thead><tbody>${brk.length?brk.map(([s,b])=>`<tr><td class="mono">${esc(s)}</td><td class="num">${b.fails}</td><td class="num">${b.open?'<span class="pill crit">Open</span>':'<span class="pill ok">Closed</span>'}</td></tr>`).join(""):'<tr><td colspan="3"><div class="empty">All servers nominal.</div></td></tr>'}</tbody></table></div></div>
      </div></div>`;
  },

  async configuration(view){
    const c=await api("/api/admin/config"); const a=c.auth||{}, g=c.gateway||{};
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Runtime configuration</h2>
      <p>Validated on startup (fails fast on misconfiguration). Secrets are never shown — they are supplied at runtime from the HSM / secret store, never baked into the image.</p></div></div>
      <div class="grid2">
        <div class="card"><div class="card-head">${I.shield}<h3>Authentication</h3></div>${kvRows([["Mode",a.mode||"builtin"],["Algorithm",a.alg||"ES256"],["Issuer",a.issuer||"—"],["Audience",a.audience||"—"],["Assurance",(a.aal||"aal2").toUpperCase()],["Access token TTL",(a.access_ttl_seconds||"—")+"s"],["Lockout after",(a.lockout_threshold||"—")+" fails"]])}</div>
        <div class="card"><div class="card-head">${I.sliders}<h3>Gateway limits</h3></div>${kvRows([["Per-user rate",(g.rate_limit_calls_per_minute||"—")+"/min"],["Per-tool rate",(g.rate_limit_per_tool_per_minute||"—")+"/min"],["Per-server rate",(g.rate_limit_per_server_per_minute||"—")+"/min"],["Max tool result",((g.max_tool_result_bytes||0)/1024|0)+" KB"],["Breaker threshold",(g.breaker_failure_threshold||"—")+" fails"],["Breaker cooldown",(g.breaker_cooldown_seconds||"—")+"s"]])}</div>
      </div>
      <div class="grid2" style="margin-top:16px">
        <div class="card"><div class="card-head">${I.reg}<h3>Governance</h3></div>${kvRows([["Registry approval gate",c.registry&&c.registry.require_approval?"required (prod)":"auto (dev)"],["SIEM export",c.audit&&c.audit.siem_export?"on":"off"],["SIEM stream",(c.audit&&c.audit.siem_stream)||"—"],["Vault-managed servers",Object.keys(c.vault||{}).join(", ")||"—"]])}</div>
        <div class="card"><div class="card-head">${I.server}<h3>Registered servers</h3></div>${kvRows((c.servers||[]).map(s=>[s.name,esc(s.command),true]))}</div>
      </div>
      <p class="note">Production swap points (config-only): <span class="mono">auth.mode: oidc</span> → Keycloak · <span class="mono">KEK</span> → HSM · vault → OpenBao · SIEM → Wazuh. Inference is client-side; the gateway runs no model.</p></div>`;
  },

  async diagnostics(view){
    const [h,m]=await Promise.all([api("/api/health"),tryApi("/api/metrics")]);
    const brk=(m&&m.circuit_breaker)||{};
    const comp=[
      ["Gateway core",h.status==="ok"?"ok":"warn",h.status],
      ["Authentication","ok",h.auth_mode||"builtin"],
      ["Audit chain",h.audit_chain_ok?"ok":"crit",h.audit_chain_ok?"verified":"BROKEN"],
      ["Tool registry","ok",h.pending_tools?`${h.pending_tools} pending`:"clean"],
      ["Credential vault","ok",(m?m.active_credential_leases:0)+" live leases"],
    ];
    view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt"><h2>Diagnostics</h2>
      <p>Component health and the live circuit-breaker state across every backend server.</p></div>
      <div class="h-actions"><button class="btn btn-ghost btn-sm" onclick="renderView('diagnostics')">Refresh</button></div></div>
      <div class="card"><div class="card-head">${I.activity}<h3>Component status</h3></div><div class="card-body">
        ${comp.map(([n,sev,detail])=>`<div class="feed-row"><span class="pill ${sev}"><span class="dot ${sev}"></span>${sev==="ok"?"Operational":sev==="warn"?"Degraded":"Failed"}</span><span class="feed-txt"><b>${esc(n)}</b></span><span class="feed-time">${esc(detail)}</span></div>`).join("")}
      </div></div>
      ${sectionH("Backend servers","Reachability & circuit-breaker state")}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Server</th><th class="num">Recent failures</th><th class="num">Circuit</th></tr></thead><tbody>${(h.servers||[]).map(s=>{const b=brk[s]||{};return `<tr><td class="mono">${esc(s)}</td><td class="num">${b.fails||0}</td><td class="num">${b.open?'<span class="pill crit">Open</span>':'<span class="pill ok">Closed</span>'}</td></tr>`;}).join("")}</tbody></table></div></div>`;
  },

  async about(view){
    const h=await tryApi("/api/health");
    view.innerHTML=`<div class="panel" style="max-width:820px"><div class="page-head"><div class="h-tt"><h2>About</h2>
      <p>Secure MCP Gateway — a zero-trust control plane for on-premise AI agents connected to internal systems via the Model Context Protocol.</p></div></div>
      <div class="card"><div class="card-head">${I.shield}<h3>Platform</h3></div>${kvRows([["Product","Secure MCP Gateway"],["Version","1.0"],["Environment","Development"],["MCP protocol","2025-11-25"],["Servers online",h?String((h.servers||[]).length):"—"],["Tools",h?String(h.tools):"—"],["Auth mode",h?h.auth_mode:"—"]])}</div>
      <div class="card" style="margin-top:16px"><div class="card-head">${I.sliders}<h3>Stack</h3></div>${kvRows([["Runtime","Python · FastAPI · Uvicorn"],["Protocol","MCP SDK — stdio (servers) + Streamable HTTP (clients)"],["Signing","ECDSA P-256 (ES256)"],["Audit","HMAC-SHA256 hash chain (WORM)"],["Inference","Client-side — the gateway runs no model"]],true)}</div>
      <p class="note">Air-gapped, sovereign, no cloud dependency. Built for a ~200-person government entity.</p></div>`;
  },
};

/* ---------------- interactions ---------------- */
function addCon(h){ const log=$("#con-log"); log.insertAdjacentHTML("beforeend",h); log.scrollTop=log.scrollHeight; }
async function conSend(){
  const inp=$("#con-in"), raw=inp.value.trim(); if(!raw) return; inp.value="";
  const empty=$("#con-log").querySelector(".con-empty"); if(empty) empty.remove();
  addCon(`<div class="msg me"><div class="bubble">${esc(raw)}</div></div>`);
  const m=raw.replace(/^#call\s+/i,"").match(/^([\w]+)\.([\w]+)\s*([\s\S]*)$/);
  if(!m){ addCon('<div class="msg sys">Format: <code>server.tool {json}</code></div>'); return; }
  const server=m[1], tool=m[2], argstr=m[3].trim(); let args={};
  if(argstr){ try{ args=JSON.parse(argstr); }catch(e){ addCon('<div class="msg sys">Invalid JSON arguments — '+esc(e.message)+'</div>'); return; } }
  try{
    if(!state.mcpSession) await mcpInitialize();
    renderConResult(server,tool,await mcpCall(server+"__"+tool,args));
  }catch(e){ addCon('<div class="msg sys">Error: '+esc(e.message)+'</div>'); }
  if(canApprove()) refreshApprCount();
}
function renderConResult(server,tool,res){
  const g=(res._meta&&res._meta.gateway)||{};
  const status=g.status||(res.isError?"error":"executed");
  const pill={executed:"ok",pending_approval:"warn",denied:"crit",blocked:"crit",error:"crit"}[status]||"info";
  const label={executed:"Executed",pending_approval:"Held for approval",denied:"Denied",blocked:"Blocked",error:"Error"}[status]||status;
  const body=res.structuredContent!=null?JSON.stringify(res.structuredContent,null,2):(res.content||[]).map(c=>c.text||"").join("");
  addCon(`<div class="result"><div class="r-head"><span class="r-name">${esc(server+"."+tool)}</span>
    ${g.tier!=null?tierPill(g.tier):""}<span class="pill ${pill}">${label}</span>
    ${g.pii_masked?'<span class="pill warn">PII masked</span>':""}${g.taint&&g.taint.length?'<span class="pill crit">Tainted</span>':""}</div>
    <div class="r-body">${esc(body)}</div></div>`);
}
async function vote(id,action){
  try{
    const res=await api(`/api/approvals/${id}/${action}`,{method:"POST"});
    if(res.status==="approved_and_executed") toast(`Approval ${id} approved and executed.`);
    else if(action==="reject") toast("Request rejected.");
    else toast(`Vote recorded — ${res.remaining} approval(s) still needed.`);
  }catch(e){
    if(e.status===401) toast("Step-up required: sign in again (fresh auth) to approve a Tier-3 action.");
    else toast(e.message);   // e.g. segregation-of-duties: cannot approve your own request
  }
  renderView("approvals"); refreshApprCount();
}
function filterTools(q){ q=q.toLowerCase();
  document.querySelectorAll("#tools-tbl tbody tr").forEach(r=>{ if(r.dataset.k) r.style.display=r.dataset.k.includes(q)?"":"none"; }); }
function auditFilter(el,ev){
  document.querySelectorAll(".chipf").forEach(c=>c.classList.remove("on")); el.classList.add("on");
  document.querySelectorAll("#audit-log .log-row").forEach(r=>r.style.display=(ev==="*"||r.dataset.ev===ev)?"":"none"); }
async function approveTool(s,t){ try{ await api(`/api/admin/registry/${s}/${t}/approve`,{method:"POST"}); toast("Tool onboarded."); }catch(e){ toast(e.message); } renderView("registry"); }
async function approveDrift(s,t){ try{ await api(`/api/admin/registry/${s}/${t}/approve_drift`,{method:"POST"}); toast("Drift accepted and re-pinned."); }catch(e){ toast(e.message); } renderView("registry"); }
async function setTier(s,t,cur){
  const v=prompt(`Risk tier for ${s}.${t}\n0 = read (auto) · 1 = reversible write (policy) · 2 = human approval · 3 = two-person`,String(cur));
  if(v===null) return;
  const tier=Number(v);
  if(![0,1,2,3].includes(tier)){ toast("Tier must be 0, 1, 2 or 3."); return; }
  try{ await api(`/api/admin/registry/${s}/${t}/tier`,{method:"POST",body:JSON.stringify({tier})}); toast("Tier updated."); }catch(e){ toast(e.message); }
  renderView("registry");
}
/* server-detail variants: same registry actions, but refresh the manage screen */
async function mgApprove(s,t){ try{ await api(`/api/admin/registry/${s}/${t}/approve`,{method:"POST"}); toast("Tool onboarded."); }catch(e){ toast(e.message); } manageServer(s); }
async function mgRepin(s,t){ try{ await api(`/api/admin/registry/${s}/${t}/approve_drift`,{method:"POST"}); toast("Drift accepted and re-pinned."); }catch(e){ toast(e.message); } manageServer(s); }

/* ---- server detail / manage screen (opened from the Servers cards) ---- */
async function manageServer(name){
  stopLive();
  CURRENT="servers"; $("#pg-title").textContent="Server · "+name;
  $("#app-view").classList.remove("side-open"); buildSidebar();
  const view=$("#view");
  view.innerHTML=`<div class="panel"><div class="empty">Loading…</div></div>`;
  try{
    const [{servers},reg,toolsRes,cfg]=await Promise.all([
      api("/api/admin/servers"), tryApi("/api/admin/registry"),
      tryApi("/api/tools"), tryApi("/api/admin/config"),
    ]);
    const s=(servers||[]).find(x=>x.name===name);
    if(!s){ view.innerHTML=`<div class="panel"><div class="page-head"><div class="h-tt">
      <button class="btn btn-ghost btn-sm" style="margin-bottom:10px" onclick="go('servers')">← All servers</button>
      <h2 class="mono">${esc(name)}</h2></div></div><div class="empty">Server not found.</div></div>`; return; }
    const desc={}; if(toolsRes&&toolsRes.tools) toolsRes.tools.forEach(t=>{ if(t.server===name) desc[t.name]=t.description||""; });
    const entries=((reg&&reg.entries)||[]).filter(e=>e.server===name);
    const cmd=((cfg&&cfg.servers)||[]).find(x=>x.name===name);
    const appr=(t)=>t===0?'<span class="pill ok">Auto</span>':t===1?'<span class="pill info">Auto · write</span>':t===2?'<span class="pill warn">1 approver</span>':'<span class="pill crit">Two-person</span>';
    const statusPill=(st)=>st==="active"?'<span class="pill ok"><span class="dot ok"></span>Active</span>':st==="pending"?'<span class="pill warn">Pending</span>':'<span class="pill crit"><span class="dot crit pulse"></span>Quarantined</span>';
    const rows=entries.map(e=>{
      const hash=e.fingerprint?e.fingerprint.slice(0,4)+"…"+e.fingerprint.slice(-4):"—";
      const act=e.status==="pending"?`<button class="btn btn-primary btn-sm" onclick="mgApprove('${jsq(e.server)}','${jsq(e.tool)}')">Approve</button>`
        :e.status==="quarantined"?`<button class="btn btn-ghost btn-sm" onclick="mgRepin('${jsq(e.server)}','${jsq(e.tool)}')">Review drift · re-pin</button>`
        :'<span style="color:var(--text-3)">—</span>';
      return `<tr class="r-strip t${e.tier}"><td><div class="t-title">${esc(e.tool)}</div><div class="t-desc">${esc(desc[e.tool]||e.quarantine_reason||"")}</div></td>
        <td>${tierPill(e.tier)}</td><td>${appr(e.tier)}</td><td>${statusPill(e.status)}</td><td><span class="mono">${esc(hash)}</span></td><td class="num">${act}</td></tr>`;
    }).join("");
    view.innerHTML=`<div class="panel">
      <div class="page-head"><div class="h-tt">
        <button class="btn btn-ghost btn-sm" style="margin-bottom:10px" onclick="go('servers')">← All servers</button>
        <h2 class="mono">${esc(name)} ${s.breaker_open?'<span class="pill crit"><span class="dot crit pulse"></span>Circuit open</span>':'<span class="pill ok"><span class="dot ok"></span>Healthy</span>'}</h2>
        <p>Isolation zone for this backend domain. Every tool below is gateway-owned, SHA-256 hash-pinned, and risk-tiered by the registry — the server never declares its own tier. Credentials are injected per call and never reach the model.</p></div>
        <div class="h-actions"><button class="btn btn-ghost btn-sm" onclick="manageServer('${jsq(name)}')">Refresh</button></div></div>
      <div class="grid kpis-3" style="margin-bottom:16px">${kpiSm("tools","Tools",s.tools)}${kpiSm("power","Circuits open",s.breaker_open?1:0)}${kpiSm("shield","Recent failures",s.fails)}</div>
      <div class="grid grid2" style="margin-bottom:16px">
        <div class="card"><div class="card-head">${I.server}<h3>Inventory</h3></div><div class="card-body pad">
          <div class="stat-strip" style="padding:0 0 12px;gap:22px"><div class="s"><span class="n">${s.tools}</span><span class="l">Tools</span></div><div class="s"><span class="n">${s.active}</span><span class="l">Active</span></div><div class="s"><span class="n">${s.pending}</span><span class="l">Pending</span></div><div class="s"><span class="n">${s.quarantined}</span><span class="l">Quarantined</span></div></div>
          ${tierbars(s.tiers)}
          <div style="display:flex;gap:7px;margin-top:12px;flex-wrap:wrap">${[0,1,2,3].map(t=>`<span class="tier t${t}">T${t}: ${s.tiers[String(t)]||0}</span>`).join("")}</div></div></div>
        <div class="card"><div class="card-head">${I.sliders}<h3>Configuration</h3></div>${kvRows([
          ["Transport","stdio · isolated subprocess"],
          ["Launch command",cmd?esc(cmd.command):"—",true],
          ["Vault-managed credentials",s.managed_credentials?"yes · per-call dynamic secrets":"no"],
          ["Circuit breaker",s.breaker_open?'<span style="color:var(--crit)">open · cooling down</span>':"closed"],
          ["Recent failures",String(s.fails)],
        ])}</div>
      </div>
      ${sectionH("Tools inside this server","Every discovered tool — risk tier, approval requirement, onboarding status, and pinned digest")}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Tool</th><th>Risk tier</th><th>Approval</th><th>Status</th><th>Pinned digest</th><th class="num">Action</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="6"><div class="empty">No tools visible at your clearance.</div></td></tr>'}</tbody></table></div></div>`;
  }catch(e){
    view.innerHTML=`<div class="panel"><div class="empty">${e.status===403?"You do not have access to this section.":"Could not load — "+esc(e.message)}</div></div>`;
  }
}
function revokePrompt(){ const s=prompt("Revoke which identity (subject)?"); if(s) revoke(s.trim()); }
async function revoke(s){ try{ await api("/api/admin/revoke",{method:"POST",body:JSON.stringify({sub:s})}); toast("Identity revoked."); }catch(e){ toast(e.message); } renderView("identities"); }
async function unrevoke(s){ try{ await api("/api/admin/unrevoke",{method:"POST",body:JSON.stringify({sub:s})}); }catch(e){ toast(e.message); } renderView("identities"); }
async function unlock(s){ try{ await api("/api/admin/unlock",{method:"POST",body:JSON.stringify({sub:s})}); toast("Lockout cleared."); }catch(e){ toast(e.message); } renderView("identities"); }
async function engageKill(){ const s=$("#kill-scope").value.trim(); if(!s) return; try{ await api("/api/admin/killswitch/engage",{method:"POST",body:JSON.stringify({scope:s})}); toast("Kill switch engaged."); }catch(e){ toast(e.message); } renderView("killswitch"); }
async function releaseKill(s){ try{ await api("/api/admin/killswitch/release",{method:"POST",body:JSON.stringify({scope:s})}); }catch(e){ toast(e.message); } renderView("killswitch"); }

/* ---------------- shell chrome ---------------- */
const _ICON_MOON='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
const _ICON_SUN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
function applyTheme(t){ document.documentElement.dataset.theme = t==="paper"?"paper":""; const b=$("#theme-btn"); if(b) b.innerHTML = t==="paper"?_ICON_SUN:_ICON_MOON; }
function toggleTheme(){ const next=document.documentElement.dataset.theme==="paper"?"ink":"paper"; try{ localStorage.setItem("mcp-theme",next); }catch(e){} applyTheme(next); }
function toggleLang(){ const h=document.documentElement, rtl=h.dir!=="rtl"; h.dir=rtl?"rtl":"ltr"; h.lang=rtl?"ar":"en"; }
let _toastT;
function toast(msg){
  let t=$("#toast");
  if(!t){ t=document.createElement("div"); t.id="toast";
    t.style.cssText="position:fixed;inset-block-end:20px;inset-inline-end:20px;z-index:100;background:var(--surface);border:1px solid var(--line);color:var(--text);padding:11px 15px;border-radius:10px;box-shadow:var(--shadow);font-size:13px;max-width:340px;transition:opacity .2s";
    document.body.appendChild(t); }
  t.textContent=msg; t.style.opacity="1"; clearTimeout(_toastT); _toastT=setTimeout(()=>t.style.opacity="0",2800);
}

/* ---------------- boot ---------------- */
try{ applyTheme(localStorage.getItem("mcp-theme")||"ink"); }catch(e){ applyTheme("ink"); }
$("#ws-av").innerHTML=I.shield;
$("#pw-toggle").innerHTML=ICON_EYE;
$("#signin-btn").onclick=doSignin;
$("#pw-toggle").onclick=togglePw;
$("#mfa-btn").onclick=doMfa;
$("#mfa-back").onclick=mfaBack;
{ const rl=$("#reset-link"); if(rl) rl.onclick=()=>toast("يرجى التواصل مع مسؤول النظام لإعادة تعيين كلمة المرور."); }
$("#login-user").addEventListener("keydown",e=>{ if(e.key==="Enter"){ e.preventDefault(); $("#login-pass").focus(); } });
$("#login-pass").addEventListener("keydown",e=>{ if(e.key==="Enter"){ e.preventDefault(); doSignin(); } });
$("#login-otp").addEventListener("keydown",e=>{ if(e.key==="Enter"){ e.preventDefault(); doMfa(); } });
$("#login-otp").addEventListener("input",e=>{ e.target.value=e.target.value.replace(/\D/g,"").slice(0,6); });
// idle-activity listeners for auto-logout
["mousemove","keydown","click","scroll"].forEach(ev=>document.addEventListener(ev,()=>{ if(state.token) resetIdle(); },{passive:true}));
loadAuthInfo();
