import { useState } from "react";
import {
  ShieldAlert, ShieldCheck, CircleAlert, TriangleAlert, Info, Ban, LockOpen,
  UserX, RotateCw, Check, X, ChevronRight,
} from "lucide-react";
import { useApi } from "./useApi";
import { apiGet, apiPost } from "@/api";
import { toast } from "./toast";

// ── shared SnowUI primitives (match the reference tokens) ─────────────────────
const STATUS_COLOR: Record<string, string> = { Online: "#4AA785", Degraded: "#E5A000", Offline: "#D9534F" };
const SEV = { critical: "#D9534F", warning: "#E5A000", info: "#6B9FD4" } as const;
const TIER_COLOR = ["#4AA785", "#6B9FD4", "#E5A000", "#D9534F"];

function CardBox({ children, title, right }: { children: React.ReactNode; title?: string; right?: React.ReactNode }) {
  return (
    <div className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4">
      {(title || right) && <div className="flex items-center justify-between"><p className="text-sm font-normal text-black">{title}</p>{right}</div>}
      {children}
    </div>
  );
}
function Th({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <th className={`text-xs text-black/40 font-normal pb-3 pr-4 ${right ? "text-right" : "text-left"}`}>{children}</th>;
}
function Td({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <td className={`text-sm text-black py-3 pr-4 border-t border-black/5 align-middle ${right ? "text-right" : "text-left"}`}>{children}</td>;
}
function Empty({ label }: { label: string }) { return <div className="text-sm text-black/30 py-8 text-center">{label}</div>; }
function Head({ title, count }: { title: string; count?: string }) {
  return <div className="flex items-center justify-between"><h1 className="text-sm font-semibold text-black">{title}</h1>{count && <span className="text-xs text-black/40">{count}</span>}</div>;
}
function TierPill({ tier }: { tier: number }) {
  const label = ["read", "reversible", "human", "two-person"][tier] ?? `T${tier}`;
  return <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: TIER_COLOR[tier] + "22", color: TIER_COLOR[tier] }}>Tier {tier} · {label}</span>;
}
function StatusPill({ status }: { status: string }) {
  const c = status === "active" ? "#4AA785" : status === "pending" ? "#E5A000" : "#D9534F";
  return <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: c + "22", color: c }}>{status}</span>;
}
function fmtTime(ts?: number) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "—"; }
function fmtDate(ts?: number) { return ts ? new Date(ts * 1000).toLocaleString() : "—"; }

// ══════════════════════════════════════════════════════════════════════════════
// 1. APPROVALS — the HITL queue (approve / reject, two-person + SoD)
// ══════════════════════════════════════════════════════════════════════════════
export function ApprovalsPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ pending: any[] }>("/api/approvals", onAuthExpired);
  const pending = data?.pending ?? [];
  const act = async (id: string, kind: "approve" | "reject") => {
    try {
      const r = await apiPost(`/api/approvals/${id}/${kind}`);
      toast(kind === "approve"
        ? (r.status === "approved_and_executed" ? "Approved & executed." : `Vote recorded — ${r.remaining} more approval(s) needed.`)
        : "Request rejected.");
      reload();
    } catch (e: any) { toast(e.message || "Action failed", "err"); }
  };
  return (
    <>
      <Head title="Authorization queue" count={loading ? "…" : `${pending.length} pending`} />
      {pending.length === 0 ? <CardBox><Empty label="Queue clear — no actions awaiting approval." /></CardBox> : (
        <div className="flex flex-col gap-3">
          {pending.map((p) => {
            const got = (p.approvals || []).length, need = p.approvals_required || 1;
            const tainted = (p.taint || []).length > 0;
            return (
              <div key={p.id} className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-sm font-semibold text-black">{p.server}.{p.tool}</span>
                  <TierPill tier={p.tier} />
                  <span className="text-xs text-black/40">requested by {p.requester}</span>
                  {tainted && <span className="text-xs px-2 py-0.5 rounded-full flex items-center gap-1" style={{ background: "#D9534F22", color: "#D9534F" }}><TriangleAlert size={11} /> tainted input</span>}
                  <span className="ml-auto text-xs text-black/40">{fmtDate(p.created)}</span>
                </div>
                {p.preview && <p className="text-sm text-black/60">{p.preview}</p>}
                <pre className="text-xs text-black/70 bg-black/[0.03] rounded-lg p-3 overflow-x-auto">{JSON.stringify(p.arguments, null, 2)}</pre>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-black/40">{got} of {need} approval{need > 1 ? "s" : ""}{need > 1 ? " · two-person (SoD)" : ""}</span>
                  <div className="flex-1 h-[3px] bg-black/10 rounded-full overflow-hidden max-w-[160px]"><div className="h-full rounded-full bg-black/60" style={{ width: `${(got / need) * 100}%` }} /></div>
                  <div className="ml-auto flex gap-2">
                    <button onClick={() => act(p.id, "reject")} className="text-xs px-3 py-1.5 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1" style={{ color: "#D9534F" }}><X size={13} /> Reject</button>
                    <button onClick={() => act(p.id, "approve")} className="text-xs px-3 py-1.5 rounded-lg text-white bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1"><Check size={13} /> Approve</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. AUDIT — tamper-evident chain integrity + security event stream
// ══════════════════════════════════════════════════════════════════════════════
export function AuditPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ chain_ok: boolean; chain_status: string; records: any[] }>("/api/admin/audit", onAuthExpired);
  const [filter, setFilter] = useState("");
  const records = [...(data?.records ?? [])].reverse();
  const types = Array.from(new Set(records.map((r) => r.event))).sort();
  const q = query.toLowerCase();
  const rows = records.filter((r) =>
    (!filter || r.event === filter) &&
    (!q || (r.event || "").toLowerCase().includes(q) || (r.user || "").toLowerCase().includes(q) || (r.server || "").toLowerCase().includes(q)));
  const secColor = (ev: string) => /fail|error|revoked|quarantine|locked|denied|step_up/i.test(ev) ? "#D9534F"
    : /killswitch|drift|approval|onboard|retier|revoke/i.test(ev) ? "#E5A000" : "#4AA785";
  return (
    <>
      <Head title="Audit" count={`${records.length} events`} />
      <div className={`rounded-[20px] p-4 flex items-center gap-3 ${data?.chain_ok ? "" : ""}`} style={{ background: data?.chain_ok ? "#e3f5e5" : "#fbe6e6" }}>
        {data?.chain_ok ? <ShieldCheck size={18} style={{ color: "#4AA785" }} /> : <ShieldAlert size={18} style={{ color: "#D9534F" }} />}
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-black">{loading ? "Verifying…" : data?.chain_ok ? "Audit chain intact" : "Audit chain integrity FAILED"}</span>
          <span className="text-xs text-black/50">{data?.chain_status || "HMAC-SHA256 hash-chained, tamper-evident"}</span>
        </div>
        <button onClick={reload} className="ml-auto text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1"><RotateCw size={12} /> Re-verify</button>
      </div>
      <CardBox right={
        <select value={filter} onChange={(e) => setFilter(e.target.value)} className="text-xs text-black bg-white border border-black/10 rounded-lg px-2 py-1 outline-none">
          <option value="">All events</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      } title="Security events">
        {rows.length === 0 ? <Empty label="No events." /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>Time</Th><Th>Event</Th><Th>Identity</Th><Th>Target</Th><Th right>Digest</Th></tr></thead>
            <tbody>
              {rows.slice(0, 200).map((r, i) => (
                <tr key={i} className="hover:bg-black/[0.02]">
                  <Td><span className="text-black/60">{fmtTime(r.ts)}</span></Td>
                  <Td><span style={{ color: secColor(r.event) }}>{r.event}</span></Td>
                  <Td>{r.user || r.sub || r.by || "—"}</Td>
                  <Td><span className="text-black/60">{r.tool ? `${r.tool}${r.server ? " · " + r.server : ""}` : (r.server || r.scope || "—")}</span></Td>
                  <Td right><span className="text-black/30 text-xs font-mono">{(r.result_digest || r.hash || "").slice(0, 10) || "—"}</span></Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. IDENTITIES & ROLES — operator directory, ABAC ladder, revoke / unlock
// ══════════════════════════════════════════════════════════════════════════════
export function IdentitiesPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const ops = useApi<{ operators: any[] }>("/api/admin/operators", onAuthExpired);
  const pol = useApi<{ clearance_order: string[]; roles: Record<string, any> }>("/api/admin/policy", onAuthExpired);
  const mfa = useApi<{ operators: Record<string, boolean> }>("/api/admin/mfa", onAuthExpired);
  const q = query.toLowerCase();
  const rows = (ops.data?.operators ?? []).filter((o) => o.sub.toLowerCase().includes(q) || o.role.toLowerCase().includes(q));
  const act = async (path: string, sub: string, label: string) => {
    try { await apiPost(path, { sub }); toast(label); ops.reload(); } catch (e: any) { toast(e.message || "Failed", "err"); }
  };
  return (
    <>
      <Head title="Identities & Roles" count={`${rows.length} operators`} />
      <CardBox title="Operators">
        <div className="overflow-x-auto"><table className="w-full">
          <thead><tr><Th>Identity</Th><Th>Role</Th><Th>Clearance</Th><Th>Capabilities</Th><Th>MFA</Th><Th>Status</Th><Th right>Actions</Th></tr></thead>
          <tbody>
            {rows.map((o) => (
              <tr key={o.sub} className="hover:bg-black/[0.02]">
                <Td><span className="font-medium">{o.sub}</span> <span className="text-black/40">· {o.name}</span></Td>
                <Td><span className="text-black/60">{o.role}</span></Td>
                <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }}>{o.clearance}</span></Td>
                <Td><span className="text-xs text-black/50">tier ≤ {o.max_tool_tier}{o.can_approve ? " · approver" : ""}{o.admin ? " · admin" : ""}</span></Td>
                <Td>{mfa.data?.operators?.[o.sub] ? <span style={{ color: "#4AA785" }} className="text-xs">enrolled</span> : <span style={{ color: "#E5A000" }} className="text-xs">missing</span>}</Td>
                <Td>{o.revoked ? <span className="text-xs" style={{ color: "#D9534F" }}>revoked</span> : o.locked ? <span className="text-xs" style={{ color: "#E5A000" }}>locked ({o.fails})</span> : <span className="text-xs" style={{ color: "#4AA785" }}>active</span>}</Td>
                <Td right>
                  <div className="flex gap-1.5 justify-end">
                    {o.locked && <button onClick={() => act("/api/admin/unlock", o.sub, `Lockout cleared for ${o.sub}`)} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1"><LockOpen size={12} /> Unlock</button>}
                    {o.revoked
                      ? <button onClick={() => act("/api/admin/unrevoke", o.sub, `${o.sub} restored`)} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">Restore</button>
                      : <button onClick={() => act("/api/admin/revoke", o.sub, `${o.sub} revoked`)} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1" style={{ color: "#D9534F" }}><UserX size={12} /> Revoke</button>}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </CardBox>
      <CardBox title="ABAC role ladder">
        <div className="flex flex-col gap-2">
          <div className="text-xs text-black/40">Clearance order: {(pol.data?.clearance_order || []).join(" < ")}</div>
          {Object.entries(pol.data?.roles || {}).map(([role, rc]: any) => (
            <div key={role} className="flex items-center gap-3 text-sm py-1 border-t border-black/5">
              <span className="w-24 font-medium">{role}</span>
              <span className="text-xs text-black/50">max tool tier {rc.max_tool_tier}</span>
              {rc.can_approve && <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#e6f1fd" }}>can approve</span>}
              {rc.admin && <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }}>admin</span>}
            </div>
          ))}
        </div>
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. REGISTRY — tool governance: onboarding approve, drift re-pin, re-tier
// ══════════════════════════════════════════════════════════════════════════════
export function RegistryPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ entries: any[] }>("/api/admin/registry", onAuthExpired);
  const [tab, setTab] = useState<"all" | "pending" | "quarantined">("all");
  const q = query.toLowerCase();
  const all = data?.entries ?? [];
  const rows = all.filter((e) => (tab === "all" || e.status === tab) &&
    (`${e.server}.${e.tool}`).toLowerCase().includes(q));
  const counts = { pending: all.filter((e) => e.status === "pending").length, quarantined: all.filter((e) => e.status === "quarantined").length };
  const act = async (path: string, label: string, body?: any) => {
    try { await apiPost(path, body); toast(label); reload(); } catch (e: any) { toast(e.message || "Failed", "err"); }
  };
  const retier = (e: any) => {
    const v = prompt(`Risk tier for ${e.server}.${e.tool}\n0 read · 1 reversible · 2 human · 3 two-person`, String(e.tier));
    if (v === null) return;
    const tier = Number(v);
    if (![0, 1, 2, 3].includes(tier)) { toast("Tier must be 0–3", "err"); return; }
    act(`/api/admin/registry/${e.server}/${e.tool}/tier`, "Tier updated", { tier });
  };
  return (
    <>
      <Head title="Tool registry" count={loading ? "…" : `${all.length} tools`} />
      <div className="flex gap-2">
        {(["all", "pending", "quarantined"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`text-xs px-3 py-1 rounded-lg border ${tab === t ? "border-black/20 bg-black/[0.04]" : "border-black/10 hover:bg-black/[0.03]"}`}>
            {t[0].toUpperCase() + t.slice(1)}{t !== "all" && (counts as any)[t] ? ` (${(counts as any)[t]})` : ""}
          </button>
        ))}
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label="No tools in this view." /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>Tool</Th><Th>Tier</Th><Th>Status</Th><Th>Pinned digest</Th><Th right>Action</Th></tr></thead>
            <tbody>
              {rows.slice(0, 300).map((e) => (
                <tr key={e.server + e.tool} className="hover:bg-black/[0.02]">
                  <Td><span className="font-medium">{e.server}.{e.tool}</span>{e.quarantine_reason && <div className="text-xs" style={{ color: "#D9534F" }}>{e.quarantine_reason}</div>}</Td>
                  <Td><div className="flex items-center gap-2"><TierPill tier={e.tier} /><button onClick={() => retier(e)} className="text-xs text-black/40 hover:text-black underline">re-tier</button></div></Td>
                  <Td><StatusPill status={e.status} /></Td>
                  <Td><span className="text-black/30 text-xs font-mono">{(e.fingerprint || "").slice(0, 6)}…{(e.fingerprint || "").slice(-4)}</span></Td>
                  <Td right>
                    {e.status === "pending" ? <button onClick={() => act(`/api/admin/registry/${e.server}/${e.tool}/approve`, "Tool onboarded")} className="text-xs px-3 py-1 rounded-lg text-white bg-[#1C1C1C] hover:opacity-80">Approve onboarding</button>
                      : e.status === "quarantined" ? <button onClick={() => act(`/api/admin/registry/${e.server}/${e.tool}/approve_drift`, "Drift accepted & re-pinned")} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">Review drift · re-pin</button>
                        : <span className="text-black/20">—</span>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. KILL SWITCH — scoped containment (global / server / tool / user)
// ══════════════════════════════════════════════════════════════════════════════
export function KillSwitchPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const ks = useApi<{ active: string[] }>("/api/admin/killswitch", onAuthExpired);
  const srv = useApi<{ servers: any[] }>("/api/admin/servers", onAuthExpired);
  const [scope, setScope] = useState("");
  const active = ks.data?.active ?? [];
  const engage = async (s: string) => {
    if (!s) return;
    try { await apiPost("/api/admin/killswitch/engage", { scope: s }); toast(`Engaged: ${s}`); setScope(""); ks.reload(); }
    catch (e: any) { toast(e.message || "Failed", "err"); }
  };
  const release = async (s: string) => {
    try { await apiPost("/api/admin/killswitch/release", { scope: s }); toast(`Released: ${s}`); ks.reload(); }
    catch (e: any) { toast(e.message || "Failed", "err"); }
  };
  return (
    <>
      <Head title="Kill switch" count={`${active.length} active`} />
      <div className="rounded-[20px] p-4 flex items-center gap-3" style={{ background: active.length ? "#fbe6e6" : "#e3f5e5" }}>
        <ShieldAlert size={18} style={{ color: active.length ? "#D9534F" : "#4AA785" }} />
        <span className="text-sm font-semibold text-black">{active.length ? `Containment engaged — ${active.length} scope(s) blocking calls` : "No containment active — all traffic flowing"}</span>
      </div>
      <CardBox title="Engage containment">
        <div className="flex items-center gap-2 flex-wrap">
          <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="scope e.g. tool:postgres:drop_table or user:sara"
            className="flex-1 min-w-[240px] bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30" />
          <button onClick={() => engage(scope)} className="text-xs px-4 py-2 rounded-lg text-white bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1"><Ban size={13} /> Engage</button>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button onClick={() => engage("global")} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]" style={{ color: "#D9534F" }}>⨯ Global kill</button>
          {(srv.data?.servers || []).map((s) => (
            <button key={s.name} onClick={() => engage(`server:${s.name}`)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">Kill server:{s.name}</button>
          ))}
        </div>
      </CardBox>
      <CardBox title="Active scopes">
        {active.length === 0 ? <Empty label="Nothing contained." /> : (
          <div className="flex flex-col gap-2">
            {active.map((s) => (
              <div key={s} className="flex items-center gap-3 py-2 border-t border-black/5 first:border-t-0">
                <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#fbe6e6", color: "#D9534F" }}>blocked</span>
                <span className="text-sm font-mono">{s}</span>
                <button onClick={() => release(s)} className="ml-auto text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">Release</button>
              </div>
            ))}
          </div>
        )}
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. ANOMALY & ALERTS — real alerts from the detection engine
// ══════════════════════════════════════════════════════════════════════════════
export function AnomalyPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ alerts: any[]; summary: any }>("/api/admin/alerts", onAuthExpired);
  const alerts = data?.alerts ?? [];
  const sum = data?.summary ?? { critical: 0, warning: 0, info: 0 };
  const Icon = (s: string) => s === "critical" ? <CircleAlert size={16} style={{ color: SEV.critical }} /> : s === "warning" ? <TriangleAlert size={16} style={{ color: SEV.warning }} /> : <Info size={16} style={{ color: SEV.info }} />;
  return (
    <>
      <Head title="Anomaly & alerts" count={loading ? "…" : `${alerts.length} active`} />
      <div className="flex gap-3 flex-wrap">
        {[["Critical", sum.critical, "#fbe6e6", SEV.critical], ["Warning", sum.warning, "#fdf3e0", SEV.warning], ["Info", sum.info, "#e6f1fd", SEV.info]].map(([label, n, bg, c]: any) => (
          <div key={label} className="flex-1 min-w-[160px] rounded-[20px] p-6 flex flex-col gap-1" style={{ background: bg }}>
            <span className="text-sm text-black">{label}</span>
            <span className="text-2xl font-semibold" style={{ color: c }}>{n}</span>
          </div>
        ))}
      </div>
      <CardBox title="Active alerts" right={<button onClick={reload} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1"><RotateCw size={12} /> Re-evaluate</button>}>
        {alerts.length === 0 ? <Empty label="No anomalies detected — all clear." /> : (
          <div className="flex flex-col">
            {alerts.map((a, i) => (
              <div key={a.id + i} className={`flex items-start gap-3 py-3 ${i > 0 ? "border-t border-black/5" : ""}`}>
                <div className="mt-0.5">{Icon(a.severity)}</div>
                <div className="flex flex-col flex-1 min-w-0">
                  <span className="text-sm text-black">{a.title}{a.count > 1 ? ` · ×${a.count}` : ""}</span>
                  <span className="text-xs text-black/50">{a.detail}</span>
                </div>
                <span className="text-xs text-black/30 shrink-0">{a.source}</span>
              </div>
            ))}
          </div>
        )}
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. SESSIONS / INVESTIGATION — per-identity forensic timeline
// ══════════════════════════════════════════════════════════════════════════════
export function InvestigatePage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const { data, loading } = useApi<{ subjects: any[] }>("/api/admin/investigate", onAuthExpired);
  const [sel, setSel] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<any | null>(null);
  const q = query.toLowerCase();
  const subjects = (data?.subjects ?? []).filter((s) => s.subject.toLowerCase().includes(q));
  const open = async (subject: string) => {
    setSel(subject); setTimeline(null);
    const t = await apiGet(`/api/admin/investigate?subject=${encodeURIComponent(subject)}`);
    setTimeline(t);
  };
  return (
    <>
      <Head title="Session investigation" count={loading ? "…" : `${subjects.length} identities`} />
      <CardBox title="Activity by identity">
        {subjects.length === 0 ? <Empty label="No recorded activity." /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>Identity</Th><Th right>Events</Th><Th right>Tool calls</Th><Th right>Errors</Th><Th>Servers</Th><Th>Last seen</Th><Th right></Th></tr></thead>
            <tbody>
              {subjects.map((s) => (
                <tr key={s.subject} className="hover:bg-black/[0.02]">
                  <Td><span className="font-medium">{s.subject}</span>{s.live && <span className="ml-2 text-xs px-2 py-0.5 rounded-full" style={{ background: "#e3f5e5", color: "#4AA785" }}>live</span>}</Td>
                  <Td right>{s.events}</Td>
                  <Td right>{s.tool_calls}</Td>
                  <Td right><span style={{ color: s.errors ? "#D9534F" : undefined }}>{s.errors}</span></Td>
                  <Td><span className="text-black/50 text-xs">{(s.servers || []).join(", ") || "—"}</span></Td>
                  <Td><span className="text-black/60">{fmtTime(s.last_ts)}</span></Td>
                  <Td right><button onClick={() => open(s.subject)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1 ml-auto">Investigate <ChevronRight size={12} /></button></Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>
      {sel && (
        <div className="fixed inset-0 z-50 flex justify-end" style={{ background: "rgba(0,0,0,0.3)" }} onClick={() => setSel(null)}>
          <div className="h-full w-[440px] bg-white p-6 flex flex-col gap-4 overflow-y-auto" style={{ fontFamily: "Inter, sans-serif" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-black">Timeline · {sel}</span>
              <button onClick={() => setSel(null)} className="text-xs text-black/40 hover:text-black">Close</button>
            </div>
            {!timeline ? <Empty label="Loading…" /> : (
              <>
                <div className="text-xs text-black/50">{timeline.event_count} events · servers: {(timeline.servers || []).join(", ") || "—"} · tools: {(timeline.tools || []).length}</div>
                <div className="flex flex-col relative">
                  <div className="absolute left-[5px] top-2 bottom-2 w-px bg-black/10" />
                  {(timeline.timeline || []).slice(0, 120).map((t: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 py-2 pl-1 relative">
                      <span className="w-[11px] h-[11px] rounded-full mt-1 shrink-0 border-2 border-white" style={{ background: /fail|error|revoked|step_up/i.test(t.event) ? "#D9534F" : /killswitch|drift|approval/i.test(t.event) ? "#E5A000" : "#4AA785" }} />
                      <div className="flex flex-col min-w-0">
                        <span className="text-sm text-black">{t.event}{t.tool ? ` · ${t.tool}` : ""}{t.server ? ` (${t.server})` : ""}</span>
                        <span className="text-xs text-black/40">{fmtDate(t.ts)}{t.tier != null ? ` · tier ${t.tier}` : ""}{t.pii_masked ? ` · ${t.pii_masked} PII masked` : ""}{t.classification ? ` · ${t.classification}` : ""}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
