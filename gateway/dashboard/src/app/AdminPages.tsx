import { useEffect, useRef, useState } from "react";
import {
  ShieldAlert, ShieldCheck, CircleAlert, TriangleAlert, Info, Ban, LockOpen,
  UserX, RotateCw, Check, X, ChevronRight, MoreHorizontal, UserPlus, KeyRound,
  LogOut, Shield, Fingerprint, Eye,
} from "lucide-react";
import { useApi } from "./useApi";
import { apiGet, apiPost } from "@/api";
import { toast } from "./toast";
import { ConfirmModal, Field, GhostBtn, Modal, PrimaryBtn, SecretModal, SelectInput, TextInput } from "./ui";
import { SeeAsModal } from "./AdminExtras";
import { getUser } from "@/api";
import { t } from "./i18n";

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
  const label = [t("read", "قراءة"), t("reversible", "قابل للتراجع"), t("human", "بشري"), t("two-person", "شخصان")][tier] ?? `T${tier}`;
  return <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: TIER_COLOR[tier] + "22", color: TIER_COLOR[tier] }}>{t("Tier", "المستوى")} {tier} · {label}</span>;
}
function StatusPill({ status }: { status: string }) {
  const c = status === "active" ? "#4AA785" : status === "pending" ? "#E5A000" : "#D9534F";
  return <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: c + "22", color: c }}>{status}</span>;
}
function fmtTime(ts?: number) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "—"; }
function fmtDate(ts?: number) { return ts ? new Date(ts * 1000).toLocaleString(t("en", "ar")) : "—"; }

// ══════════════════════════════════════════════════════════════════════════════
// 1. APPROVALS — the HITL queue (approve / reject, two-person + SoD)
// ══════════════════════════════════════════════════════════════════════════════
const APPR_STATUS_COLOR: Record<string, string> = {
  approved: "#4AA785", rejected: "#D9534F", expired: "#E5A000", pending: "#6B9FD4",
};

// Queue health (A18): what is rotting right now, and how fast decisions actually happen.
// A request quietly aging toward its 24-hour TTL is a stalled action nobody is watching.
function ApprovalAging() {
  const { data } = useApi<any>("/api/admin/approvals/aging");
  if (!data || (!data.pending_count && !data.decided_samples)) return null;
  const mins = (s: number) => s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.round(s / 60)}m` : `${Math.round(s / 3600)}h`;
  const breach = data.breaching_sla > 0;
  return (
    <div className="rounded-[20px] p-4 flex items-center gap-6 flex-wrap"
      style={{ background: breach ? "#fdf3e0" : "#f9f9fa" }}>
      {breach && <TriangleAlert size={18} style={{ color: "#E5A000" }} />}
      <div className="flex flex-col">
        <span className="text-xs text-black/40">{t("Breaching SLA", "خرق اتفاقية مستوى الخدمة (SLA)")}</span>
        <span className="text-sm font-semibold" style={{ color: breach ? "#8a6100" : undefined }}>
          {data.breaching_sla} {t("of", "من")} {data.pending_count} (SLA {mins(data.sla_seconds)})
        </span>
      </div>
      <div className="flex flex-col">
        <span className="text-xs text-black/40">{t("Oldest waiting", "الأقدم انتظاراً")}</span>
        <span className="text-sm font-semibold">{data.oldest_seconds ? mins(data.oldest_seconds) : "—"}</span>
      </div>
      <div className="flex flex-col">
        <span className="text-xs text-black/40">{t("Median time to decide", "الوسيط الزمني لاتخاذ القرار")}</span>
        <span className="text-sm font-semibold">
          {data.decided_samples ? mins(data.median_decide_seconds) : "—"}
        </span>
      </div>
      <div className="flex flex-col">
        <span className="text-xs text-black/40">{t("p95 time to decide", "زمن اتخاذ القرار (p95)")}</span>
        <span className="text-sm font-semibold">
          {data.decided_samples ? mins(data.p95_decide_seconds) : "—"}
        </span>
      </div>
      <span className="text-xs text-black/40 ml-auto">
        {t("measured from the audit chain", "مُقاس من سلسلة التدقيق")} · {data.decided_samples} {t("decision(s)", "قرار(ات)")}
      </span>
    </div>
  );
}

export function ApprovalsPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ pending: any[] }>("/api/approvals", onAuthExpired);
  const [tab, setTab] = useState<"pending" | "history">("pending");
  const hist = useApi<{ history: any[] }>("/api/approvals/history", onAuthExpired);
  const pending = data?.pending ?? [];
  const history = hist.data?.history ?? [];
  const act = async (id: string, kind: "approve" | "reject") => {
    try {
      const r = await apiPost(`/api/approvals/${id}/${kind}`);
      toast(kind === "approve"
        ? (r.status === "approved_and_executed" ? t("Approved & executed.", "تمت الموافقة والتنفيذ.") : t(`Vote recorded — ${r.remaining} more approval(s) needed.`, `تم تسجيل التصويت — يلزم ${r.remaining} موافقة/موافقات إضافية.`))
        : t("Request rejected.", "تم رفض الطلب."));
      reload(); hist.reload();
    } catch (e: any) { toast(e.message || t("Action failed", "فشل الإجراء"), "err"); }
  };
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Authorization queue", "طابور التفويض")}</h1>
        <div className="flex gap-2">
          {(["pending", "history"] as const).map((tb) => (
            <button key={tb} onClick={() => tb === "history" ? (setTab(tb), hist.reload()) : setTab(tb)}
              className={`text-xs px-3 py-1 rounded-lg border ${tab === tb ? "border-black/20 bg-black/[0.07]" : "border-black/10 hover:bg-black/[0.08]"}`}>
              {tb === "pending" ? `${t("Pending", "قيد الانتظار")} (${pending.length})` : t("History", "السجل")}
            </button>
          ))}
        </div>
      </div>
      {tab === "pending" && <ApprovalAging />}
      {tab === "history" ? (
        history.length === 0 ? <CardBox><Empty label={t("No resolved approvals yet.", "لا توجد موافقات محسومة بعد.")} /></CardBox> : (
          <CardBox title={t("Resolved approvals — who decided what, when", "الموافقات المحسومة — من قرر ماذا ومتى")}>
            <div className="overflow-x-auto"><table className="w-full">
              <thead><tr><Th>{t("Action", "الإجراء")}</Th><Th>{t("Requester", "مقدّم الطلب")}</Th><Th>{t("Outcome", "النتيجة")}</Th><Th>{t("Signers", "الموقّعون")}</Th><Th right>{t("Resolved", "تاريخ الحسم")}</Th></tr></thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="hover:bg-black/[0.04]">
                    <Td><span className="font-medium">{h.server}.{h.tool}</span> <TierPill tier={h.tier} /></Td>
                    <Td>{h.requester}</Td>
                    <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: (APPR_STATUS_COLOR[h.status] || "#888") + "22", color: APPR_STATUS_COLOR[h.status] || "#888" }}>{h.status}</span></Td>
                    <Td><span className="text-xs text-black/50">{h.status === "rejected" ? t(`rejected by ${h.rejected_by || "—"}`, `مرفوض من قبل ${h.rejected_by || "—"}`) : h.status === "expired" ? t("auto-expired", "منتهي تلقائياً") : (h.approvals || []).join(", ") || "—"}</span></Td>
                    <Td right><span className="text-black/60">{fmtDate(h.resolved_at)}</span></Td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </CardBox>
        )
      ) : (
      pending.length === 0 ? <CardBox><Empty label={t("Queue clear — no actions awaiting approval.", "الطابور خالٍ — لا إجراءات بانتظار الموافقة.")} /></CardBox> : (
        <div className="flex flex-col gap-3">
          {pending.map((p) => {
            const got = (p.approvals || []).length, need = p.approvals_required || 1;
            const tainted = (p.taint || []).length > 0;
            return (
              <div key={p.id} className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-sm font-semibold text-black">{p.server}.{p.tool}</span>
                  <TierPill tier={p.tier} />
                  <span className="text-xs text-black/40">{t("requested by", "طلب من")} {p.requester}</span>
                  {tainted && <span className="text-xs px-2 py-0.5 rounded-full flex items-center gap-1" style={{ background: "#D9534F22", color: "#D9534F" }}><TriangleAlert size={11} /> {t("tainted input", "مدخل ملوّث")}</span>}
                  <span className="ml-auto text-xs text-black/40">{fmtDate(p.created)}</span>
                </div>
                {p.preview && <p className="text-sm text-black/60">{p.preview}</p>}
                <pre className="text-xs text-black/70 bg-black/[0.03] rounded-lg p-3 overflow-x-auto">{JSON.stringify(p.arguments, null, 2)}</pre>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-black/40">{got} {t("of", "من")} {need} {t(`approval${need > 1 ? "s" : ""}`, "موافقة")}{need > 1 ? t(" · two-person (SoD)", " · شخصان (فصل المهام)") : ""}</span>
                  <div className="flex-1 h-[3px] bg-black/10 rounded-full overflow-hidden max-w-[160px]"><div className="h-full rounded-full bg-black/60" style={{ width: `${(got / need) * 100}%` }} /></div>
                  <div className="ml-auto flex gap-2">
                    <button onClick={() => act(p.id, "reject")} className="text-xs px-3 py-1.5 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1" style={{ color: "#D9534F" }}><X size={13} /> {t("Reject", "رفض")}</button>
                    <button onClick={() => act(p.id, "approve")} className="text-xs px-3 py-1.5 rounded-lg text-white bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1"><Check size={13} /> {t("Approve", "موافقة")}</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )
      )}
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. AUDIT — tamper-evident chain integrity + security event stream
// ══════════════════════════════════════════════════════════════════════════════
// Investigation, not just a tail (A2). Server-side filters over the WHOLE chain,
// pagination, and CSV/JSON export — "what did khalid touch last Tuesday?" is now a
// question the console can answer, instead of an SSH session and a grep.
const PAGE_SIZE = 50;

export function AuditPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const [f, setF] = useState({ event: "", user: "", server: "", tool: "", text: "", since: "", until: "" });
  const [offset, setOffset] = useState(0);
  const { data: facets } = useApi<any>("/api/admin/audit/facets", onAuthExpired);

  const qs = new URLSearchParams();
  if (f.event) qs.set("event", f.event);
  if (f.user) qs.set("user", f.user);
  if (f.server) qs.set("server", f.server);
  if (f.tool) qs.set("tool", f.tool);
  if (f.text || query) qs.set("text", f.text || query);
  if (f.since) qs.set("since", String(Date.parse(f.since) / 1000));
  if (f.until) qs.set("until", String(Date.parse(f.until) / 1000));
  qs.set("limit", String(PAGE_SIZE));
  qs.set("offset", String(offset));

  const { data, loading, reload } = useApi<any>(`/api/admin/audit?${qs}`, onAuthExpired);
  const rows: any[] = data?.records ?? [];
  const total = data?.total ?? 0;

  const set = (k: string, v: string) => { setF({ ...f, [k]: v }); setOffset(0); };
  const clear = () => { setF({ event: "", user: "", server: "", tool: "", text: "", since: "", until: "" }); setOffset(0); };
  const active = Object.values(f).some(Boolean) || !!query;

  const exportAs = (fmt: "csv" | "json") => {
    const e = new URLSearchParams(qs);
    e.set("fmt", fmt); e.delete("limit"); e.delete("offset");
    // Same filters as the view on screen — you export what you are looking at.
    window.open(`/api/admin/audit/export?${e}`, "_blank");
  };

  const secColor = (ev: string) => /fail|error|revoked|quarantine|locked|denied|step_up/i.test(ev) ? "#D9534F"
    : /killswitch|drift|approval|onboard|retier|revoke|reject|maintenance/i.test(ev) ? "#E5A000" : "#4AA785";

  return (
    <>
      <Head title={t("Audit", "التدقيق")} count={loading ? "…" : `${total} ${t("matching events", "حدث مطابق")}`} />
      <div className="rounded-[20px] p-4 flex items-center gap-3" style={{ background: data?.chain_ok ? "#e3f5e5" : "#fbe6e6" }}>
        {data?.chain_ok ? <ShieldCheck size={18} style={{ color: "#4AA785" }} /> : <ShieldAlert size={18} style={{ color: "#D9534F" }} />}
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-black">{loading ? t("Verifying…", "جارٍ التحقق…") : data?.chain_ok ? t("Audit chain intact", "سلسلة التدقيق سليمة") : t("Audit chain integrity FAILED", "فشل تكامل سلسلة التدقيق")}</span>
          <span className="text-xs text-black/50">{data?.chain_status || t("HMAC-SHA256 hash-chained, tamper-evident", "مرتبطة بتجزئة HMAC-SHA256، مقاومة للتلاعب")}</span>
        </div>
        {/* Forces a FULL chain re-verification (the listing itself reads a short-lived
            cached result — an O(n) HMAC pass on every poll is what made the gateway slow). */}
        <button onClick={async () => {
          try {
            const v: any = await apiGet("/api/admin/audit/verify");
            toast(v.chain_ok ? t(`Chain verified — ${v.chain_status}`, `تم التحقق من السلسلة — ${v.chain_status}`) : t(`TAMPERING: ${v.chain_status}`, `تلاعب: ${v.chain_status}`),
              v.chain_ok ? "ok" : "err");
            reload();
          } catch (e: any) { toast(e?.message || t("Verification failed", "فشل التحقق"), "err"); }
        }} className="ml-auto text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1">
          <RotateCw size={12} /> {t("Re-verify", "إعادة التحقق")}
        </button>
      </div>

      <CardBox title={t("Filters", "المرشحات")}>
        <div className="flex gap-2 flex-wrap items-end">
          <Field label={t("Event", "الحدث")}>
            <SelectInput value={f.event} onChange={(e) => set("event", e.target.value)}>
              <option value="">{t("All events", "كل الأحداث")}</option>
              {(facets?.events || []).map((t: string) => <option key={t} value={t}>{t}</option>)}
            </SelectInput>
          </Field>
          <Field label={t("Identity", "الهوية")}>
            <SelectInput value={f.user} onChange={(e) => set("user", e.target.value)}>
              <option value="">{t("Anyone", "أي شخص")}</option>
              {(facets?.users || []).map((t: string) => <option key={t} value={t}>{t}</option>)}
            </SelectInput>
          </Field>
          <Field label={t("Server", "الخادم")}>
            <SelectInput value={f.server} onChange={(e) => set("server", e.target.value)}>
              <option value="">{t("Any server", "أي خادم")}</option>
              {(facets?.servers || []).map((t: string) => <option key={t} value={t}>{t}</option>)}
            </SelectInput>
          </Field>
          <Field label={t("Tool", "الأداة")}>
            <SelectInput value={f.tool} onChange={(e) => set("tool", e.target.value)}>
              <option value="">{t("Any tool", "أي أداة")}</option>
              {(facets?.tools || []).map((t: string) => <option key={t} value={t}>{t}</option>)}
            </SelectInput>
          </Field>
          <Field label={t("From", "من")}><TextInput type="datetime-local" value={f.since} onChange={(e) => set("since", e.target.value)} /></Field>
          <Field label={t("To", "إلى")}><TextInput type="datetime-local" value={f.until} onChange={(e) => set("until", e.target.value)} /></Field>
          <Field label={t("Contains text", "يحتوي على نص")}><TextInput value={f.text} onChange={(e) => set("text", e.target.value)} placeholder={t("free text", "نص حر")} /></Field>
          <div className="flex gap-2 ml-auto">
            {active && <GhostBtn onClick={clear}>{t("Clear", "مسح")}</GhostBtn>}
            <GhostBtn onClick={() => exportAs("csv")}>{t("Export CSV", "تصدير CSV")}</GhostBtn>
            <GhostBtn onClick={() => exportAs("json")}>{t("Export JSON", "تصدير JSON")}</GhostBtn>
          </div>
        </div>
      </CardBox>

      <CardBox title={t("Security events", "أحداث الأمان")}>
        {rows.length === 0 ? <Empty label={t("No events match these filters.", "لا توجد أحداث مطابقة لهذه المرشحات.")} /> : (
          <>
            <div className="overflow-x-auto"><table className="w-full">
              <thead><tr><Th>{t("Time", "الوقت")}</Th><Th>{t("Event", "الحدث")}</Th><Th>{t("Identity", "الهوية")}</Th><Th>{t("Target", "الهدف")}</Th><Th right>{t("Duration", "المدة")}</Th><Th right>{t("Digest", "البصمة")}</Th></tr></thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="hover:bg-black/[0.04]">
                    <Td><span className="text-black/60" title={fmtDate(r.ts)}>{fmtTime(r.ts)}</span></Td>
                    <Td><span style={{ color: secColor(r.event) }}>{r.event}</span></Td>
                    <Td>{r.user || r.sub || r.by || "—"}</Td>
                    <Td><span className="text-black/60">{r.tool ? `${r.tool}${r.server ? " · " + r.server : ""}` : (r.server || r.scope || "—")}</span></Td>
                    <Td right><span className="text-black/40">{r.duration_ms != null ? `${Math.round(r.duration_ms)}ms` : "—"}</span></Td>
                    <Td right><span className="text-black/30 text-xs font-mono">{(r.result_digest || r.hash || "").slice(0, 10) || "—"}</span></Td>
                  </tr>
                ))}
              </tbody>
            </table></div>
            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-black/40">
                {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} {t("of", "من")} {total}
              </span>
              <div className="flex gap-2">
                <GhostBtn onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>{t("← Newer", "← الأحدث")}</GhostBtn>
                <GhostBtn onClick={() => data?.has_more && setOffset(offset + PAGE_SIZE)}>{t("Older →", "الأقدم →")}</GhostBtn>
              </div>
            </div>
          </>
        )}
      </CardBox>
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. IDENTITIES & ROLES — operator directory, ABAC ladder, revoke / unlock
// ══════════════════════════════════════════════════════════════════════════════
function RowMenu({ items }: { items: { label: string; icon: React.ReactNode; danger?: boolean; onClick: () => void }[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="relative inline-block" ref={ref}>
      <button onClick={() => setOpen(!open)} className={`p-1.5 rounded-lg border border-black/10 hover:bg-black/[0.08] ${open ? "bg-black/[0.07]" : ""}`}>
        <MoreHorizontal size={14} className="text-black/60" />
      </button>
      {open && (
        <div className="absolute right-0 top-8 w-[210px] bg-white border border-black/10 rounded-xl shadow-lg p-1 z-40 flex flex-col">
          {items.map((it) => (
            <button key={it.label} onClick={() => { setOpen(false); it.onClick(); }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-left hover:bg-black/[0.08]"
              style={it.danger ? { color: "#D9534F" } : { color: "#000" }}>
              {it.icon} {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function IdentitiesPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const ops = useApi<{ operators: any[] }>("/api/admin/operators", onAuthExpired);
  const pol = useApi<{ clearance_order: string[]; roles: Record<string, any> }>("/api/admin/policy", onAuthExpired);
  const mfa = useApi<{ operators: Record<string, boolean> }>("/api/admin/mfa", onAuthExpired);
  const me = getUser()?.sub;
  const q = query.toLowerCase();
  const rows = (ops.data?.operators ?? []).filter((o) => o.sub.toLowerCase().includes(q) || o.role.toLowerCase().includes(q));
  const roles = Object.keys(pol.data?.roles || {});
  const clearances = pol.data?.clearance_order || [];

  const [createOpen, setCreateOpen] = useState(false);
  const [roleEdit, setRoleEdit] = useState<any | null>(null);
  const [offboard, setOffboard] = useState<any | null>(null);
  const [signout, setSignout] = useState<any | null>(null);
  const [mfaEnroll, setMfaEnroll] = useState<any | null>(null);
  const [pwReset, setPwReset] = useState<any | null>(null);
  const [seeAs, setSeeAs] = useState<string | null>(null);
  const [secret, setSecret] = useState<{ title: string; note: string; rows: { label: string; value: string }[] } | null>(null);

  const reloadAll = () => { ops.reload(); mfa.reload(); };
  const act = async (path: string, sub: string, label: string) => {
    try { await apiPost(path, { sub }); toast(label); reloadAll(); } catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };

  const doOffboard = async () => {
    if (!offboard) return;
    try {
      await apiPost(`/api/admin/operators/${offboard.sub}/offboard`);
      toast(t(`${offboard.sub} offboarded — sessions terminated, credentials purged.`, `تم إنهاء عمل ${offboard.sub} — أُنهيت الجلسات ومُسحت بيانات الاعتماد.`));
      setOffboard(null); reloadAll();
    } catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };
  const doSignout = async () => {
    if (!signout) return;
    try {
      await apiPost(`/api/admin/operators/${signout.sub}/signout`);
      toast(t(`${signout.sub} signed out everywhere — all tokens are dead.`, `تم تسجيل خروج ${signout.sub} من كل مكان — جميع الرموز أصبحت لاغية.`));
      setSignout(null); reloadAll();
    } catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };
  const doMfaEnroll = async () => {
    if (!mfaEnroll) return;
    const sub = mfaEnroll.sub;
    setMfaEnroll(null);
    try {
      const r = await apiPost(`/api/admin/mfa/${sub}/enroll`);
      setSecret({
        title: t(`Authenticator enrolled — ${sub}`, `تم تسجيل تطبيق المصادقة — ${sub}`),
        note: t("Add this to the operator's authenticator app now (any TOTP app; enter the secret or the URI).", "أضف هذا إلى تطبيق المصادقة الخاص بالمشغّل الآن (أي تطبيق TOTP؛ أدخل السر أو الرابط)."),
        rows: [{ label: t("TOTP secret", "سر TOTP"), value: r.secret }, { label: t("otpauth:// URI", "رابط otpauth://"), value: r.otpauth_uri }],
      });
      reloadAll();
    } catch (e: any) { toast(e.message || t("Enroll failed", "فشل التسجيل"), "err"); }
  };
  const doPwReset = async () => {
    if (!pwReset) return;
    const sub = pwReset.sub;
    setPwReset(null);
    try {
      const r = await apiPost(`/api/admin/operators/${sub}/reset_password`);
      setSecret({
        title: t(`Temporary password — ${sub}`, `كلمة مرور مؤقتة — ${sub}`),
        note: t("Hand it over out-of-band. The operator must rotate it at first login.", "سلّمها عبر قناة خارجية. يجب على المشغّل تغييرها عند أول تسجيل دخول."),
        rows: [{ label: t("Temporary password", "كلمة المرور المؤقتة"), value: r.temp_password }],
      });
      reloadAll();
    } catch (e: any) { toast(e.message || t("Reset failed", "فشلت إعادة التعيين"), "err"); }
  };

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Identities & Roles", "الهويات والأدوار")}</h1>
        <button onClick={() => setCreateOpen(true)}
          className="text-xs text-white px-3 py-1.5 rounded-lg bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1">
          <UserPlus size={13} /> {t("New operator", "مشغّل جديد")}
        </button>
      </div>
      <CardBox title={t("Operators", "المشغّلون")} right={<span className="text-xs text-black/40">{rows.length} {t("operators", "مشغّل")}</span>}>
        <div className="overflow-x-auto"><table className="w-full">
          <thead><tr><Th>{t("Identity", "الهوية")}</Th><Th>{t("Role", "الدور")}</Th><Th>{t("Clearance", "التصريح")}</Th><Th>{t("Capabilities", "الصلاحيات")}</Th><Th>{t("MFA", "المصادقة الثنائية")}</Th><Th>{t("Status", "الحالة")}</Th><Th right>{t("Actions", "الإجراءات")}</Th></tr></thead>
          <tbody>
            {rows.map((o) => (
              <tr key={o.sub} className="hover:bg-black/[0.04]">
                <Td><span className="font-medium">{o.sub}</span> <span className="text-black/40">· {o.name}</span>{o.sub === me && <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full" style={{ background: "#e6f1fd" }}>{t("you", "أنت")}</span>}</Td>
                <Td><span className="text-black/60">{o.role}</span></Td>
                <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }}>{o.clearance}</span></Td>
                <Td><span className="text-xs text-black/50">{t("tier", "المستوى")} ≤ {o.max_tool_tier}{o.can_approve ? t(" · approver", " · معتمِد") : ""}{o.admin ? t(" · admin", " · مدير") : ""}</span></Td>
                <Td>{mfa.data?.operators?.[o.sub] ? <span style={{ color: "#4AA785" }} className="text-xs">{t("enrolled", "مُسجَّل")}</span> : <span style={{ color: "#E5A000" }} className="text-xs">{t("missing", "غير مسجَّل")}</span>}</Td>
                <Td>{o.revoked ? <span className="text-xs" style={{ color: "#D9534F" }}>{t("revoked", "مُبطَل")}</span> : o.locked ? <span className="text-xs" style={{ color: "#E5A000" }}>{t("locked", "مقفل")} ({o.fails})</span> : <span className="text-xs" style={{ color: "#4AA785" }}>{t("active", "نشط")}</span>}</Td>
                <Td right>
                  <div className="flex gap-1.5 justify-end items-center">
                    {o.locked && <button onClick={() => act("/api/admin/unlock", o.sub, t(`Lockout cleared for ${o.sub}`, `تم إلغاء القفل عن ${o.sub}`))} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1"><LockOpen size={12} /> {t("Unlock", "إلغاء القفل")}</button>}
                    {o.revoked
                      ? <button onClick={() => act("/api/admin/unrevoke", o.sub, t(`${o.sub} restored`, `تمت استعادة ${o.sub}`))} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08]">{t("Restore", "استعادة")}</button>
                      : <button onClick={() => act("/api/admin/revoke", o.sub, t(`${o.sub} revoked`, `تم إبطال ${o.sub}`))} className="text-xs px-2.5 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1" style={{ color: "#D9534F" }}><UserX size={12} /> {t("Revoke", "إبطال")}</button>}
                    <RowMenu items={[
                      { label: t("See what their AI sees", "عرض ما يراه الذكاء الاصطناعي الخاص به"), icon: <Eye size={13} />, onClick: () => setSeeAs(o.sub) },
                      { label: t("Change role / clearance", "تغيير الدور / التصريح"), icon: <Shield size={13} />, onClick: () => setRoleEdit(o) },
                      { label: t("Enroll / reset MFA", "تسجيل / إعادة تعيين المصادقة الثنائية"), icon: <Fingerprint size={13} />, onClick: () => setMfaEnroll(o) },
                      { label: t("Reset password", "إعادة تعيين كلمة المرور"), icon: <KeyRound size={13} />, onClick: () => setPwReset(o) },
                      { label: t("Sign out everywhere", "تسجيل الخروج من كل مكان"), icon: <LogOut size={13} />, onClick: () => setSignout(o) },
                      { label: t("Offboard operator", "إنهاء عمل المشغّل"), icon: <UserX size={13} />, danger: true, onClick: () => setOffboard(o) },
                    ]} />
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </CardBox>
      <CardBox title={t("ABAC role ladder", "سلم أدوار ABAC")}>
        <div className="flex flex-col gap-2">
          <div className="text-xs text-black/40">{t("Clearance order:", "ترتيب التصاريح:")} {(pol.data?.clearance_order || []).join(" < ")}</div>
          {Object.entries(pol.data?.roles || {}).map(([role, rc]: any) => (
            <div key={role} className="flex items-center gap-3 text-sm py-1 border-t border-black/5">
              <span className="w-24 font-medium">{role}</span>
              <span className="text-xs text-black/50">{t("max tool tier", "أقصى مستوى للأداة")} {rc.max_tool_tier}</span>
              {rc.can_approve && <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#e6f1fd" }}>{t("can approve", "يمكنه الموافقة")}</span>}
              {rc.admin && <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }}>{t("admin", "مدير")}</span>}
            </div>
          ))}
        </div>
      </CardBox>

      {createOpen && (
        <CreateOperatorModal roles={roles} clearances={clearances}
          onClose={() => setCreateOpen(false)}
          onCreated={(r) => {
            setCreateOpen(false); reloadAll();
            setSecret({
              title: t(`Operator ${r.sub} created`, `تم إنشاء المشغّل ${r.sub}`),
              note: t("Hand the temporary password and authenticator enrollment over out-of-band. The password must be rotated at first login.", "سلّم كلمة المرور المؤقتة وتسجيل المصادقة عبر قناة خارجية. يجب تغيير كلمة المرور عند أول تسجيل دخول."),
              rows: [
                { label: t("Temporary password", "كلمة المرور المؤقتة"), value: r.temp_password },
                { label: t("TOTP secret", "سر TOTP"), value: r.totp_secret },
                { label: t("otpauth:// URI", "رابط otpauth://"), value: r.otpauth_uri },
              ],
            });
          }} />
      )}
      {roleEdit && (
        <RoleModal op={roleEdit} roles={roles} clearances={clearances}
          onClose={() => setRoleEdit(null)}
          onSaved={() => { setRoleEdit(null); reloadAll(); }} />
      )}
      {seeAs && <SeeAsModal sub={seeAs} onClose={() => setSeeAs(null)} />}
      {offboard && (
        <ConfirmModal title={t(`Offboard ${offboard.sub}?`, `إنهاء عمل ${offboard.sub}؟`)}
          body={<>{t("Removes", "يزيل")} <b>{offboard.sub}</b> {t("from the directory, terminates every session and token, and purges their password and authenticator. Their audit history is kept. This cannot be undone from the UI.", "من الدليل، وينهي جميع الجلسات والرموز، ويمسح كلمة مروره وتطبيق المصادقة. يُحتفظ بسجل التدقيق الخاص به. لا يمكن التراجع عن هذا من الواجهة.")}</>}
          confirmLabel={t("Offboard", "إنهاء العمل")} onCancel={() => setOffboard(null)} onConfirm={doOffboard} />
      )}
      {signout && (
        <ConfirmModal title={t(`Sign out ${signout.sub} everywhere?`, `تسجيل خروج ${signout.sub} من كل مكان؟`)}
          body={<>{t("Every console session, OAuth token, refresh token, live MCP session and previously-issued API key for", "تنتهي فوراً كل جلسة في وحدة التحكم، ورمز OAuth، ورمز التحديث، وجلسة MCP الحية، وأي مفتاح API صادر سابقاً لـ")} <b>{signout.sub}</b> {t("dies immediately. They can sign back in with their password + authenticator.", "يمكنه تسجيل الدخول مجدداً بكلمة المرور والمصادقة.")}</>}
          confirmLabel={t("Sign out everywhere", "تسجيل الخروج من كل مكان")} onCancel={() => setSignout(null)} onConfirm={doSignout} />
      )}
      {mfaEnroll && (
        <ConfirmModal title={t(`Enroll authenticator for ${mfaEnroll.sub}?`, `تسجيل مصادقة لـ ${mfaEnroll.sub}؟`)} danger={false}
          body={<>{t("Generates a fresh TOTP secret for", "يُنشئ سر TOTP جديداً لـ")} <b>{mfaEnroll.sub}</b> {t("and shows it once. Any previously enrolled authenticator stops working immediately.", "ويعرضه مرة واحدة. يتوقف أي تطبيق مصادقة مسجَّل سابقاً عن العمل فوراً.")}</>}
          confirmLabel={t("Enroll", "تسجيل")} onCancel={() => setMfaEnroll(null)} onConfirm={doMfaEnroll} />
      )}
      {pwReset && (
        <ConfirmModal title={t(`Reset password for ${pwReset.sub}?`, `إعادة تعيين كلمة المرور لـ ${pwReset.sub}؟`)} danger={false}
          body={<>{t("Issues a strong temporary password for", "يُصدر كلمة مرور مؤقتة قوية لـ")} <b>{pwReset.sub}</b> {t("(shown once) and forces rotation at their next login. Their current password stops working.", "(تُعرض مرة واحدة) ويفرض تغييرها عند تسجيل الدخول التالي. تتوقف كلمة مروره الحالية عن العمل.")}</>}
          confirmLabel={t("Reset password", "إعادة تعيين كلمة المرور")} onCancel={() => setPwReset(null)} onConfirm={doPwReset} />
      )}
      {secret && <SecretModal title={secret.title} note={secret.note} rows={secret.rows} onClose={() => setSecret(null)} />}
    </>
  );
}

function CreateOperatorModal({ roles, clearances, onClose, onCreated }: {
  roles: string[]; clearances: string[]; onClose: () => void; onCreated: (r: any) => void;
}) {
  const [sub, setSub] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState(roles.includes("employee") ? "employee" : roles[0] || "");
  const [clearance, setClearance] = useState(clearances.includes("restricted") ? "restricted" : clearances[0] || "");
  const [busy, setBusy] = useState(false);
  const create = async () => {
    if (!sub.trim()) { toast(t("Username is required", "اسم المستخدم مطلوب"), "err"); return; }
    setBusy(true);
    try {
      const r = await apiPost("/api/admin/operators", { sub: sub.trim(), name: name.trim(), role, clearance });
      onCreated(r);
    } catch (e: any) { toast(e.message || t("Create failed", "فشل الإنشاء"), "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title={t("New operator", "مشغّل جديد")} onClose={onClose}>
      <Field label={t("Username", "اسم المستخدم")}><TextInput value={sub} onChange={(e) => setSub(e.target.value)} placeholder={t("e.g. lina", "مثال: lina")} autoFocus /></Field>
      <Field label={t("Display name", "الاسم المعروض")}><TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. Lina (Analyst)", "مثال: لينا (محلل)")} /></Field>
      <Field label={t("Role", "الدور")}>
        <SelectInput value={role} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => <option key={r} value={r}>{r}</option>)}
        </SelectInput>
      </Field>
      <Field label={t("Clearance", "التصريح")}>
        <SelectInput value={clearance} onChange={(e) => setClearance(e.target.value)}>
          {clearances.map((c) => <option key={c} value={c}>{c}</option>)}
        </SelectInput>
      </Field>
      <p className="text-xs text-black/40 leading-4">{t("A temporary password and authenticator enrollment are generated and shown once — hand them over out-of-band.", "تُنشأ كلمة مرور مؤقتة وتسجيل مصادقة وتُعرضان مرة واحدة فقط — سلّمهما عبر قناة خارجية.")}</p>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>{t("Cancel", "إلغاء")}</GhostBtn>
        <PrimaryBtn onClick={create} disabled={busy}>{busy ? t("Creating…", "جارٍ الإنشاء…") : t("Create operator", "إنشاء مشغّل")}</PrimaryBtn>
      </div>
    </Modal>
  );
}

function RoleModal({ op, roles, clearances, onClose, onSaved }: {
  op: any; roles: string[]; clearances: string[]; onClose: () => void; onSaved: () => void;
}) {
  const [role, setRole] = useState(op.role);
  const [clearance, setClearance] = useState(op.clearance);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await apiPost(`/api/admin/operators/${op.sub}/role`, { role, clearance });
      toast(t(`${op.sub} is now ${role} / ${clearance}. Their sessions were terminated.`, `${op.sub} أصبح الآن ${role} / ${clearance}. أُنهيت جلساته.`));
      onSaved();
    } catch (e: any) { toast(e.message || t("Update failed", "فشل التحديث"), "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title={t(`Change role — ${op.sub}`, `تغيير الدور — ${op.sub}`)} onClose={onClose}>
      <Field label={t("Role", "الدور")}>
        <SelectInput value={role} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => <option key={r} value={r}>{r}</option>)}
        </SelectInput>
      </Field>
      <Field label={t("Clearance", "التصريح")}>
        <SelectInput value={clearance} onChange={(e) => setClearance(e.target.value)}>
          {clearances.map((c) => <option key={c} value={c}>{c}</option>)}
        </SelectInput>
      </Field>
      <p className="text-xs text-black/40 leading-4">{t("Applying a role change signs the operator out everywhere so no session keeps the old privileges.", "يؤدي تطبيق تغيير الدور إلى تسجيل خروج المشغّل من كل مكان حتى لا تحتفظ أي جلسة بالصلاحيات القديمة.")}</p>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>{t("Cancel", "إلغاء")}</GhostBtn>
        <PrimaryBtn onClick={save} disabled={busy}>{busy ? t("Saving…", "جارٍ الحفظ…") : t("Apply change", "تطبيق التغيير")}</PrimaryBtn>
      </div>
    </Modal>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. REGISTRY — tool governance: onboarding approve, drift re-pin, re-tier
// ══════════════════════════════════════════════════════════════════════════════
// Governance you can actually perform (A8/A24): read a tool's schema BEFORE approving it,
// see exactly what changed when drift quarantines it, REJECT one (previously an admin
// could only ever say yes), and manually quarantine on suspicion instead of waiting for a
// hash to drift. Re-tier is a real dialog, not window.prompt().
export function RegistryPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const { data, loading, reload } = useApi<{ entries: any[] }>("/api/admin/registry", onAuthExpired);
  const [tab, setTab] = useState<"all" | "pending" | "quarantined" | "rejected">("all");
  const [inspect, setInspect] = useState<any | null>(null);
  const [diff, setDiff] = useState<any | null>(null);
  const [retierOn, setRetierOn] = useState<any | null>(null);
  const [tierVal, setTierVal] = useState(0);
  const [reasonFor, setReasonFor] = useState<{ e: any; kind: "reject" | "quarantine" } | null>(null);
  const [reason, setReason] = useState("");

  const q = query.toLowerCase();
  const all = data?.entries ?? [];
  const rows = all.filter((e) => (tab === "all" || e.status === tab) &&
    (`${e.server}.${e.tool}`).toLowerCase().includes(q));
  const counts = {
    pending: all.filter((e) => e.status === "pending").length,
    quarantined: all.filter((e) => e.status === "quarantined").length,
    rejected: all.filter((e) => e.status === "rejected").length,
  };

  const act = async (path: string, label: string, body?: any) => {
    try { await apiPost(path, body); toast(label); reload(); }
    catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };

  const openDiff = async (e: any) => {
    try { setDiff(await apiGet(`/api/admin/registry/${e.server}/${e.tool}/diff`)); }
    catch { toast(t("No pending drift for this tool", "لا يوجد انحراف معلّق لهذه الأداة"), "err"); }
  };

  const submitReason = async () => {
    if (!reasonFor) return;
    if (reason.trim().length < 3) { toast(t("A reason is required", "السبب مطلوب"), "err"); return; }
    const { e, kind } = reasonFor;
    await act(`/api/admin/registry/${e.server}/${e.tool}/${kind}`,
      kind === "reject" ? t("Tool rejected — it cannot be called and will not resurrect", "تم رفض الأداة — لا يمكن استدعاؤها ولن تُستعاد")
                        : t("Tool quarantined", "تم عزل الأداة"), { reason: reason.trim() });
    setReasonFor(null); setReason("");
  };

  const TAB_LABEL: Record<string, string> = { all: t("All", "الكل"), pending: t("Pending", "قيد الانتظار"), quarantined: t("Quarantined", "معزول"), rejected: t("Rejected", "مرفوض") };

  return (
    <>
      <Head title={t("Tool registry", "سجل الأدوات")} count={loading ? "…" : `${all.length} ${t("tools", "أداة")}`} />
      <div className="flex gap-2">
        {(["all", "pending", "quarantined", "rejected"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`text-xs px-3 py-1 rounded-lg border ${tab === t ? "border-black/20 bg-black/[0.07]" : "border-black/10 hover:bg-black/[0.08]"}`}>
            {TAB_LABEL[t]}{t !== "all" && (counts as any)[t] ? ` (${(counts as any)[t]})` : ""}
          </button>
        ))}
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label={t("No tools in this view.", "لا توجد أدوات في هذا العرض.")} /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>{t("Tool", "الأداة")}</Th><Th>{t("Tier", "المستوى")}</Th><Th>{t("Status", "الحالة")}</Th><Th>{t("Pinned digest", "البصمة المثبَّتة")}</Th><Th right>{t("Action", "الإجراء")}</Th></tr></thead>
            <tbody>
              {rows.slice(0, 300).map((e) => (
                <tr key={e.server + e.tool} className="hover:bg-black/[0.04]">
                  <Td>
                    <button onClick={() => setInspect(e)} className="font-medium hover:underline text-left">
                      {e.server}.{e.tool}
                    </button>
                    {e.quarantine_reason && <div className="text-xs" style={{ color: "#D9534F" }}>{e.quarantine_reason}</div>}
                  </Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <TierPill tier={e.tier} />
                      <button onClick={() => { setRetierOn(e); setTierVal(e.tier); }}
                        className="text-xs text-black/40 hover:text-black underline">{t("re-tier", "إعادة التصنيف")}</button>
                    </div>
                  </Td>
                  <Td><StatusPill status={e.status} /></Td>
                  <Td><span className="text-black/30 text-xs font-mono">{(e.fingerprint || "").slice(0, 6)}…{(e.fingerprint || "").slice(-4)}</span></Td>
                  <Td right>
                    <div className="flex gap-2 justify-end flex-wrap">
                      <GhostBtn onClick={() => setInspect(e)}>{t("Inspect", "فحص")}</GhostBtn>
                      {e.status === "pending" && (
                        <>
                          <GhostBtn danger onClick={() => { setReasonFor({ e, kind: "reject" }); setReason(""); }}>{t("Reject", "رفض")}</GhostBtn>
                          <PrimaryBtn onClick={() => act(`/api/admin/registry/${e.server}/${e.tool}/approve`, t("Tool onboarded", "تم إدماج الأداة"))}>{t("Approve", "موافقة")}</PrimaryBtn>
                        </>
                      )}
                      {e.status === "quarantined" && (
                        e.has_drift
                          ? <PrimaryBtn onClick={() => openDiff(e)}>{t("Review drift", "مراجعة الانحراف")}</PrimaryBtn>
                          : <GhostBtn onClick={() => act(`/api/admin/registry/${e.server}/${e.tool}/unquarantine`, t("Quarantine released", "تم رفع العزل"))}>{t("Release", "رفع العزل")}</GhostBtn>
                      )}
                      {e.status === "active" && (
                        <GhostBtn danger onClick={() => { setReasonFor({ e, kind: "quarantine" }); setReason(""); }}>{t("Quarantine", "عزل")}</GhostBtn>
                      )}
                      {e.status === "rejected" && (
                        <GhostBtn onClick={() => act(`/api/admin/registry/${e.server}/${e.tool}/reinstate`, t("Back to pending", "أُعيدت إلى قيد الانتظار"))}>{t("Reinstate", "إعادة الإدراج")}</GhostBtn>
                      )}
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>

      {/* Read the tool before you approve it — approving a hash you cannot inspect is not governance. */}
      {inspect && (
        <Modal title={`${inspect.server}.${inspect.tool}`} onClose={() => setInspect(null)} width={620}>
          <div className="flex items-center gap-2">
            <TierPill tier={inspect.tier} /><StatusPill status={inspect.status} />
            <span className="text-xs text-black/30 font-mono ml-auto">{inspect.fingerprint}</span>
          </div>
          <Field label={t("Description", "الوصف")}>
            <div className="text-sm text-black/70 bg-black/[0.03] rounded-lg p-3">
              {inspect.description || <span className="text-black/30">{t("(none)", "(لا شيء)")}</span>}
            </div>
          </Field>
          <Field label={t("Input schema (what the model may send)", "مخطط الإدخال (ما يمكن أن يرسله النموذج)")}>
            <pre className="text-xs bg-black/[0.03] rounded-lg p-3 overflow-auto max-h-[40vh] font-mono">
              {JSON.stringify(inspect.schema || {}, null, 2)}
            </pre>
          </Field>
          {inspect.status === "pending" && (
            <div className="flex gap-2 justify-end">
              <GhostBtn danger onClick={() => { setReasonFor({ e: inspect, kind: "reject" }); setReason(""); setInspect(null); }}>{t("Reject", "رفض")}</GhostBtn>
              <PrimaryBtn onClick={() => { act(`/api/admin/registry/${inspect.server}/${inspect.tool}/approve`, t("Tool onboarded", "تم إدماج الأداة")); setInspect(null); }}>
                {t("Approve onboarding", "الموافقة على الإدماج")}
              </PrimaryBtn>
            </div>
          )}
        </Modal>
      )}

      {/* What actually CHANGED — re-pinning a hash you haven't read is rubber-stamping. */}
      {diff && (
        <Modal title={t(`Definition drift · ${diff.server}.${diff.tool}`, `انحراف التعريف · ${diff.server}.${diff.tool}`)} onClose={() => setDiff(null)} width={720}>
          <div className="rounded-xl p-3 text-xs leading-5" style={{ background: "#fdf3e0", color: "#8a6100" }}>
            {t("This tool's definition changed after it was pinned. A rug-pull looks exactly like this. Read the diff — a new parameter or a rewritten description can turn a safe tool into an exfiltration path.", "تغيّر تعريف هذه الأداة بعد تثبيتها. هذا هو الشكل الدقيق لهجوم rug-pull. اقرأ الفرق — فمعامل جديد أو وصف مُعاد صياغته قد يحوّل أداة آمنة إلى مسار لتسريب البيانات.")}
          </div>
          <div className="text-xs text-black/50">{t("Changed:", "تغيّر:")} {diff.changed_fields.join(", ") || t("nothing", "لا شيء")}</div>
          <div className="flex gap-3">
            <div className="flex-1 min-w-0">
              <span className="text-xs text-black/50">{t("Pinned (trusted)", "مثبَّت (موثوق)")}</span>
              <pre className="text-xs bg-black/[0.03] rounded-lg p-3 overflow-auto max-h-[40vh] font-mono mt-1">
                {JSON.stringify(diff.old, null, 2)}
              </pre>
            </div>
            <div className="flex-1 min-w-0">
              <span className="text-xs" style={{ color: "#B03A36" }}>{t("Proposed (new)", "مقترَح (جديد)")}</span>
              <pre className="text-xs rounded-lg p-3 overflow-auto max-h-[40vh] font-mono mt-1" style={{ background: "#fdeaea" }}>
                {JSON.stringify(diff.new, null, 2)}
              </pre>
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setDiff(null)}>{t("Leave quarantined", "إبقاء معزولة")}</GhostBtn>
            <GhostBtn danger onClick={() => { setReasonFor({ e: diff, kind: "reject" }); setReason(""); setDiff(null); }}>{t("Reject tool", "رفض الأداة")}</GhostBtn>
            <PrimaryBtn onClick={() => { act(`/api/admin/registry/${diff.server}/${diff.tool}/approve_drift`, t("Drift accepted & re-pinned", "تم قبول الانحراف وإعادة التثبيت")); setDiff(null); }}>
              {t("Accept & re-pin", "قبول وإعادة التثبيت")}
            </PrimaryBtn>
          </div>
        </Modal>
      )}

      {retierOn && (
        <Modal title={t(`Risk tier · ${retierOn.server}.${retierOn.tool}`, `مستوى الخطورة · ${retierOn.server}.${retierOn.tool}`)} onClose={() => setRetierOn(null)}>
          <Field label={t("Tier", "المستوى")}>
            <SelectInput value={tierVal} onChange={(e) => setTierVal(Number(e.target.value))}>
              <option value={0}>{t("0 — read only", "0 — قراءة فقط")}</option>
              <option value={1}>{t("1 — reversible write", "1 — كتابة قابلة للتراجع")}</option>
              <option value={2}>{t("2 — human approval", "2 — موافقة بشرية")}</option>
              <option value={3}>{t("3 — two-person approval", "3 — موافقة شخصين")}</option>
            </SelectInput>
          </Field>
          <p className="text-xs text-black/40">
            {t("The tier decides whether a call runs, pauses for one approver, or needs two.", "يحدد المستوى ما إذا كان الاستدعاء يُنفَّذ، أو يتوقف بانتظار معتمِد واحد، أو يحتاج إلى اثنين.")}
          </p>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setRetierOn(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={() => { act(`/api/admin/registry/${retierOn.server}/${retierOn.tool}/tier`, t("Tier updated", "تم تحديث المستوى"), { tier: tierVal }); setRetierOn(null); }}>
              {t("Save tier", "حفظ المستوى")}
            </PrimaryBtn>
          </div>
        </Modal>
      )}

      {reasonFor && (
        <Modal title={reasonFor.kind === "reject"
          ? t(`Reject ${reasonFor.e.server}.${reasonFor.e.tool}?`, `رفض ${reasonFor.e.server}.${reasonFor.e.tool}؟`)
          : t(`Quarantine ${reasonFor.e.server}.${reasonFor.e.tool}?`, `عزل ${reasonFor.e.server}.${reasonFor.e.tool}؟`)} onClose={() => setReasonFor(null)}>
          <p className="text-xs text-black/60 leading-5">
            {reasonFor.kind === "reject"
              ? t("The tool stays known but permanently inactive, and re-discovery will not resurrect it. You can reinstate it later.", "تبقى الأداة معروفة لكنها معطّلة بشكل دائم، ولن يُعيدها إعادة الاكتشاف. يمكنك إعادة إدراجها لاحقاً.")
              : t("The tool stops being callable immediately. Use this when you suspect a tool but its hash has not drifted.", "تتوقف الأداة عن كونها قابلة للاستدعاء فوراً. استخدم هذا عندما تشتبه في أداة لكن بصمتها لم تنحرف.")}
          </p>
          <Field label={t("Reason (recorded in the audit chain)", "السبب (يُسجَّل في سلسلة التدقيق)")}>
            <TextInput value={reason} onChange={(e) => setReason(e.target.value)}
              placeholder={t("e.g. exposes bulk export; not approved for this deployment", "مثال: يكشف تصديراً جماعياً؛ غير معتمد لهذا النشر")} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setReasonFor(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn danger onClick={submitReason}>
              {reasonFor.kind === "reject" ? t("Reject tool", "رفض الأداة") : t("Quarantine tool", "عزل الأداة")}
            </PrimaryBtn>
          </div>
        </Modal>
      )}
    </>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. KILL SWITCH — scoped containment (global / server / tool / user)
// ══════════════════════════════════════════════════════════════════════════════
// The most powerful button in the product. Until Phase 2 it was a free-text box and a
// one-click "Global kill" with no confirmation, no reason, and no way to un-forget it:
// a typo silently protected nothing, and a global kill left no trace of WHY 300 people
// were cut off. Now: scope pickers, a mandatory reason, an optional auto-release, and a
// confirmation that states the blast radius (A7).
function scopeBlastRadius(scope: string): string {
  if (scope === "global") return t("EVERY user and EVERY tool on the gateway — all 300+ staff.", "كل مستخدم وكل أداة على البوابة — أكثر من 300 موظف.");
  if (scope.startsWith("server:")) return t(`every tool on the ${scope.slice(7)} server, for all users.`, `كل أداة على خادم ${scope.slice(7)}، لجميع المستخدمين.`);
  if (scope.startsWith("tool:")) return t(`one tool (${scope.slice(5)}), for all users.`, `أداة واحدة (${scope.slice(5)})، لجميع المستخدمين.`);
  if (scope.startsWith("user:")) return t(`every tool call by ${scope.slice(5)}.`, `كل استدعاء أداة من قبل ${scope.slice(5)}.`);
  return t("the selected scope.", "النطاق المحدد.");
}

export function KillSwitchPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const ks = useApi<{ active: string[]; details: any[]; scopes: any }>("/api/admin/killswitch", onAuthExpired);
  const [kind, setKind] = useState<"global" | "server" | "tool" | "user">("server");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);

  const details = ks.data?.details ?? [];
  const opts = ks.data?.scopes ?? { servers: [], tools: [], users: [] };
  const scope = kind === "global" ? "global" : target ? `${kind}:${target}` : "";

  const doEngage = async () => {
    setConfirm(null);
    try {
      await apiPost("/api/admin/killswitch/engage", {
        scope, reason: reason.trim(), ttl_minutes: ttl ? Number(ttl) : null,
      });
      toast(t(`Engaged: ${scope}`, `تم التفعيل: ${scope}`));
      setTarget(""); setReason(""); setTtl("");
      ks.reload();
    } catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };

  const askEngage = () => {
    if (!scope) { toast(t("Pick a scope first", "اختر نطاقاً أولاً"), "err"); return; }
    if (reason.trim().length < 3) { toast(t("A reason is required — containment must say why", "السبب مطلوب — يجب أن يوضح الاحتواء السبب"), "err"); return; }
    setConfirm(scope);
  };

  const release = async (s: string) => {
    try { await apiPost("/api/admin/killswitch/release", { scope: s }); toast(t(`Released: ${s}`, `تم التحرير: ${s}`)); ks.reload(); }
    catch (e: any) { toast(e.message || t("Failed", "فشل"), "err"); }
  };

  const targets = kind === "server" ? opts.servers : kind === "tool" ? opts.tools : opts.users;
  const KIND_LABEL: Record<string, string> = { server: t("server", "الخادم"), tool: t("tool", "الأداة"), user: t("user", "المستخدم") };

  return (
    <>
      <Head title={t("Kill switch", "مفتاح الإيقاف الطارئ")} count={`${details.length} ${t("active", "نشط")}`} />
      <div className="rounded-[20px] p-4 flex items-center gap-3" style={{ background: details.length ? "#fbe6e6" : "#e3f5e5" }}>
        <ShieldAlert size={18} style={{ color: details.length ? "#D9534F" : "#4AA785" }} />
        <span className="text-sm font-semibold text-black">
          {details.length ? t(`Containment engaged — ${details.length} scope(s) blocking calls`, `الاحتواء مفعّل — ${details.length} نطاق(ات) تحظر الاستدعاءات`)
                          : t("No containment active — all traffic flowing", "لا يوجد احتواء نشط — كل حركة المرور تتدفق")}
        </span>
      </div>

      <CardBox title={t("Engage containment", "تفعيل الاحتواء")}>
        <div className="flex gap-2 flex-wrap items-end">
          <Field label={t("Scope type", "نوع النطاق")}>
            <SelectInput value={kind} onChange={(e) => { setKind(e.target.value as any); setTarget(""); }}>
              <option value="server">{t("Server", "خادم")}</option>
              <option value="tool">{t("Tool", "أداة")}</option>
              <option value="user">{t("User", "مستخدم")}</option>
              <option value="global">{t("Global (everything)", "عام (كل شيء)")}</option>
            </SelectInput>
          </Field>
          {kind !== "global" && (
            <Field label={t(`Which ${kind}?`, `أي ${KIND_LABEL[kind] || kind}؟`)}>
              <SelectInput value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">{t("Select…", "اختر…")}</option>
                {(targets || []).map((t: string) => <option key={t} value={t}>{t}</option>)}
              </SelectInput>
            </Field>
          )}
          <Field label={t("Auto-release after (minutes, optional)", "التحرير التلقائي بعد (دقائق، اختياري)")}>
            <TextInput type="number" min={1} max={10080} value={ttl} placeholder={t("never", "أبداً")}
              onChange={(e) => setTtl(e.target.value)} />
          </Field>
        </div>
        <Field label={t("Reason (required — recorded in the audit chain)", "السبب (مطلوب — يُسجَّل في سلسلة التدقيق)")}>
          <TextInput value={reason} onChange={(e) => setReason(e.target.value)}
            placeholder={t("e.g. suspected rug-pull on gitea; contained pending review", "مثال: اشتباه بهجوم rug-pull على gitea؛ احتواء بانتظار المراجعة")} />
        </Field>
        <div className="flex items-center justify-between">
          <span className="text-xs text-black/40">
            {scope ? <>{t("Will block:", "سيحظر:")} <b className="text-black/60">{scopeBlastRadius(scope)}</b></>
                   : t("Pick a scope to see the blast radius.", "اختر نطاقاً لرؤية نطاق التأثير.")}
          </span>
          <PrimaryBtn danger onClick={askEngage}>
            <span className="flex items-center gap-1"><Ban size={13} /> {t("Engage containment", "تفعيل الاحتواء")}</span>
          </PrimaryBtn>
        </div>
      </CardBox>

      <CardBox title={t("Active scopes", "النطاقات النشطة")}>
        {details.length === 0 ? <Empty label={t("Nothing contained.", "لا شيء محتوى.")} /> : (
          <div className="flex flex-col gap-2">
            {details.map((d) => (
              <div key={d.scope} className="flex items-start gap-3 py-3 border-t border-black/5 first:border-t-0">
                <span className="text-xs px-2 py-0.5 rounded-full shrink-0" style={{ background: "#fbe6e6", color: "#D9534F" }}>{t("blocked", "محظور")}</span>
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-sm font-mono">{d.scope}</span>
                  <span className="text-xs text-black/50">
                    {d.reason || t("(no reason recorded)", "(لا يوجد سبب مسجَّل)")} — {t("by", "بواسطة")} {d.by || "?"}
                    {d.ts ? ` · ${new Date(d.ts * 1000).toLocaleString(t("en", "ar"))}` : ""}
                  </span>
                  {d.expires && (
                    <span className="text-xs" style={{ color: "#8a6100" }}>
                      {t("auto-releases", "يُحرَّر تلقائياً في")} {new Date(d.expires * 1000).toLocaleString(t("en", "ar"))}
                    </span>
                  )}
                </div>
                <button onClick={() => release(d.scope)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] shrink-0">{t("Release", "تحرير")}</button>
              </div>
            ))}
          </div>
        )}
      </CardBox>

      {confirm && (
        <ConfirmModal
          title={confirm === "global" ? t("Engage a GLOBAL kill switch?", "تفعيل مفتاح إيقاف طارئ عام؟") : t(`Contain ${confirm}?`, `احتواء ${confirm}؟`)}
          body={<>
            {t("This immediately blocks", "يحظر هذا فوراً")} <b>{scopeBlastRadius(confirm)}</b>
            <br /><br />{t("Reason:", "السبب:")} <i>{reason}</i>
            {ttl ? <><br />{t(`Auto-releases after ${ttl} minute(s).`, `يُحرَّر تلقائياً بعد ${ttl} دقيقة/دقائق.`)}</>
                 : <><br /><b>{t("No auto-release", "لا تحرير تلقائي")}</b> — {t("it stays until an admin releases it.", "يبقى حتى يُحرره أحد المديرين.")}</>}
          </>}
          confirmLabel={t("Engage containment", "تفعيل الاحتواء")}
          onCancel={() => setConfirm(null)}
          onConfirm={doEngage} />
      )}
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
      <Head title={t("Anomaly & alerts", "الشذوذ والتنبيهات")} count={loading ? "…" : `${alerts.length} ${t("active", "نشط")}`} />
      <div className="flex gap-3 flex-wrap">
        {[[t("Critical", "حرج"), sum.critical, "#fbe6e6", SEV.critical], [t("Warning", "تحذير"), sum.warning, "#fdf3e0", SEV.warning], [t("Info", "معلومات"), sum.info, "#e6f1fd", SEV.info]].map(([label, n, bg, c]: any) => (
          <div key={label} className="flex-1 min-w-[160px] rounded-[20px] p-6 flex flex-col gap-1" style={{ background: bg }}>
            <span className="text-sm text-black">{label}</span>
            <span className="text-2xl font-semibold" style={{ color: c }}>{n}</span>
          </div>
        ))}
      </div>
      <CardBox title={t("Active alerts", "التنبيهات النشطة")} right={<button onClick={reload} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1"><RotateCw size={12} /> {t("Re-evaluate", "إعادة التقييم")}</button>}>
        {alerts.length === 0 ? <Empty label={t("No anomalies detected — all clear.", "لم يُكتشف أي شذوذ — كل شيء سليم.")} /> : (
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
      <Head title={t("Session investigation", "تحقيق الجلسات")} count={loading ? "…" : `${subjects.length} ${t("identities", "هوية")}`} />
      <CardBox title={t("Activity by identity", "النشاط حسب الهوية")}>
        {subjects.length === 0 ? <Empty label={t("No recorded activity.", "لا يوجد نشاط مسجَّل.")} /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>{t("Identity", "الهوية")}</Th><Th right>{t("Events", "الأحداث")}</Th><Th right>{t("Tool calls", "استدعاءات الأدوات")}</Th><Th right>{t("Errors", "الأخطاء")}</Th><Th>{t("Servers", "الخوادم")}</Th><Th>{t("Last seen", "آخر ظهور")}</Th><Th right></Th></tr></thead>
            <tbody>
              {subjects.map((s) => (
                <tr key={s.subject} className="hover:bg-black/[0.04]">
                  <Td><span className="font-medium">{s.subject}</span>{s.live && <span className="ml-2 text-xs px-2 py-0.5 rounded-full" style={{ background: "#e3f5e5", color: "#4AA785" }}>{t("live", "مباشر")}</span>}</Td>
                  <Td right>{s.events}</Td>
                  <Td right>{s.tool_calls}</Td>
                  <Td right><span style={{ color: s.errors ? "#D9534F" : undefined }}>{s.errors}</span></Td>
                  <Td><span className="text-black/50 text-xs">{(s.servers || []).join(", ") || "—"}</span></Td>
                  <Td><span className="text-black/60">{fmtTime(s.last_ts)}</span></Td>
                  <Td right><button onClick={() => open(s.subject)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1 ml-auto">{t("Investigate", "تحقيق")} <ChevronRight size={12} /></button></Td>
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
              <span className="text-sm font-semibold text-black">{t("Timeline", "الجدول الزمني")} · {sel}</span>
              <button onClick={() => setSel(null)} className="text-xs text-black/40 hover:text-black">{t("Close", "إغلاق")}</button>
            </div>
            {!timeline ? <Empty label={t("Loading…", "جارٍ التحميل…")} /> : (
              <>
                <div className="text-xs text-black/50">{timeline.event_count} {t("events", "حدث")} · {t("servers:", "الخوادم:")} {(timeline.servers || []).join(", ") || "—"} · {t("tools:", "الأدوات:")} {(timeline.tools || []).length}</div>
                <div className="flex flex-col relative">
                  <div className="absolute left-[5px] top-2 bottom-2 w-px bg-black/10" />
                  {(timeline.timeline || []).slice(0, 120).map((ev: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 py-2 pl-1 relative">
                      <span className="w-[11px] h-[11px] rounded-full mt-1 shrink-0 border-2 border-white" style={{ background: /fail|error|revoked|step_up/i.test(ev.event) ? "#D9534F" : /killswitch|drift|approval/i.test(ev.event) ? "#E5A000" : "#4AA785" }} />
                      <div className="flex flex-col min-w-0">
                        <span className="text-sm text-black">{ev.event}{ev.tool ? ` · ${ev.tool}` : ""}{ev.server ? ` (${ev.server})` : ""}</span>
                        <span className="text-xs text-black/40">{fmtDate(ev.ts)}{ev.tier != null ? ` · ${t("tier", "المستوى")} ${ev.tier}` : ""}{ev.pii_masked ? ` · ${ev.pii_masked} ${t("PII masked", "من بيانات PII مُخفاة")}` : ""}{ev.classification ? ` · ${ev.classification}` : ""}</span>
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
