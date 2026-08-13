// Four admin features built from the "what I reach for and can't find" list:
//   1. ActivityPage    — live feed of what one identity's AI is doing, right now
//   2. ServerHealth    — is the BACKEND reachable (DB/Gitea/Qdrant), not just "process up"
//   3. SeeAsModal      — the exact tools a role/operator sees ("what does khalid's AI see?")
//   4. GlobalSearchBox — search across the whole system, not just the current table
import { useCallback, useEffect, useRef, useState } from "react";
import { Search, Radio, HeartPulse, Eye, X } from "lucide-react";
import { useApi } from "./useApi";
import { apiGet } from "@/api";
import { Modal, GhostBtn, SelectInput } from "./ui";
import { t } from "./i18n";

function fmtTime(ts?: number) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "—"; }
function ms(v?: number | null) { return v == null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(2)}s` : `${Math.round(v)}ms`; }

function Card({ children, title, right }: { children: React.ReactNode; title?: string; right?: React.ReactNode }) {
  return (
    <div className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4">
      {(title || right) && <div className="flex items-center justify-between"><p className="text-sm font-normal text-black">{title}</p>{right}</div>}
      {children}
    </div>
  );
}
function Empty({ label }: { label: string }) { return <div className="text-sm text-black/30 py-8 text-center">{label}</div>; }

// event → colour, matching the audit page's convention
function evColor(ev: string) {
  return /fail|error|revoked|quarantine|locked|denied|blocked/i.test(ev) ? "#D9534F"
    : /killswitch|drift|approval|onboard|retier|reject|pending/i.test(ev) ? "#E5A000" : "#4AA785";
}

// ── 1. Live per-user activity ────────────────────────────────────────────────
// "Show me everything sara's AI is doing." Polls with a cursor so it only pulls NEW
// events, and appends them — you watch the feed scroll during an incident instead of
// re-querying the audit page by hand.
export function ActivityPage({ query, onAuthExpired }: { query: string; onAuthExpired: () => void }) {
  const { data: subjects } = useApi<{ subjects: any[] }>("/api/admin/investigate", onAuthExpired);
  const [subject, setSubject] = useState("");
  const [events, setEvents] = useState<any[]>([]);
  const [activeNow, setActiveNow] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const cursor = useRef(0);

  // reset the feed when the target changes
  useEffect(() => { setEvents([]); cursor.current = 0; }, [subject]);

  const poll = useCallback(async () => {
    if (paused) return;
    const qs = new URLSearchParams();
    if (subject) qs.set("subject", subject);
    qs.set("since", String(cursor.current));
    const r = await apiGet<any>(`/api/admin/activity?${qs}`);
    if (!r) return;
    setActiveNow(r.active_now || []);
    if (r.events?.length) {
      cursor.current = r.cursor;
      setEvents((prev) => [...r.events, ...prev].slice(0, 300));  // newest on top, capped
    }
  }, [subject, paused]);

  useEffect(() => {
    poll();
    const t = setInterval(poll, 3000);   // live: every 3s
    return () => clearInterval(t);
  }, [poll]);

  const shown = events.filter((e) =>
    !query || `${e.who} ${e.tool} ${e.server} ${e.event}`.toLowerCase().includes(query.toLowerCase()));

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Live Activity", "النشاط المباشر")}</h1>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-xs text-black/50">
            <Radio size={13} className={paused ? "text-black/30" : "text-[#4AA785]"} />
            {paused ? t("paused", "متوقف مؤقتًا") : t("live · every 3s", "مباشر · كل 3 ثوانٍ")}
          </span>
          <GhostBtn onClick={() => setPaused((p) => !p)}>{paused ? t("Resume", "استئناف") : t("Pause", "إيقاف مؤقت")}</GhostBtn>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap items-end">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-black/50">{t("Watch", "مراقبة")}</span>
          <SelectInput value={subject} onChange={(e) => setSubject(e.target.value)}>
            <option value="">{t("Everyone", "الجميع")}</option>
            {(subjects?.subjects || []).map((s) => (
              <option key={s.subject} value={s.subject}>
                {s.subject}{s.live ? t(" · online", " · متصل") : ""} ({s.events} {t("events", "أحداث")})
              </option>
            ))}
          </SelectInput>
        </label>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-black/50">{t("Online now", "متصل الآن")}</span>
          <div className="flex gap-1 flex-wrap">
            {activeNow.length ? activeNow.map((u) => (
              <button key={u} onClick={() => setSubject(u)}
                className="text-xs px-2 py-1 rounded-full bg-[#e3f4ec] text-[#1F7A5C] hover:opacity-80">
                {u}
              </button>
            )) : <span className="text-xs text-black/30 py-1">{t("no active sessions", "لا توجد جلسات نشطة")}</span>}
          </div>
        </div>
      </div>

      <Card title={subject ? t(`${subject}'s AI — live`, `${subject} — الذكاء الاصطناعي مباشر`) : t("All activity — live", "كل النشاط — مباشر")}>
        {shown.length === 0 ? <Empty label={t("Waiting for activity…", "في انتظار النشاط…")} /> : (
          <div className="flex flex-col">
            {shown.map((e, i) => (
              <div key={i} className="flex items-center gap-3 py-2 border-t border-black/5 first:border-t-0 text-sm">
                <span className="text-black/40 w-[70px] shrink-0 tabular-nums">{fmtTime(e.ts)}</span>
                <span className="w-[150px] shrink-0" style={{ color: evColor(e.event) }}>{e.event}</span>
                {!subject && <span className="text-black/60 w-[90px] shrink-0 truncate">{e.who}</span>}
                <span className="text-black flex-1 min-w-0 truncate">
                  {e.tool ? `${e.tool}${e.server ? " · " + e.server : ""}` : (e.server || e.reason || "—")}
                </span>
                {e.tier != null && <span className="text-xs text-black/40 shrink-0">t{e.tier}</span>}
                {e.pii_masked && <span className="text-xs px-1.5 py-0.5 rounded bg-[#edeefc] text-[#4b4fa6] shrink-0">{t("masked", "مخفي")}</span>}
                {e.duration_ms != null && <span className="text-xs text-black/40 w-[52px] text-right shrink-0">{ms(e.duration_ms)}</span>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}

// ── 2. Backend health ────────────────────────────────────────────────────────
// "Is postgres even up? Is gitea reachable?" Probes each connector's real backend, not
// just whether the server process is alive. Drop this card onto the Servers page.
export function ServerHealth() {
  const { data, loading, reload } = useApi<any>("/api/admin/health/servers");
  const [busy, setBusy] = useState(false);
  const refresh = async () => { setBusy(true); await reload(); setBusy(false); };

  const tone = (b: string) => b === "up" ? { bg: "#e3f4ec", fg: "#1F7A5C", label: t("reachable", "قابل للوصول") }
    : b === "down" ? { bg: "#fbe6e6", fg: "#B03A36", label: t("UNREACHABLE", "غير قابل للوصول") }
    : b === "unknown" ? { bg: "rgba(0,0,0,0.05)", fg: "rgba(0,0,0,0.5)", label: t("process only", "العملية فقط") }
    : { bg: "#fdf3e0", fg: "#8a6100", label: t("stopped", "متوقف") };

  const s = data?.summary || {};
  return (
    <Card title={t("Backend health — is each connector's data source actually reachable?", "سلامة الخلفية — هل مصدر بيانات كل موصل قابل للوصول فعليًا؟")}
      right={<div className="flex items-center gap-2">
        {data && <span className="text-xs text-black/40">{s.up || 0} {t("up", "فعّال")} · {s.down || 0} {t("down", "متعطل")}</span>}
        <GhostBtn onClick={refresh}>{busy ? t("Probing…", "جارٍ الفحص…") : t("Probe now", "افحص الآن")}</GhostBtn>
      </div>}>
      {loading && !data ? <Empty label={t("Probing backends…", "جارٍ فحص الخلفيات…")} /> : (
        <table className="w-full">
          <thead><tr>
            <th className="text-xs text-black/40 font-normal pb-2 text-left">{t("Server", "الخادم")}</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-left">{t("Backend", "الخلفية")}</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-right">{t("Latency", "زمن الاستجابة")}</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-left pl-4">{t("Detail", "التفاصيل")}</th>
          </tr></thead>
          <tbody>
            {(data?.servers || []).map((p: any) => {
              const tn = tone(p.backend);
              return (
                <tr key={p.server} className="hover:bg-black/[0.04]">
                  <td className="text-sm text-black py-2 border-t border-black/5">{p.server}</td>
                  <td className="py-2 border-t border-black/5">
                    <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: tn.bg, color: tn.fg }}>{tn.label}</span>
                  </td>
                  <td className="text-sm text-black/60 py-2 border-t border-black/5 text-right tabular-nums">{ms(p.latency_ms)}</td>
                  <td className="text-xs text-black/40 py-2 border-t border-black/5 pl-4 max-w-[340px] truncate">{p.detail || (p.probe ? t(`probe: ${p.probe}`, `الفحص: ${p.probe}`) : "")}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Card>
  );
}

// ── 3. See-as / role preview ─────────────────────────────────────────────────
// "What does khalid's AI actually see?" Opens the exact visible tool set for a role or a
// specific operator — read-only, without being them.
export function SeeAsModal({ sub, role, onClose }: { sub?: string; role?: string; onClose: () => void }) {
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    const qs = sub ? `sub=${encodeURIComponent(sub)}` : `role=${encodeURIComponent(role || "")}`;
    apiGet<any>(`/api/admin/preview?${qs}`).then((d) => d ? setData(d) : setErr(t("could not load", "تعذر التحميل")))
      .catch(() => setErr(t("could not load", "تعذر التحميل")));
  }, [sub, role]);

  return (
    <Modal title={t(`See as — ${sub || role}`, `عرض بصفة — ${sub || role}`)} onClose={onClose} width={560}>
      {err ? <Empty label={err} /> : !data ? <Empty label={t("Loading…", "جارٍ التحميل…")} /> : (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded-full bg-[#edeefc] text-[#4b4fa6]">{data.as}</span>
            <span className="text-black/50">{t("clearance ", "التصريح ")}{data.clearance}</span>
            <span className="text-black/50">{t("· can request up to tier ", "· يمكنه الطلب حتى المستوى ")}{data.max_tool_tier}</span>
            <span className="text-black/50 ml-auto">{data.visible_tool_count} {t("tools visible", "أداة مرئية")}</span>
          </div>
          <div className="flex flex-col gap-2 max-h-[46vh] overflow-y-auto">
            {Object.entries(data.by_server || {}).map(([server, tools]: any) => (
              <div key={server} className="bg-white rounded-lg p-3">
                <div className="text-sm font-medium text-black mb-1">{server} <span className="text-xs text-black/40">· {tools.length}</span></div>
                <div className="flex flex-wrap gap-1">
                  {tools.map((t: any) => (
                    <span key={t.tool} className="text-xs px-2 py-0.5 rounded bg-black/[0.04] text-black/70">
                      {t.tool}<span className="text-black/30"> t{t.tier}</span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {Object.keys(data.by_server || {}).length === 0 && <Empty label={t("This role sees no tools.", "هذا الدور لا يرى أي أدوات.")} />}
          </div>
          {data.blocked_servers?.length > 0 && (
            <div className="text-xs text-black/50">
              <span className="text-[#B03A36]">{t("Cannot reach:", "غير قادر على الوصول:")}</span> {data.blocked_servers.join(", ")}
              <span className="text-black/30">{t(" — servers this role is not entitled to (invisible to them).", " — خوادم لا يملك هذا الدور صلاحية الوصول إليها (غير مرئية له).")}</span>
            </div>
          )}
          <p className="text-xs text-black/40">{data.note}</p>
        </div>
      )}
    </Modal>
  );
}

// ── 4. Global search ─────────────────────────────────────────────────────────
// "Search for that thing." Looks across identities, sessions, tools, audit, keys and OAuth
// clients — not just the current table — and jumps you to the right page.
// `label` holds the Arabic; `en` the English. Rendered via t(en, label) so it
// follows the runtime language switch (module-level maps can't call t() directly).
const KIND_META: Record<string, { en: string; label: string; color: string }> = {
  identity: { en: "Identity", label: "الهوية", color: "#4b4fa6" },
  session: { en: "Session", label: "الجلسة", color: "#1F7A5C" },
  tool: { en: "Tool", label: "الأداة", color: "#8a6100" },
  api_key: { en: "API key", label: "مفتاح API", color: "#4b4fa6" },
  oauth_client: { en: "OAuth", label: "OAuth", color: "#4b4fa6" },
  audit: { en: "Audit", label: "سجل التدقيق", color: "#787878" },
};

export function GlobalSearchBox({ query, setQuery, onNavigate }: {
  query: string; setQuery: (q: string) => void; onNavigate: (page: string, target?: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);
  const timer = useRef<any>(null);

  // debounce the cross-system search; the query still filters the current page too
  useEffect(() => {
    clearTimeout(timer.current);
    if (query.trim().length < 2) { setResults([]); return; }
    timer.current = setTimeout(async () => {
      setLoading(true);
      const r = await apiGet<any>(`/api/admin/search?q=${encodeURIComponent(query)}`);
      setResults(r?.results || []);
      setLoading(false);
    }, 200);
    return () => clearTimeout(timer.current);
  }, [query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => { if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const go = (r: any) => { onNavigate(r.page, r.target); setOpen(false); };

  return (
    <div className="relative" ref={boxRef}>
      <div className="flex items-center gap-2 bg-black/[0.04] rounded-2xl px-3 py-1 w-52">
        <Search size={14} className="text-black/30 shrink-0" />
        <input value={query} onChange={(e) => { setQuery(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)}
          placeholder={t("Search everything…", "ابحث عن أي شيء…")}
          className="text-sm text-black bg-transparent outline-none border-none w-full placeholder:text-black/20" />
        {query && <button onClick={() => { setQuery(""); setResults([]); }} className="text-black/30 hover:text-black"><X size={12} /></button>}
      </div>
      {open && query.trim().length >= 2 && (
        <div className="absolute right-0 top-[38px] w-[380px] max-h-[60vh] overflow-y-auto bg-white rounded-xl shadow-xl border border-black/10 z-50 py-2"
          style={{ fontFamily: "Inter, sans-serif" }}>
          {loading && results.length === 0 ? <div className="px-4 py-3 text-xs text-black/40">{t("Searching…", "جارٍ البحث…")}</div>
            : results.length === 0 ? <div className="px-4 py-3 text-xs text-black/40">{t("No matches across the system.", "لا توجد نتائج مطابقة في النظام.")}</div>
              : results.map((r, i) => {
                const meta = KIND_META[r.kind] || { en: r.kind, label: r.kind, color: "#787878" };
                return (
                  <button key={i} onClick={() => go(r)}
                    className="w-full text-left px-4 py-2 hover:bg-black/[0.08] flex items-center gap-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0 w-[54px] text-center"
                      style={{ background: meta.color + "22", color: meta.color }}>{t(meta.en, meta.label)}</span>
                    <span className="flex flex-col min-w-0 flex-1">
                      <span className="text-sm text-black truncate">{r.label}</span>
                      <span className="text-xs text-black/40 truncate">{r.detail}</span>
                    </span>
                    <span className="text-xs text-black/30 shrink-0">{r.page} →</span>
                  </button>
                );
              })}
        </div>
      )}
    </div>
  );
}
