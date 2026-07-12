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
        <h1 className="text-sm font-semibold text-black">Live Activity</h1>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-xs text-black/50">
            <Radio size={13} className={paused ? "text-black/30" : "text-[#4AA785]"} />
            {paused ? "paused" : "live · every 3s"}
          </span>
          <GhostBtn onClick={() => setPaused((p) => !p)}>{paused ? "Resume" : "Pause"}</GhostBtn>
        </div>
      </div>

      <div className="flex gap-3 flex-wrap items-end">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-black/50">Watch</span>
          <SelectInput value={subject} onChange={(e) => setSubject(e.target.value)}>
            <option value="">Everyone</option>
            {(subjects?.subjects || []).map((s) => (
              <option key={s.subject} value={s.subject}>
                {s.subject}{s.live ? " · online" : ""} ({s.events} events)
              </option>
            ))}
          </SelectInput>
        </label>
        <div className="flex flex-col gap-1">
          <span className="text-xs text-black/50">Online now</span>
          <div className="flex gap-1 flex-wrap">
            {activeNow.length ? activeNow.map((u) => (
              <button key={u} onClick={() => setSubject(u)}
                className="text-xs px-2 py-1 rounded-full bg-[#e3f4ec] text-[#1F7A5C] hover:opacity-80">
                {u}
              </button>
            )) : <span className="text-xs text-black/30 py-1">no active sessions</span>}
          </div>
        </div>
      </div>

      <Card title={subject ? `${subject}'s AI — live` : "All activity — live"}>
        {shown.length === 0 ? <Empty label="Waiting for activity…" /> : (
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
                {e.pii_masked && <span className="text-xs px-1.5 py-0.5 rounded bg-[#edeefc] text-[#4b4fa6] shrink-0">masked</span>}
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

  const tone = (b: string) => b === "up" ? { bg: "#e3f4ec", fg: "#1F7A5C", label: "reachable" }
    : b === "down" ? { bg: "#fbe6e6", fg: "#B03A36", label: "UNREACHABLE" }
    : b === "unknown" ? { bg: "rgba(0,0,0,0.05)", fg: "rgba(0,0,0,0.5)", label: "process only" }
    : { bg: "#fdf3e0", fg: "#8a6100", label: "stopped" };

  const s = data?.summary || {};
  return (
    <Card title="Backend health — is each connector's data source actually reachable?"
      right={<div className="flex items-center gap-2">
        {data && <span className="text-xs text-black/40">{s.up || 0} up · {s.down || 0} down</span>}
        <GhostBtn onClick={refresh}>{busy ? "Probing…" : "Probe now"}</GhostBtn>
      </div>}>
      {loading && !data ? <Empty label="Probing backends…" /> : (
        <table className="w-full">
          <thead><tr>
            <th className="text-xs text-black/40 font-normal pb-2 text-left">Server</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-left">Backend</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-right">Latency</th>
            <th className="text-xs text-black/40 font-normal pb-2 text-left pl-4">Detail</th>
          </tr></thead>
          <tbody>
            {(data?.servers || []).map((p: any) => {
              const t = tone(p.backend);
              return (
                <tr key={p.server} className="hover:bg-black/[0.02]">
                  <td className="text-sm text-black py-2 border-t border-black/5">{p.server}</td>
                  <td className="py-2 border-t border-black/5">
                    <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: t.bg, color: t.fg }}>{t.label}</span>
                  </td>
                  <td className="text-sm text-black/60 py-2 border-t border-black/5 text-right tabular-nums">{ms(p.latency_ms)}</td>
                  <td className="text-xs text-black/40 py-2 border-t border-black/5 pl-4 max-w-[340px] truncate">{p.detail || (p.probe ? `probe: ${p.probe}` : "")}</td>
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
    apiGet<any>(`/api/admin/preview?${qs}`).then((d) => d ? setData(d) : setErr("could not load"))
      .catch(() => setErr("could not load"));
  }, [sub, role]);

  return (
    <Modal title={`See as — ${sub || role}`} onClose={onClose} width={560}>
      {err ? <Empty label={err} /> : !data ? <Empty label="Loading…" /> : (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded-full bg-[#edeefc] text-[#4b4fa6]">{data.as}</span>
            <span className="text-black/50">clearance {data.clearance}</span>
            <span className="text-black/50">· can request up to tier {data.max_tool_tier}</span>
            <span className="text-black/50 ml-auto">{data.visible_tool_count} tools visible</span>
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
            {Object.keys(data.by_server || {}).length === 0 && <Empty label="This role sees no tools." />}
          </div>
          {data.blocked_servers?.length > 0 && (
            <div className="text-xs text-black/50">
              <span className="text-[#B03A36]">Cannot reach:</span> {data.blocked_servers.join(", ")}
              <span className="text-black/30"> — servers this role is not entitled to (invisible to them).</span>
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
const KIND_META: Record<string, { label: string; color: string }> = {
  identity: { label: "Identity", color: "#4b4fa6" },
  session: { label: "Session", color: "#1F7A5C" },
  tool: { label: "Tool", color: "#8a6100" },
  api_key: { label: "API key", color: "#4b4fa6" },
  oauth_client: { label: "OAuth", color: "#4b4fa6" },
  audit: { label: "Audit", color: "#787878" },
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
          placeholder="Search everything…"
          className="text-sm text-black bg-transparent outline-none border-none w-full placeholder:text-black/20" />
        {query && <button onClick={() => { setQuery(""); setResults([]); }} className="text-black/30 hover:text-black"><X size={12} /></button>}
      </div>
      {open && query.trim().length >= 2 && (
        <div className="absolute right-0 top-[38px] w-[380px] max-h-[60vh] overflow-y-auto bg-white rounded-xl shadow-xl border border-black/10 z-50 py-2"
          style={{ fontFamily: "Inter, sans-serif" }}>
          {loading && results.length === 0 ? <div className="px-4 py-3 text-xs text-black/40">Searching…</div>
            : results.length === 0 ? <div className="px-4 py-3 text-xs text-black/40">No matches across the system.</div>
              : results.map((r, i) => {
                const meta = KIND_META[r.kind] || { label: r.kind, color: "#787878" };
                return (
                  <button key={i} onClick={() => go(r)}
                    className="w-full text-left px-4 py-2 hover:bg-black/[0.03] flex items-center gap-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0 w-[54px] text-center"
                      style={{ background: meta.color + "22", color: meta.color }}>{meta.label}</span>
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
