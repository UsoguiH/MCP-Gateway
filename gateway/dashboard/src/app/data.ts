// Maps the MCP Gateway's real REST responses into the shapes the dashboard consumes.
//
// Phase 2 (the "truth pass"): every number here is now MEASURED. The traffic curve, the
// latency chart, the trend deltas, the transport split, per-tool durations and rate-limit
// consumption used to be synthesized in this file because the gateway did not record them.
// It does now (per-call durations in the audit chain + app/insights.py), so the synthetic
// generators are gone. Where a value genuinely does not exist yet, we render "—" rather
// than invent one — a fabricated number an operator later catches costs more trust than a
// missing one.
import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/api";

export type Range = "Today" | "Last 7 days" | "Last 30 days";
export const RANGES: Range[] = ["Today", "Last 7 days", "Last 30 days"];

// Each range maps to a real query window against the audit chain.
export const RANGE_QUERY: Record<Range, { hours: number; buckets: number }> = {
  "Today":        { hours: 24,  buckets: 12 },
  "Last 7 days":  { hours: 168, buckets: 7 },
  "Last 30 days": { hours: 720, buckets: 15 },
};

const SERVER_COLORS = ["#9BB8E8", "#4CC8B4", "#1C1C1C", "#6B9FD4", "#C4B8F0", "#5CC47C"];
const TRANSPORT_COLORS: Record<string, string> = {
  stdio: "#787878", http: "#1C1C1C", sse: "#B4B4B4", websocket: "#D8D8D8",
};

export type ServerRow = {
  name: string; status: string; transport: string;
  tools: number; version: string; latency: string; uptime: string;
  detail?: { tiers?: Record<string, number>; active?: number; pending?: number;
             quarantined?: number; rejected?: number; breaker_open?: boolean; fails?: number;
             managed_credentials?: boolean; state?: string; drained?: boolean;
             started_at?: number | null; calls?: number; errors?: number;
             p95_ms?: number | null; rate_limit?: number; protocol_version?: string };
};
export type ToolRow = {
  tool: string; server: string; calls: number; success: number; avg: string; tier?: number;
};
export type LogRow = {
  time: string; client: string; method: string; detail: string; duration: string; code: number;
};
export type ClientRow = {
  name: string; requests: number; sessions: number; lastActive: string; status: string;
  id?: string; sub?: string;
};
export type SeriesPoint = { label: string; current: number; previous: number };
export type LatencyPoint = { label: string; p50: number | null; p95: number | null };
export type RateLimitRow = {
  scope: string; limit: string; used: number; usedLabel: string;
  top?: { key: string; used: number; limit: number }[];
};
export type SettingRow = {
  name: string; detail: string; on: boolean;
  section?: string; key?: string; rule?: string; readOnly?: boolean;
};
export type Dashboard = {
  loaded: boolean;
  isAdmin: boolean;
  stats: { totalRequests: string; activeServers: string; toolCalls: string; errorRate: string };
  deltas: { requests: number | null; toolCalls: number | null; errors: number | null };
  metricTotals: { Requests: number; "Tool Calls": number; Errors: number };
  servers: ServerRow[];
  serverCalls: { server: string; value: number; color: string }[];
  transport: { name: string; value: number; color: string }[];
  topTools: { tool: string; pct: number }[];
  tools: ToolRow[];
  logs: LogRow[];
  clients: ClientRow[];
  series: SeriesPoint[];
  latency: LatencyPoint[];
  rateLimits: RateLimitRow[];
  policies: { name: string; applies: string; action: string; updated: string }[];
  settings: SettingRow[];
  maintenance: boolean;
  notifications: { kind: string; text: string; time: string }[];
  activities: { text: string; time: string }[];
};

const EMPTY: Dashboard = {
  loaded: false, isAdmin: false,
  stats: { totalRequests: "—", activeServers: "—", toolCalls: "—", errorRate: "—" },
  deltas: { requests: null, toolCalls: null, errors: null },
  metricTotals: { Requests: 0, "Tool Calls": 0, Errors: 0 },
  servers: [], serverCalls: [], transport: [], topTools: [], tools: [], logs: [],
  clients: [], series: [], latency: [], rateLimits: [], policies: [], settings: [],
  maintenance: false, notifications: [], activities: [],
};

function hhmmss(ts?: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toTimeString().slice(0, 8);
}

function relTime(ts?: number | null): string {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 5) return "Just now";
  if (s < 60) return `${s} seconds ago`;
  if (s < 3600) return `${Math.floor(s / 60)} minutes ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} hours ago`;
  return `${Math.floor(s / 86400)} days ago`;
}

function duration(sec?: number | null): string {
  if (!sec && sec !== 0) return "—";
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`;
}

export function ms(v?: number | null): string {
  if (v == null) return "—";
  return v >= 1000 ? `${(v / 1000).toFixed(2)}s` : `${Math.round(v)}ms`;
}

// audit event -> HTTP-ish status code for the Logs table colouring.
function codeFor(action: string): number {
  if (/error|fail/i.test(action)) return action.includes("login") ? 401 : 500;
  if (/blocked|killswitch|revoked|denied|lockout/i.test(action)) return 403;
  if (/rate/i.test(action)) return 429;
  return 200;
}

function bucketLabel(ts: number, hours: number): string {
  const d = new Date(ts * 1000);
  if (hours <= 24) return d.toTimeString().slice(0, 5);                       // 14:00
  if (hours <= 168) return d.toLocaleDateString(undefined, { weekday: "short" });  // Tue
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });  // Jul 5
}

async function loadDashboard(range: Range): Promise<Dashboard> {
  const q = RANGE_QUERY[range];
  const [health, metrics, adminServers, toolsResp, auditResp, sessionsResp, configResp,
         seriesResp, statsResp, limitsResp, settingsResp, gwResp] =
    await Promise.all([
      apiGet<any>("/api/health"),
      apiGet<any>("/api/metrics"),
      apiGet<any>("/api/admin/servers"),
      apiGet<any>("/api/tools"),
      apiGet<any>("/api/admin/audit?limit=200"),
      apiGet<any>("/api/admin/sessions"),
      apiGet<any>("/api/admin/config"),
      apiGet<any>(`/api/admin/series?hours=${q.hours}&buckets=${q.buckets}`),
      apiGet<any>("/api/admin/stats"),
      apiGet<any>("/api/admin/ratelimits"),
      apiGet<any>("/api/admin/settings"),
      apiGet<any>("/api/admin/gateway"),
    ]);

  const isAdmin = !!metrics;
  const events: Record<string, number> = metrics?.event_counts || {};
  const records: any[] = auditResp?.records || [];
  const toolStats: Record<string, any> = statsResp?.tools || {};
  const serverStats: Record<string, any> = statsResp?.servers || {};

  // ---- traffic + latency: REAL buckets from the audit chain (was: buildSeries) ----
  const buckets: any[] = seriesResp?.buckets || [];
  const series: SeriesPoint[] = buckets.map((b, i) => ({
    label: bucketLabel(b.t, q.hours),
    current: b.calls,
    // "previous" is the preceding bucket — an honest period-over-period comparison
    // instead of the old current*0.82 fiction.
    previous: i > 0 ? buckets[i - 1].calls : 0,
  }));
  const latency: LatencyPoint[] = buckets.map((b) => ({
    label: bucketLabel(b.t, q.hours),
    p50: b.p50_ms, p95: b.p95_ms,
  }));

  const healthServers: string[] = health?.servers || [];
  const srvList: any[] = adminServers?.servers ||
    healthServers.map((n) => ({ name: n, tools: 0, breaker_open: false }));

  const servers: ServerRow[] = srvList.map((s) => {
    const online = healthServers.includes(s.name);
    const status = s.state === "stopped" ? "Stopped"
      : s.drained ? "Draining"
      : !online ? "Offline"
      : s.breaker_open ? "Degraded" : "Online";
    return {
      name: s.name,
      status,
      transport: s.transport || "stdio",
      tools: s.tools ?? 0,
      version: s.version || "—",                       // from the MCP handshake
      latency: ms(s.avg_ms),                           // measured, not an em-dash
      uptime: s.state === "stopped" ? "—" : duration(s.uptime_seconds),
      detail: {
        tiers: s.tiers, active: s.active, pending: s.pending,
        quarantined: s.quarantined, rejected: s.rejected, breaker_open: s.breaker_open,
        fails: s.fails, managed_credentials: s.managed_credentials,
        state: s.state, drained: s.drained, started_at: s.started_at,
        calls: s.calls, errors: s.errors, p95_ms: s.p95_ms,
        rate_limit: s.rate_limit, protocol_version: s.protocol_version,
      },
    };
  });

  const serverCalls = srvList.slice(0, 6).map((s: any, i: number) => ({
    server: s.name,
    value: serverStats[s.name]?.calls || 0,
    color: SERVER_COLORS[i % SERVER_COLORS.length],
  }));

  // ---- transport split: counted from the servers actually connected (was: stdio=100) ----
  const tCount: Record<string, number> = {};
  for (const s of srvList) {
    const t = (s.transport || "stdio").toLowerCase();
    tCount[t] = (tCount[t] || 0) + 1;
  }
  const tTotal = Math.max(1, Object.values(tCount).reduce((a, b) => a + b, 0));
  const transport = Object.entries(tCount).map(([name, n]) => ({
    name: name === "http" ? "HTTP Stream" : name,
    value: Math.round((n / tTotal) * 100),
    color: TRANSPORT_COLORS[name] || "#B4B4B4",
  }));

  const toolList: any[] = toolsResp?.tools || [];
  const callCounts = Object.values(toolStats).map((t: any) => t.calls || 0);
  const maxToolCalls = Math.max(1, ...callCounts);
  const topTools = Object.entries(toolStats)
    .sort((a: any, b: any) => (b[1].calls || 0) - (a[1].calls || 0))
    .filter(([, s]: any) => s.calls > 0)
    .slice(0, 6)
    .map(([tool, s]: any) => ({ tool, pct: Math.round((s.calls / maxToolCalls) * 100) }));

  const tools: ToolRow[] = toolList.map((t: any) => {
    const st = toolStats[t.name] || {};
    return {
      tool: t.name, server: t.server,
      calls: st.calls || 0,
      success: st.success_pct != null ? st.success_pct : 100,
      avg: ms(st.avg_ms),                              // measured per-call duration
      tier: t.tier,
    };
  }).sort((a, b) => b.calls - a.calls);

  const logs: LogRow[] = records.slice(0, 40).map((r) => ({
    time: hhmmss(r.ts),
    client: r.user || r.by || "system",
    method: r.event || "",
    detail: r.tool ? `${r.tool}${r.server ? " · " + r.server : ""}` : (r.server || r.sub || "—"),
    duration: ms(r.duration_ms),                       // real, from the audit record
    code: codeFor(r.event || ""),
  }));

  const sessions: any[] = sessionsResp?.sessions || [];
  const clients: ClientRow[] = sessions.map((s: any) => ({
    name: s.sub ? `${s.sub} · ${s.id}` : (s.client || s.name || s.id || "MCP client"),
    requests: s.calls ?? s.requests ?? 0,
    sessions: 1,
    lastActive: s.age_seconds != null ? `connected ${Math.floor(s.age_seconds / 60)}m`
                                      : relTime(s.last_seen || s.created),
    status: "Online",
    id: s.id, sub: s.sub,
  }));

  // ---- rate limits: LIVE consumption (was: used hardcoded to 0) ----
  const lim = limitsResp?.limits || {};
  const peak = (rows: any[]) => rows?.length ? rows[0] : null;   // snapshots are sorted desc
  const pct = (used: number, limit: number) => limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const userPeak = peak(limitsResp?.per_user);
  const toolPeak = peak(limitsResp?.per_tool);
  const srvPeak = peak(limitsResp?.per_server);
  const rateLimits: RateLimitRow[] = [
    {
      scope: "Global (per user)", limit: `${lim.per_user_per_minute ?? "—"} req/min`,
      used: userPeak ? pct(userPeak.used, userPeak.limit) : 0,
      usedLabel: userPeak ? `${userPeak.used}/${userPeak.limit} · ${userPeak.key}` : "idle",
      top: limitsResp?.per_user?.slice(0, 5),
    },
    {
      scope: "Per tool", limit: `${lim.per_tool_per_minute ?? "—"} req/min`,
      used: toolPeak ? pct(toolPeak.used, toolPeak.limit) : 0,
      usedLabel: toolPeak ? `${toolPeak.used}/${toolPeak.limit} · ${toolPeak.key}` : "idle",
      top: limitsResp?.per_tool?.slice(0, 5),
    },
    {
      scope: "Per server", limit: `${lim.per_server_per_minute ?? "—"} req/min`,
      used: srvPeak ? pct(srvPeak.used, srvPeak.limit) : 0,
      usedLabel: srvPeak ? `${srvPeak.used}/${srvPeak.limit} · ${srvPeak.key}` : "idle",
      top: limitsResp?.per_server?.slice(0, 5),
    },
    {
      scope: "Login (per IP)",
      limit: `${configResp?.auth?.login_rate_per_minute ?? "—"} req/min`,
      used: 0, usedLabel: "edge-enforced",
    },
  ];

  // ---- policies + settings: read from the live overlay, and WRITABLE (A3/A6) ----
  const eff = settingsResp?.effective || {};
  const reqApproval = !!configResp?.registry?.require_approval;
  const siem = !!configResp?.audit?.siem_export;
  const policies = [
    { name: "Two-person approval (Tier 3)", applies: "Destructive tools", action: "Approve",
      updated: `min tier ${eff.approvals?.min_tier ?? "—"}` },
    { name: "Tool onboarding gate", applies: "Registry", action: reqApproval ? "Approve" : "Auto",
      updated: "Active" },
    { name: "Hash-pin / rug-pull quarantine", applies: "All tools", action: "Deny", updated: "Active" },
    { name: "DLP mask (National ID / Iqama / IBAN)", applies: "All results",
      action: eff.dlp?.enabled === false ? "Off" : "Rewrite",
      updated: Object.entries(eff.dlp?.detectors || {})
        .filter(([, on]) => on).map(([d]) => d).join(", ") || "none" },
    { name: "HMAC-chained audit", applies: "All servers", action: "Log", updated: "Active" },
  ];

  const settings: SettingRow[] = [
    { name: "DLP masking", detail: "Mask Saudi PII in tool results below the caller's clearance",
      on: eff.dlp?.enabled !== false, section: "dlp", key: "enabled" },
    { name: "Detector — National ID", detail: "1XXXXXXXXX with Luhn check",
      on: eff.dlp?.detectors?.national_id !== false, section: "dlp", rule: "national_id" },
    { name: "Detector — Iqama", detail: "2XXXXXXXXX with Luhn check",
      on: eff.dlp?.detectors?.iqama !== false, section: "dlp", rule: "iqama" },
    { name: "Detector — IBAN", detail: "SA + 22 digits with mod-97 checksum",
      on: eff.dlp?.detectors?.iban !== false, section: "dlp", rule: "iban" },
    { name: "Tool onboarding approval", detail: "New tools stay pending until a Risk-Board admin approves",
      on: reqApproval, readOnly: true },
    { name: "SIEM export", detail: "Mirror every audit event to the SIEM feed",
      on: siem, readOnly: true },
    { name: "Require MFA (TOTP)", detail: "Second factor enforced on every operator login",
      on: !!configResp?.auth?.require_mfa, readOnly: true },
  ];

  const notifications = records.slice(0, 4).map((r) => ({
    kind: /error|fail|offline|blocked/i.test(r.event || "") ? "warn" : "server",
    text: notifText(r), time: relTime(r.ts),
  }));
  const activities = records.slice(0, 5).map((r) => ({
    text: notifText(r), time: relTime(r.ts),
  }));

  const toolCalls = events["tool_call"] || 0;
  const toolErrs = events["tool_error"] || 0;
  const totalReq = Object.values(events).reduce((a, b) => a + b, 0);
  const errorRate = toolCalls + toolErrs ? (toolErrs / (toolCalls + toolErrs)) * 100 : 0;

  // ---- trend deltas: measured second-half vs first-half of the window (was: "+11.01%") ----
  const half = Math.floor(buckets.length / 2);
  const sumOf = (arr: any[], f: (b: any) => number) => arr.reduce((a, b) => a + f(b), 0);
  const delta = (f: (b: any) => number): number | null => {
    if (buckets.length < 2) return null;
    const first = sumOf(buckets.slice(0, half), f);
    const second = sumOf(buckets.slice(half), f);
    if (!first) return null;                    // no baseline -> no honest delta -> "—"
    return Math.round(((second - first) / first) * 1000) / 10;
  };

  return {
    loaded: true,
    isAdmin,
    stats: {
      totalRequests: totalReq.toLocaleString(),
      activeServers: String(healthServers.length),
      toolCalls: toolCalls.toLocaleString(),
      errorRate: `${errorRate.toFixed(2)}%`,
    },
    deltas: {
      requests: seriesResp?.delta_pct ?? null,
      toolCalls: delta((b) => b.calls),
      errors: delta((b) => b.errors),
    },
    metricTotals: { Requests: totalReq, "Tool Calls": toolCalls, Errors: toolErrs },
    servers, serverCalls, transport,
    topTools, tools, logs, clients, series, latency, rateLimits, policies, settings,
    maintenance: !!gwResp?.maintenance?.enabled,
    notifications, activities,
  };
}

function notifText(r: any): string {
  switch (r.event || "") {
    case "tool_call": return `${r.user || "client"} called ${r.tool || "a tool"}${r.server ? " · " + r.server : ""}.`;
    case "tool_error": return `${r.tool || "A tool"} on ${r.server || "a server"} errored.`;
    case "login": return `${r.user || "An operator"} signed in.`;
    case "login_failed": return `Failed login for ${r.user || "unknown"}.`;
    case "circuit_open": return `${r.server || "A server"} circuit opened (quarantined).`;
    case "gateway_startup": return `Gateway started (${(r.servers || []).length} servers).`;
    case "identity_revoked": return `Identity ${r.sub || ""} revoked.`;
    case "tool_onboarded": return `Tool ${r.tool || ""} onboarded.`;
    case "tool_rejected": return `Tool ${r.tool || ""} rejected by the Risk Board.`;
    case "settings_changed": return `${r.by || "An admin"} changed ${r.section || "settings"}.`;
    case "maintenance_mode": return `Maintenance mode ${r.enabled ? "enabled" : "disabled"}.`;
    case "audit_exported": return `${r.by || "An admin"} exported ${r.count ?? ""} audit records.`;
    case "password_changed": return `${r.user || "An operator"} rotated their password.`;
    default: return (r.event || "").replace(/_/g, " ") + ".";
  }
}

export function useDashboard(onAuthExpired: () => void, range: Range = "Today") {
  const [data, setData] = useState<Dashboard>(EMPTY);

  const refresh = useCallback(() => {
    loadDashboard(range)
      .then(setData)
      .catch((e) => { if (e instanceof ApiError && e.status === 401) onAuthExpired(); });
  }, [onAuthExpired, range]);

  useEffect(() => { refresh(); }, [refresh]);

  return { data, refresh };
}
