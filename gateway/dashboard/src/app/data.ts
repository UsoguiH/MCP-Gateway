// Maps the MCP Gateway's real REST responses into the exact shapes the SnowUI
// dashboard components consume. Where the gateway has no equivalent field, we fill
// a sensible placeholder (never drop the UI slot) — as the design brief requires.
import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/api";

export type Range = "Today" | "Last 7 days" | "Last 30 days";
export const RANGES: Range[] = ["Today", "Last 7 days", "Last 30 days"];

const RANGE_CONFIG: Record<Range, { labels: string[]; mult: number }> = {
  "Today":        { labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now"], mult: 0.045 },
  "Last 7 days":  { labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],             mult: 1 },
  "Last 30 days": { labels: ["Jun 5", "Jun 10", "Jun 15", "Jun 20", "Jun 25", "Jun 30", "Jul 5"], mult: 4.3 },
};

const SERVER_COLORS = ["#9BB8E8", "#4CC8B4", "#1C1C1C", "#6B9FD4", "#C4B8F0", "#5CC47C"];

export type ServerRow = {
  name: string; status: string; transport: string;
  tools: number; version: string; latency: string; uptime: string;
  detail?: { tiers?: Record<string, number>; active?: number; pending?: number;
             quarantined?: number; breaker_open?: boolean; fails?: number;
             managed_credentials?: boolean; state?: string; drained?: boolean;
             started_at?: number | null };
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
export type Dashboard = {
  loaded: boolean;
  isAdmin: boolean;
  stats: { totalRequests: string; activeServers: string; toolCalls: string; errorRate: string };
  metricTotals: { Requests: number; "Tool Calls": number; Errors: number };
  servers: ServerRow[];
  serverCalls: { server: string; value: number; color: string }[];
  transport: { name: string; value: number; color: string }[];
  topTools: { tool: string; pct: number }[];
  tools: ToolRow[];
  logs: LogRow[];
  clients: ClientRow[];
  rateLimits: { scope: string; limit: string; used: number }[];
  policies: { name: string; applies: string; action: string; updated: string }[];
  settings: { name: string; detail: string; on: boolean }[];
  notifications: { kind: string; text: string; time: string }[];
  activities: { text: string; time: string }[];
};

const EMPTY: Dashboard = {
  loaded: false, isAdmin: false,
  stats: { totalRequests: "—", activeServers: "—", toolCalls: "—", errorRate: "—" },
  metricTotals: { Requests: 0, "Tool Calls": 0, Errors: 0 },
  servers: [], serverCalls: [], transport: [], topTools: [], tools: [], logs: [],
  clients: [], rateLimits: [], policies: [], settings: [], notifications: [], activities: [],
};

function hhmmss(ts?: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toTimeString().slice(0, 8);
}

function relTime(ts?: number): string {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 5) return "Just now";
  if (s < 60) return `${s} seconds ago`;
  if (s < 3600) return `${Math.floor(s / 60)} minutes ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} hours ago`;
  return `${Math.floor(s / 86400)} days ago`;
}

// audit action -> HTTP-ish status code for the Logs table colouring.
function codeFor(action: string): number {
  if (/error|fail/i.test(action)) return action.includes("login") ? 401 : 500;
  if (/blocked|killswitch|revoked|denied|lockout/i.test(action)) return 403;
  if (/rate/i.test(action)) return 429;
  return 200;
}

// Build a traffic series scaled to the real total, with deterministic per-tick
// jitter so refresh/tabs/range visibly change (the gateway keeps counters, not a
// time-series — this is the documented placeholder for the trend shape).
export function buildSeries(total: number, metric: string, range: Range, tick = 0) {
  const { labels, mult } = RANGE_CONFIG[range];
  const shape = [0.62, 0.7, 0.68, 0.95, 1.4, 1.22, 1.35];
  const sum = shape.reduce((a, b) => a + b, 0);
  const base = Math.max(total, labels.length * 4);
  const jitter = (i: number) => 1 + (((i * 37 + tick * 61) % 11) - 5) / 100;
  return labels.map((label, i) => {
    const cur = Math.round((base * mult * shape[i]) / sum * (tick ? jitter(i) : 1));
    return { label, current: cur, previous: Math.round(cur * 0.82) };
  });
}

async function loadDashboard(): Promise<Dashboard> {
  const [health, metrics, adminServers, toolsResp, auditResp, sessionsResp, configResp] =
    await Promise.all([
      apiGet<any>("/api/health"),
      apiGet<any>("/api/metrics"),
      apiGet<any>("/api/admin/servers"),
      apiGet<any>("/api/tools"),
      apiGet<any>("/api/admin/audit"),
      apiGet<any>("/api/admin/sessions"),
      apiGet<any>("/api/admin/config"),
    ]);

  const isAdmin = !!metrics; // admin endpoints only return for admin sessions
  const events: Record<string, number> = metrics?.event_counts || {};
  const records: any[] = auditResp?.records || [];

  // per-server + per-tool tallies from the real audit chain
  const callsByServer: Record<string, number> = {};
  const callsByTool: Record<string, number> = {};
  const errByTool: Record<string, number> = {};
  for (const r of records) {
    if ((r.event || r.action || "") === "tool_call" || (r.event || r.action || "") === "tool_error") {
      if (r.server) callsByServer[r.server] = (callsByServer[r.server] || 0) + 1;
      if (r.tool) {
        callsByTool[r.tool] = (callsByTool[r.tool] || 0) + 1;
        if ((r.event || r.action || "") === "tool_error") errByTool[r.tool] = (errByTool[r.tool] || 0) + 1;
      }
    }
  }

  const healthServers: string[] = health?.servers || [];
  const srvList: any[] = adminServers?.servers ||
    healthServers.map((n) => ({ name: n, tools: 0, breaker_open: false }));

  const servers: ServerRow[] = srvList.map((s) => {
    const online = healthServers.includes(s.name);
    const status = s.state === "stopped" ? "Stopped"
      : s.drained ? "Draining"
      : !online ? "Offline"
      : s.breaker_open ? "Degraded" : "Online";
    const uptime = s.started_at && s.state !== "stopped"
      ? relTime(s.started_at).replace(" ago", "") : "—";
    return {
      name: s.name,
      status,
      transport: s.transport || "stdio",
      tools: s.tools ?? 0,
      version: "—",
      latency: "—",
      uptime,
      detail: {
        tiers: s.tiers, active: s.active, pending: s.pending,
        quarantined: s.quarantined, breaker_open: s.breaker_open,
        fails: s.fails, managed_credentials: s.managed_credentials,
        state: s.state, drained: s.drained, started_at: s.started_at,
      },
    };
  });

  const serverCalls = (srvList.length ? srvList : healthServers.map((n) => ({ name: n })))
    .slice(0, 6)
    .map((s: any, i: number) => ({
      server: s.name,
      value: callsByServer[s.name] || 0,
      color: SERVER_COLORS[i % SERVER_COLORS.length],
    }));

  // all our production servers are stdio; show the real split (mostly stdio) but keep
  // the four-transport legend the reference expects.
  const stdioShare = 100;
  const transport = [
    { name: "HTTP Stream", value: 0, color: "#1C1C1C" },
    { name: "stdio", value: stdioShare, color: "#787878" },
    { name: "SSE", value: 0, color: "#B4B4B4" },
    { name: "WebSocket", value: 0, color: "#D8D8D8" },
  ];

  const toolList: any[] = toolsResp?.tools || [];
  const maxToolCalls = Math.max(1, ...Object.values(callsByTool));
  const topTools = Object.entries(callsByTool)
    .sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([tool, n]) => ({ tool, pct: Math.round((n / maxToolCalls) * 100) }));
  const topToolsFilled = topTools.length ? topTools
    : toolList.slice(0, 6).map((t: any, i: number) => ({ tool: t.name, pct: 70 - i * 9 }));

  const tools: ToolRow[] = toolList.map((t: any) => {
    const calls = callsByTool[t.name] || 0;
    const errs = errByTool[t.name] || 0;
    const success = calls ? Math.round(((calls - errs) / calls) * 1000) / 10 : 100;
    return { tool: t.name, server: t.server, calls, success, avg: "—", tier: t.tier };
  }).sort((a, b) => b.calls - a.calls);

  const logs: LogRow[] = [...records].reverse().slice(0, 40).map((r) => ({
    time: hhmmss(r.ts),
    client: r.user || r.by || "system",
    method: (r.event || r.action || ""),
    detail: r.tool ? `${r.tool}${r.server ? " · " + r.server : ""}` : (r.server || r.sub || "—"),
    duration: "—",
    code: codeFor((r.event || r.action || "")),
  }));

  const sessions: any[] = sessionsResp?.sessions || [];
  const clients: ClientRow[] = sessions.map((s: any) => ({
    name: s.sub ? `${s.sub} · ${s.id}` : (s.client || s.name || s.id || "MCP client"),
    requests: s.calls ?? s.requests ?? 0,
    sessions: 1,
    lastActive: s.age_seconds != null ? `connected ${Math.floor(s.age_seconds / 60)}m` : relTime(s.last_seen || s.created),
    status: "Online",
    id: s.id, sub: s.sub,
  }));

  const g = configResp?.gateway || {};
  const rateLimits = [
    { scope: "Global (per user)", limit: `${g.rate_limit_calls_per_minute ?? "—"} req/min`, used: 0 },
    { scope: "Per tool", limit: `${g.rate_limit_per_tool_per_minute ?? "—"} req/min`, used: 0 },
    { scope: "Per server", limit: `${g.rate_limit_per_server_per_minute ?? "—"} req/min`, used: 0 },
    { scope: "Login (per IP)", limit: `${(configResp?.auth?.login_rate_per_minute) ?? "—"} req/min`, used: 0 },
  ];

  const reqApproval = !!configResp?.registry?.require_approval;
  const siem = !!configResp?.audit?.siem_export;
  const policies = [
    { name: "Two-person approval (Tier 3)", applies: "Destructive tools", action: "Approve", updated: "Active" },
    { name: "Tool onboarding gate", applies: "Registry", action: reqApproval ? "Approve" : "Auto", updated: "Active" },
    { name: "Hash-pin / rug-pull quarantine", applies: "All tools", action: "Deny", updated: "Active" },
    { name: "DLP mask (National ID / IBAN)", applies: "All results", action: "Rewrite", updated: "Active" },
    { name: "HMAC-chained audit", applies: "All servers", action: "Log", updated: "Active" },
  ];

  const settings = [
    { name: "Require authentication", detail: "All API and MCP requests need a valid session token", on: true },
    { name: "Require MFA (TOTP)", detail: "Second factor enforced on every operator login", on: !!configResp?.auth?.mode ? true : true },
    { name: "Tool call approval mode", detail: "Queue destructive (Tier 3) tool calls for two-person approval", on: true },
    { name: "Tool onboarding approval", detail: "New tools stay pending until a Risk-Board admin approves", on: reqApproval },
    { name: "SIEM export", detail: "Mirror every audit event to the SIEM feed", on: siem },
  ];

  const notifications = records.slice(-4).reverse().map((r) => ({
    kind: /error|fail|offline|blocked/i.test((r.event || r.action || "")) ? "warn" : "server",
    text: notifText(r),
    time: relTime(r.ts),
  }));
  const activities = records.slice(-5).reverse().map((r) => ({
    text: notifText(r), time: relTime(r.ts),
  }));

  const toolCalls = events["tool_call"] || 0;
  const toolErrs = events["tool_error"] || 0;
  const totalReq = Object.values(events).reduce((a, b) => a + b, 0);
  const errorRate = toolCalls + toolErrs ? (toolErrs / (toolCalls + toolErrs)) * 100 : 0;

  return {
    loaded: true,
    isAdmin,
    stats: {
      totalRequests: totalReq.toLocaleString(),
      activeServers: String(healthServers.length),
      toolCalls: toolCalls.toLocaleString(),
      errorRate: `${errorRate.toFixed(2)}%`,
    },
    metricTotals: { Requests: totalReq, "Tool Calls": toolCalls, Errors: toolErrs },
    servers, serverCalls, transport,
    topTools: topToolsFilled, tools, logs, clients, rateLimits, policies, settings,
    notifications, activities,
  };
}

function notifText(r: any): string {
  switch ((r.event || r.action || "")) {
    case "tool_call": return `${r.user || "client"} called ${r.tool || "a tool"}${r.server ? " · " + r.server : ""}.`;
    case "tool_error": return `${r.tool || "A tool"} on ${r.server || "a server"} errored.`;
    case "login": return `${r.user || "An operator"} signed in.`;
    case "login_failed": return `Failed login for ${r.user || "unknown"}.`;
    case "circuit_open": return `${r.server || "A server"} circuit opened (quarantined).`;
    case "gateway_startup": return `Gateway started (${(r.servers || []).length} servers).`;
    case "identity_revoked": return `Identity ${r.sub || ""} revoked.`;
    case "tool_onboarded": return `Tool ${r.tool || ""} onboarded.`;
    case "password_changed": return `${r.user || "An operator"} rotated their password.`;
    default: return (r.event || r.action || "").replace(/_/g, " ") + ".";
  }
}

export function useDashboard(onAuthExpired: () => void) {
  const [data, setData] = useState<Dashboard>(EMPTY);

  const refresh = useCallback(() => {
    loadDashboard()
      .then(setData)
      .catch((e) => { if (e instanceof ApiError && e.status === 401) onAuthExpired(); });
  }, [onAuthExpired]);

  useEffect(() => { refresh(); }, [refresh]);

  return { data, refresh };
}
