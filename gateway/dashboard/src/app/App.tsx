import { useMemo, useState, useCallback } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell,
} from "recharts";
import {
  ChevronDown, ChevronRight, Search, Sun, Moon, RotateCcw, Bell, Maximize2,
  PanelLeft, PanelRight, LogOut,
} from "lucide-react";

import imgByewind from "@/imports/DashboardOverview/5d1e58c8086fe7ad86b64a6151f47a2a2aa8357a.png";
import imgAbstract03 from "@/imports/DashboardOverview/a6291df320bba44005babfd6bca1bab752b24ac1.png";
import imgFemale03 from "@/imports/DashboardOverview/82dab5f59562fb682b36a8ccaa46b847a00123c7.png";
import imgMale02 from "@/imports/DashboardOverview/ff23b0883aad53dd3045b7033a7f72108d9cf839.png";
import img3D03 from "@/imports/DashboardOverview/efb4c5c371433b7befe07a6b8161dddcd8d2353c.png";
import imgAbstract04 from "@/imports/DashboardOverview/f10b0beb90c63012fc68d587fb84811d19f6de9e.png";

import {
  CheckCheck, ScrollText, Users, PackageSearch, ShieldBan, Siren, SearchCheck,
  Scale, Lock, Activity, MonitorSmartphone, KeyRound, Gauge, ShieldCheck,
} from "lucide-react";
import {
  GridIcon, ServerIcon, WrenchIcon, GatewayIcon, ShieldIcon, BellSmallIcon,
  GearIcon, HomeIcon, ServerSmallIcon, KeySmallIcon, WarnSmallIcon, ActivitySmallIcon,
} from "./icons";
import {
  useDashboard, buildSeries, RANGES, type Range, type Dashboard, type ServerRow,
} from "./data";
import { getUser, logout as apiLogout, apiPost, type User } from "@/api";
import { LoginScreen, ChangePasswordScreen } from "./Login";
import {
  ApprovalsPage, AuditPage, IdentitiesPage, RegistryPage, KillSwitchPage,
  AnomalyPage, InvestigatePage,
} from "./AdminPages";
import { ApiKeysPage } from "./AccessPages";
import {
  useNotifications, NotificationFeed, NotificationDropdown, BellBadge, type Notif,
} from "./notify";
import { ConfirmModal, Field, GhostBtn, Modal, PrimaryBtn, SelectInput, TextInput } from "./ui";
import { toast, Toaster } from "./toast";

type Page =
  | "Overview" | "Servers" | "Tools" | "Logs" | "Clients"
  | "API Keys" | "Rate Limits" | "Policies" | "Alerts" | "Settings"
  | "Approvals" | "Audit" | "Identities" | "Registry" | "Kill Switch"
  | "Anomaly" | "Sessions";

const STATUS_COLOR: Record<string, string> = {
  Online: "#4AA785", Degraded: "#E5A000", Offline: "#D9534F",
  Stopped: "#787878", Draining: "#E5A000",
};
const CLIENT_COLORS = ["#edeefc", "#e6f1fd", "#e3f5e5", "#fdf0e6", "#f2e6fd", "#e6fdfa"];
const ACTIVITY_AVATARS = [imgAbstract03, imgFemale03, imgMale02, img3D03, imgAbstract04];

// ── Tiny helpers ─────────────────────────────────────────────────────────────

function Avatar({ src, alt = "", size = 24 }: { src: string; alt?: string; size?: number }) {
  return <img src={src} alt={alt} style={{ width: size, height: size }} className="rounded-full object-cover shrink-0 bg-black/4" />;
}

function InitialAvatar({ name, bg, size = 24 }: { name: string; bg: string; size?: number }) {
  const initials = name.split(/[\s-]+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  return (
    <div className="rounded-full flex items-center justify-center shrink-0 font-medium text-black/70"
      style={{ background: bg, width: size, height: size, fontSize: size >= 28 ? 11 : 10 }}>
      {initials}
    </div>
  );
}

function formatK(n: number) { return n >= 1000 ? (n / 1000).toFixed(0) + "K" : String(n); }

function StatusDot({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? "rgba(0,0,0,0.4)";
  return (
    <span className="flex items-center gap-1.5 text-xs whitespace-nowrap" style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: color }} />
      {status}
    </span>
  );
}

// ── Sidebar ──────────────────────────────────────────────────────────────────

const BW = 2.2;   // bold stroke for nav icons

const railItems: { page: Page; icon: React.ReactNode; label: string }[] = [
  { page: "Overview", icon: <GridIcon />, label: "Overview" },
  { page: "Servers", icon: <ServerIcon />, label: "Servers" },
  { page: "Tools", icon: <WrenchIcon />, label: "Tools" },
  { page: "Logs", icon: <GatewayIcon />, label: "Traffic & Logs" },
  { page: "Approvals", icon: <CheckCheck size={16} strokeWidth={2.2} />, label: "Approvals" },
  { page: "Registry", icon: <PackageSearch size={16} strokeWidth={2.2} />, label: "Registry" },
  { page: "Identities", icon: <Users size={16} strokeWidth={2.2} />, label: "Identities" },
  { page: "Anomaly", icon: <Siren size={16} strokeWidth={2.2} />, label: "Anomaly" },
  { page: "Kill Switch", icon: <ShieldBan size={16} strokeWidth={2.2} />, label: "Kill Switch" },
  { page: "Audit", icon: <ScrollText size={16} strokeWidth={2.2} />, label: "Audit" },
  { page: "Sessions", icon: <SearchCheck size={16} strokeWidth={2.2} />, label: "Sessions" },
  { page: "Settings", icon: <GearIcon />, label: "Settings" },
];

function SideNavRail({ page, setPage, onLogout }: { page: Page; setPage: (p: Page) => void; onLogout: () => void }) {
  return (
    <aside className="w-[72px] h-full flex flex-col items-center overflow-y-auto border-r border-black/10 py-3 gap-1.5 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="p-1 mb-2"><Avatar src={imgByewind} size={30} alt="MCP Gateway" /></div>
      {railItems.map((item) => (
        <button key={item.page} title={item.label} onClick={() => setPage(item.page)}
          className={`p-2.5 rounded-xl cursor-pointer ${page === item.page ? "bg-black/[0.04]" : "hover:bg-black/[0.03]"}`}>
          <span className="flex items-center justify-center" style={{ transform: "scale(1.35)", width: 16, height: 16 }}>{item.icon}</span>
        </button>
      ))}
      <div className="mt-auto pt-4">
        <button title="Logout" onClick={onLogout} className="p-2.5 rounded-xl hover:bg-black/[0.03] cursor-pointer">
          <LogOut size={20} strokeWidth={1.5} className="text-black" />
        </button>
      </div>
    </aside>
  );
}

function SideNav({ page, setPage, open, onLogout }: { page: Page; setPage: (p: Page) => void; open: boolean; onLogout: () => void }) {
  if (!open) {
    return <div className="shrink-0 h-full overflow-hidden transition-all duration-200" style={{ width: 72 }}>
      <SideNavRail page={page} setPage={setPage} onLogout={onLogout} />
    </div>;
  }
  return (
    <div className="shrink-0 h-full overflow-hidden transition-all duration-200" style={{ width: 212 }}>
      <aside className="w-[212px] h-full flex flex-col overflow-y-auto border-r border-black/10 py-3 px-3 gap-0 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
        <div className="flex items-center gap-2 px-2 py-2 rounded-lg mb-1">
          <Avatar src={imgByewind} size={24} alt="MCP Gateway" />
          <span className="text-sm text-black font-normal">MCP Gateway</span>
        </div>
        <div className="flex gap-1 px-1 mb-1">
          <button className="text-xs text-black/40 px-3 py-1 rounded-full">Favorites</button>
          <button className="text-xs text-black/20 px-3 py-1 rounded-full">Recently</button>
        </div>
        <NavBullet label="Overview" onClick={() => setPage("Overview")} />
        <NavBullet label="Servers" onClick={() => setPage("Servers")} />
        <p className="text-xs text-black/40 px-3 py-1 mt-2">Dashboards</p>
        <NavItem icon={<GridIcon />} label="Overview" active={page === "Overview"} onClick={() => setPage("Overview")} />
        <NavItem icon={<ServerIcon />} label="Servers" active={page === "Servers"} onClick={() => setPage("Servers")} />
        <NavItem icon={<WrenchIcon />} label="Tools" active={page === "Tools"} onClick={() => setPage("Tools")} />
        <p className="text-xs text-black/40 px-3 py-1 mt-2">Gateway</p>
        {/* Traffic — collapsible parent group with icon sub-tabs */}
        <NavGroup label="Traffic" icon={<GatewayIcon />} page={page} setPage={setPage} items={[
          { page: "Logs", icon: <Activity size={15} strokeWidth={BW} /> },
          { page: "Clients", icon: <MonitorSmartphone size={15} strokeWidth={BW} /> },
          { page: "API Keys", icon: <KeyRound size={15} strokeWidth={BW} /> },
          { page: "Rate Limits", icon: <Gauge size={15} strokeWidth={BW} /> },
        ]} />

        {/* Governance — collapsible parent group */}
        <NavGroup label="Governance" icon={<Scale size={16} strokeWidth={1.6} />} page={page} setPage={setPage} items={[
          { page: "Approvals", icon: <CheckCheck size={15} strokeWidth={BW} /> },
          { page: "Registry", icon: <PackageSearch size={15} strokeWidth={BW} /> },
          { page: "Identities", icon: <Users size={15} strokeWidth={BW} /> },
          { page: "Policies", icon: <ShieldCheck size={15} strokeWidth={BW} /> },
        ]} />

        {/* Security — collapsible parent group */}
        <NavGroup label="Security" icon={<Lock size={16} strokeWidth={1.6} />} page={page} setPage={setPage} items={[
          { page: "Anomaly", icon: <Siren size={15} strokeWidth={BW} /> },
          { page: "Kill Switch", icon: <ShieldBan size={15} strokeWidth={BW} /> },
          { page: "Audit", icon: <ScrollText size={15} strokeWidth={BW} /> },
          { page: "Sessions", icon: <SearchCheck size={15} strokeWidth={BW} /> },
        ]} />

        <p className="text-xs text-black/40 px-3 py-1 mt-2">System</p>
        <NavItemChevron icon={<BellSmallIcon />} label="Alerts" active={page === "Alerts"} onClick={() => setPage("Alerts")} />
        <NavItemChevron icon={<GearIcon />} label="Settings" active={page === "Settings"} onClick={() => setPage("Settings")} />
        <button onClick={onLogout} className="mt-auto pt-4 flex items-center gap-2 px-2 py-2 rounded-lg hover:bg-black/[0.03] text-sm text-black cursor-pointer">
          <LogOut size={16} strokeWidth={1.5} className="text-black shrink-0" />
          <span className="font-normal">Logout</span>
        </button>
      </aside>
    </div>
  );
}

function NavBullet({ label, onClick }: { label: string; onClick?: () => void }) {
  return (
    <div onClick={onClick} className="flex items-center gap-2 px-2 py-2 rounded-lg text-sm text-black hover:bg-black/[0.03] cursor-pointer">
      <span className="w-4 h-4 flex items-center justify-center">
        <svg viewBox="0 0 6 6" width="6" height="6"><circle cx="3" cy="3" r="2" fill="black" fillOpacity="0.2" /></svg>
      </span>
      {label}
    </div>
  );
}
function NavItem({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} className={`flex items-center gap-2 px-2 py-2 rounded-lg text-sm text-black cursor-pointer ${active ? "bg-black/[0.04]" : "hover:bg-black/[0.03]"}`}>
      <span className="w-4 h-4 flex items-center justify-center opacity-0"><ChevronRight size={10} /></span>
      <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
      <span className="font-normal">{label}</span>
    </div>
  );
}
function NavItemChevron({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} className={`flex items-center gap-2 px-2 py-2 rounded-lg text-sm text-black cursor-pointer ${active ? "bg-black/[0.04]" : "hover:bg-black/[0.03]"}`}>
      <span className="w-4 h-4 flex items-center justify-center text-black/20"><ChevronRight size={10} /></span>
      <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
      <span className="font-normal">{label}</span>
    </div>
  );
}

// Collapsible parent group (like "Traffic"): a header that expands to nested,
// icon-labelled sub-tabs. Auto-opens when the active page lives inside it.
type NavChild = { page: Page; icon: React.ReactNode };
function NavGroup({ label, icon, items, page, setPage }: { label: string; icon: React.ReactNode; items: NavChild[]; page: Page; setPage: (p: Page) => void }) {
  const [open, setOpen] = useState(items.some((it) => it.page === page));
  return (
    <>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1 w-full px-2 py-2 rounded-lg hover:bg-black/[0.03] text-sm">
        <span className="text-black/30 text-xs mr-1">{open ? <ChevronDown size={13} strokeWidth={2.4} /> : <ChevronRight size={13} strokeWidth={2.4} />}</span>
        <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
        <span className="text-black text-sm font-normal">{label}</span>
      </button>
      {open && items.map(({ page: p, icon: ic }) => (
        <div key={p} onClick={() => setPage(p)}
          className={`flex items-center gap-2 pl-8 pr-2 py-[6px] text-sm text-black rounded-lg cursor-pointer ${page === p ? "bg-black/[0.04]" : "hover:bg-black/[0.03]"}`}>
          <span className="w-4 h-4 flex items-center justify-center shrink-0 text-black">{ic}</span>
          {p}
        </div>
      ))}
    </>
  );
}

// ── Header ───────────────────────────────────────────────────────────────────

function Header({
  page, setPage, query, setQuery, leftOpen, setLeftOpen, rightOpen, setRightOpen,
  dark, setDark, onRefresh, notifs, unread, onMarkAllRead,
}: {
  page: Page; setPage: (p: Page) => void; query: string; setQuery: (q: string) => void;
  leftOpen: boolean; setLeftOpen: (v: boolean) => void; rightOpen: boolean; setRightOpen: (v: boolean) => void;
  dark: boolean; setDark: (v: boolean) => void; onRefresh: () => void;
  notifs: Notif[]; unread: number; onMarkAllRead: () => void;
}) {
  const [bellOpen, setBellOpen] = useState(false);
  const [spinning, setSpinning] = useState(false);
  const refresh = () => { onRefresh(); setSpinning(true); setTimeout(() => setSpinning(false), 500); };
  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else document.documentElement.requestFullscreen();
  };
  return (
    <header className="h-[60px] shrink-0 flex items-center justify-between px-7 border-b border-black/10 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="flex items-center gap-2">
        <div className="flex gap-1 mr-2">
          <button onClick={() => setLeftOpen(!leftOpen)} title="Toggle navigation"
            className={`p-1 rounded-lg hover:bg-black/[0.04] ${leftOpen ? "" : "bg-black/[0.04]"}`}>
            <PanelLeft size={16} strokeWidth={1.5} className="text-black" />
          </button>
          <button title="Home" onClick={() => setPage("Overview")} className="p-1 rounded-lg hover:bg-black/[0.04]"><HomeIcon /></button>
        </div>
        <div className="flex items-center gap-1 text-xs">
          <span onClick={() => setPage("Overview")} className="text-black/40 px-2 py-1 rounded-lg hover:bg-black/[0.04] cursor-pointer">Gateway</span>
          <span className="text-black/20">/</span>
          <span className="text-black px-2 py-1 rounded-lg font-normal cursor-pointer">{page}</span>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 bg-black/[0.04] rounded-2xl px-3 py-1 w-40">
          <Search size={14} className="text-black/30 shrink-0" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search"
            className="text-sm text-black bg-transparent outline-none border-none w-full placeholder:text-black/20" />
          <span className="text-xs text-black/20 border border-black/10 rounded px-1">/</span>
        </div>
        <div className="flex items-center gap-1">
          <button title={dark ? "Light mode" : "Dark mode"} onClick={() => setDark(!dark)} className="p-1 rounded-lg hover:bg-black/[0.04]">
            {dark ? <Moon size={16} className="text-black" /> : <Sun size={16} className="text-black" />}
          </button>
          <button title="Refresh data" onClick={refresh} className="p-1 rounded-lg hover:bg-black/[0.04]">
            <RotateCcw size={16} className="text-black" style={{ transition: "transform 0.5s", transform: spinning ? "rotate(-360deg)" : "none" }} />
          </button>
          <div className="relative">
            <button title="Notifications" onClick={() => setBellOpen(!bellOpen)}
              className={`relative p-1 rounded-lg hover:bg-black/[0.04] ${bellOpen ? "bg-black/[0.04]" : ""}`}>
              <Bell size={16} className="text-black" />
              <BellBadge unread={unread} />
            </button>
            {bellOpen && (
              <NotificationDropdown items={notifs} unread={unread}
                onMarkAllRead={onMarkAllRead}
                onViewAll={() => { setRightOpen(true); setBellOpen(false); }} />
            )}
          </div>
          <button title="Fullscreen" onClick={toggleFullscreen} className="p-1 rounded-lg hover:bg-black/[0.04]">
            <Maximize2 size={16} className="text-black" />
          </button>
          <button onClick={() => setRightOpen(!rightOpen)} title="Toggle right panel"
            className={`p-1 rounded-lg hover:bg-black/[0.04] ${rightOpen ? "" : "bg-black/[0.04]"}`}>
            <PanelRight size={16} strokeWidth={1.5} className="text-black" />
          </button>
        </div>
      </div>
    </header>
  );
}

// ── Stat cards + charts ───────────────────────────────────────────────────────

function StatCard({ label, value, change, up, bg }: { label: string; value: string; change: string; up: boolean; bg: string }) {
  return (
    <div className="flex-1 min-w-[180px] rounded-[20px] p-6 flex flex-col gap-2" style={{ background: bg }}>
      <p className="text-sm text-black font-normal">{label}</p>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="text-2xl font-semibold text-[#1c1c1c]">{value}</span>
        <div className="flex items-center gap-1">
          <span className="text-xs text-black">{change}</span>
          {up
            ? <svg width="16" height="16" viewBox="0 0 12.5 8"><path d="M1 7L6 2L11 7" stroke="black" strokeWidth="1.5" strokeLinecap="round" fill="none" /></svg>
            : <svg width="16" height="16" viewBox="0 0 12.5 8"><path d="M1 1L6 6L11 1" stroke="black" strokeWidth="1.5" strokeLinecap="round" fill="none" /></svg>}
        </div>
      </div>
    </div>
  );
}

const CHART_TABS = ["Requests", "Tool Calls", "Errors"];

function TrafficChart({ range, tick, totals }: { range: Range; tick: number; totals: Dashboard["metricTotals"] }) {
  const [tab, setTab] = useState("Requests");
  const data = useMemo(() => buildSeries(totals[tab as keyof typeof totals] ?? 0, tab, range, tick), [tab, range, tick, totals]);
  return (
    <div className="flex-1 min-w-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4" style={{ minHeight: 280 }}>
      <div className="flex items-center gap-4 flex-wrap">
        {CHART_TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`text-sm ${tab === t ? "font-semibold text-black" : "text-black/40 font-normal"}`}>{t}</button>
        ))}
        <span className="text-black/20 text-sm">|</span>
        <div className="flex items-center gap-3 ml-1">
          <span className="flex items-center gap-1.5 text-xs text-black"><span className="w-2 h-2 rounded-full bg-black inline-block" /> Current</span>
          <span className="flex items-center gap-1.5 text-xs text-black/40"><span className="w-2 h-2 rounded-full bg-black/30 inline-block" /> Previous</span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="label" tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
          <YAxis tickFormatter={formatK} tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={36} />
          <Tooltip formatter={(v: number) => v.toLocaleString()} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
          <Area type="monotone" dataKey="previous" stroke="rgba(160,188,232,0.8)" strokeWidth={1.5} strokeDasharray="4 6" fill="none" dot={false} />
          <Area type="monotone" dataKey="current" stroke="black" strokeWidth={1.5} fill="none" dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopTools({ data }: { data: Dashboard["topTools"] }) {
  return (
    <div className="w-[220px] shrink-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-3">
      <p className="text-sm font-normal text-black">Top Tools</p>
      <div className="flex flex-col gap-3">
        {(data.length ? data : [{ tool: "—", pct: 0 }]).map(({ tool, pct }, i) => (
          <div key={tool + i} className="flex items-center gap-3">
            <span className="text-sm text-black w-[92px] shrink-0 truncate">{tool}</span>
            <div className="flex-1 h-[3px] bg-black/10 rounded-full overflow-hidden">
              <div className="h-full bg-black/60 rounded-full" style={{ width: `${pct}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CallsByServer({ data }: { data: Dashboard["serverCalls"] }) {
  const d = data.length ? data : [{ server: "—", value: 0, color: "#9BB8E8" }];
  return (
    <div className="flex-1 min-w-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4" style={{ minHeight: 260 }}>
      <p className="text-sm font-normal text-black">Tool Calls by Server</p>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={d} margin={{ top: 4, right: 4, left: 0, bottom: 0 }} barSize={28}>
          <XAxis dataKey="server" tick={{ fontSize: 11, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
          <YAxis tickFormatter={formatK} tick={{ fontSize: 11, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={36} />
          <Tooltip formatter={(v: number) => v.toLocaleString()} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>{d.map((x) => <Cell key={x.server} fill={x.color} />)}</Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TrafficByTransport({ data }: { data: Dashboard["transport"] }) {
  return (
    <div className="w-[280px] shrink-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4">
      <p className="text-sm font-normal text-black">Traffic by Transport</p>
      <div className="flex items-center gap-4">
        <PieChart width={120} height={120}>
          <Pie data={data} cx={55} cy={55} innerRadius={36} outerRadius={55} dataKey="value" startAngle={90} endAngle={-270} strokeWidth={0}>
            {data.map((d) => <Cell key={d.name} fill={d.color} />)}
          </Pie>
        </PieChart>
        <div className="flex flex-col gap-2">
          {data.map((d) => (
            <div key={d.name} className="flex items-center justify-between gap-6">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: d.color }} />
                <span className="text-xs text-black whitespace-nowrap">{d.name}</span>
              </div>
              <span className="text-xs text-black font-normal">{d.value}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const latencyData = [
  { label: "Mon", p50: 118, p95: 320 }, { label: "Tue", p50: 126, p95: 355 },
  { label: "Wed", p50: 112, p95: 298 }, { label: "Thu", p50: 145, p95: 410 },
  { label: "Fri", p50: 168, p95: 520 }, { label: "Sat", p50: 121, p95: 305 },
  { label: "Sun", p50: 109, p95: 276 },
];

function GatewayPerformance() {
  return (
    <div className="flex flex-col gap-4">
      <h2 className="text-sm font-semibold text-black">Gateway Performance</h2>
      <div className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4" style={{ minHeight: 240 }}>
        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-sm font-semibold text-black">Latency</span>
          <div className="flex items-center gap-3 ml-1">
            <span className="flex items-center gap-1.5 text-xs text-black"><span className="w-2 h-2 rounded-full bg-black inline-block" /> p50</span>
            <span className="flex items-center gap-1.5 text-xs text-black/40"><span className="w-2 h-2 rounded-full bg-[#A0BCE8] inline-block" /> p95</span>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={latencyData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="gradP50" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="black" stopOpacity="0.12" />
                <stop offset="100%" stopColor="black" stopOpacity="0" />
              </linearGradient>
            </defs>
            <XAxis dataKey="label" tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
            <YAxis tickFormatter={(v: number) => `${v}ms`} tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={44} />
            <Tooltip formatter={(v: number) => `${v} ms`} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
            <Area type="monotone" dataKey="p95" stroke="#A0BCE8" strokeWidth={1.5} fill="none" dot={false} />
            <Area type="monotone" dataKey="p50" stroke="black" strokeWidth={1.5} fill="url(#gradP50)" dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ── Table primitives ─────────────────────────────────────────────────────────

function CardBox({ children, title }: { children: React.ReactNode; title?: string }) {
  return <div className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4">{title && <p className="text-sm font-normal text-black">{title}</p>}{children}</div>;
}
function Th({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <th className={`text-xs text-black/40 font-normal pb-3 pr-4 ${right ? "text-right" : "text-left"}`}>{children}</th>;
}
function Td({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <td className={`text-sm text-black py-3 pr-4 border-t border-black/5 ${right ? "text-right" : "text-left"}`}>{children}</td>;
}
function Empty({ label }: { label: string }) {
  return <div className="text-sm text-black/30 py-6 text-center">{label}</div>;
}

// ── Pages ────────────────────────────────────────────────────────────────────

function OverviewPage({ d, range, cycleRange, tick }: { d: Dashboard; range: Range; cycleRange: () => void; tick: number }) {
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Overview</h1>
        <button onClick={cycleRange} className="flex items-center gap-1 text-xs text-black px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">
          {range} <ChevronDown size={12} className="text-black/40" />
        </button>
      </div>
      <div className="flex gap-3 flex-wrap">
        <StatCard label="Total Requests" value={d.stats.totalRequests} change="+11.01%" up bg="#edeefc" />
        <StatCard label="Active Servers" value={d.stats.activeServers} change="live" up bg="#e6f1fd" />
        <StatCard label="Tool Calls" value={d.stats.toolCalls} change="+15.03%" up bg="#edeefc" />
        <StatCard label="Error Rate" value={d.stats.errorRate} change="-0.08%" up={false} bg="#e6f1fd" />
      </div>
      <div className="flex gap-3 min-w-0">
        <TrafficChart range={range} tick={tick} totals={d.metricTotals} />
        <TopTools data={d.topTools} />
      </div>
      <div className="flex gap-3 min-w-0">
        <CallsByServer data={d.serverCalls} />
        <TrafficByTransport data={d.transport} />
      </div>
      <GatewayPerformance />
    </>
  );
}

function ServersPage({ d, query, onManage, onChanged }: { d: Dashboard; query: string; onManage: (s: ServerRow) => void; onChanged: () => void }) {
  const rows = d.servers.filter((s) => s.name.toLowerCase().includes(query.toLowerCase()));
  const [addOpen, setAddOpen] = useState(false);
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Servers</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-black/40">{rows.length} of {d.servers.length} servers</span>
          <button onClick={() => setAddOpen(true)}
            className="text-xs text-white px-3 py-1.5 rounded-lg bg-[#1C1C1C] hover:opacity-80">+ Add server</button>
        </div>
      </div>
      {addOpen && <AddServerModal onClose={() => setAddOpen(false)} onAdded={() => { setAddOpen(false); onChanged(); }} />}
      <CardBox>
        {rows.length === 0 ? <Empty label="No servers connected." /> : (
          <table className="w-full">
            <thead><tr>
              <Th>Server</Th><Th>Status</Th><Th>Transport</Th><Th right>Tools</Th><Th right>Version</Th><Th right>Latency</Th><Th right>Uptime</Th><Th right></Th>
            </tr></thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.name} className="hover:bg-black/[0.02]">
                  <Td>{s.name}</Td>
                  <Td><StatusDot status={s.status} /></Td>
                  <Td>{s.transport}</Td>
                  <Td right>{s.tools}</Td>
                  <Td right>{s.version}</Td>
                  <Td right>{s.latency}</Td>
                  <Td right>{s.uptime}</Td>
                  <Td right>
                    <button onClick={() => onManage(s)} className="text-xs text-black px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04]">Manage</button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardBox>
      <div className="flex gap-3 min-w-0">
        <CallsByServer data={d.serverCalls} />
        <TrafficByTransport data={d.transport} />
      </div>
    </>
  );
}

function ManageDrawer({ server, onClose, onChanged }: { server: ServerRow; onClose: () => void; onChanged: () => void }) {
  const det = server.detail || {};
  const tiers = det.tiers || {};
  const [busy, setBusy] = useState<string | null>(null);
  const [removeOpen, setRemoveOpen] = useState(false);
  const stopped = det.state === "stopped";
  const drained = !!det.drained;

  const act = async (action: string, label: string) => {
    setBusy(action);
    try {
      await apiPost(`/api/admin/servers/${server.name}/${action}`);
      toast(label);
      onChanged();
      onClose();
    } catch (e: any) { toast(e.message || `${action} failed`, "err"); }
    finally { setBusy(null); }
  };
  const doRemove = async () => {
    setRemoveOpen(false);
    setBusy("remove");
    try {
      await apiPost(`/api/admin/servers/${server.name}/remove`);
      toast(`Server ${server.name} removed.`);
      onChanged();
      onClose();
    } catch (e: any) { toast(e.message || "remove failed", "err"); }
    finally { setBusy(null); }
  };
  const Btn = ({ action, label, busyLabel, danger }: { action: string; label: string; busyLabel: string; danger?: boolean }) => (
    <button onClick={() => act(action, `${server.name}: ${busyLabel}`)} disabled={!!busy}
      className="text-xs px-3 py-2 rounded-lg border border-black/10 hover:bg-black/[0.04] disabled:opacity-40 flex-1 min-w-[100px]"
      style={danger ? { color: "#D9534F" } : undefined}>
      {busy === action ? "Working…" : label}
    </button>
  );

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: "rgba(0,0,0,0.3)" }} onClick={onClose}>
      <div className="h-full w-[360px] bg-white p-6 flex flex-col gap-5 overflow-y-auto" style={{ fontFamily: "Inter, sans-serif" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold text-black">Manage · {server.name}</span>
          <button onClick={onClose} className="text-xs text-black/40 hover:text-black">Close</button>
        </div>
        <div className="flex items-center gap-2"><StatusDot status={server.status} /><span className="text-xs text-black/40">{server.transport}</span></div>

        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-3">
          <span className="text-sm font-normal text-black">Server actions</span>
          <div className="flex gap-2 flex-wrap">
            {stopped
              ? <Btn action="start" label="▶ Start" busyLabel="started" />
              : <>
                  <Btn action="restart" label="↻ Restart" busyLabel="restarted" />
                  <Btn action="stop" label="■ Stop" busyLabel="stopped" danger />
                </>}
            {!stopped && (drained
              ? <Btn action="undrain" label="Resume traffic" busyLabel="traffic resumed" />
              : <Btn action="drain" label="Drain" busyLabel="draining — new calls refused" />)}
            {(det.breaker_open || (det.fails ?? 0) > 0) &&
              <Btn action="breaker_reset" label="Reset breaker" busyLabel="breaker force-closed" />}
          </div>
          <button onClick={() => setRemoveOpen(true)} disabled={!!busy}
            className="text-xs px-3 py-2 rounded-lg border border-black/10 hover:bg-black/[0.04] disabled:opacity-40" style={{ color: "#D9534F" }}>
            Remove server from gateway…
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Metric label="Tools" value={String(server.tools)} />
          <Metric label="Active" value={String(det.active ?? "—")} />
          <Metric label="Pending" value={String(det.pending ?? "—")} />
          <Metric label="Quarantined" value={String(det.quarantined ?? "—")} />
        </div>
        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-3">
          <span className="text-sm font-normal text-black">Risk tiers</span>
          {[0, 1, 2, 3].map((t) => (
            <div key={t} className="flex items-center justify-between text-xs">
              <span className="text-black/60">Tier {t} · {["read", "reversible write", "human approval", "two-person"][t]}</span>
              <span className="text-black">{tiers[String(t)] ?? 0}</span>
            </div>
          ))}
        </div>
        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-2 text-xs">
          <Row label="State" value={det.state === "stopped" ? "Stopped" : drained ? "Draining" : "Running"} color={det.state === "stopped" ? "#787878" : drained ? "#E5A000" : "#4AA785"} />
          <Row label="Circuit breaker" value={det.breaker_open ? "Open (quarantined)" : "Closed"} color={det.breaker_open ? "#D9534F" : "#4AA785"} />
          <Row label="Recent failures" value={String(det.fails ?? 0)} />
          <Row label="Managed credentials" value={det.managed_credentials ? "Yes" : "No"} />
        </div>
        {removeOpen && (
          <ConfirmModal title={`Remove ${server.name}?`}
            body={<>The server disconnects immediately and stays removed across gateway restarts (its registry entries are kept in case it is re-added). Tool calls to it will fail.</>}
            confirmLabel="Remove server" onCancel={() => setRemoveOpen(false)} onConfirm={doRemove} />
        )}
      </div>
    </div>
  );
}

function AddServerModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [name, setName] = useState("");
  const [transport, setTransport] = useState("stdio");
  const [command, setCommand] = useState("python");
  const [args, setArgs] = useState("");
  const [url, setUrl] = useState("");
  const [env, setEnv] = useState("");
  const [busy, setBusy] = useState(false);
  const add = async () => {
    if (!name.trim()) { toast("Server name is required", "err"); return; }
    const envObj: Record<string, string> = {};
    for (const line of env.split("\n")) {
      const [k, ...v] = line.split("=");
      if (k.trim() && v.length) envObj[k.trim()] = v.join("=").trim();
    }
    setBusy(true);
    try {
      const r = await apiPost("/api/admin/servers/add", {
        name: name.trim(), transport,
        command: command.trim(), args: args.split(/\s+/).filter(Boolean),
        url: url.trim(), env: envObj,
      });
      toast(`Server ${r.server} connected — ${r.tools} tool(s) discovered${r.pending_tools ? `, ${r.pending_tools} pending approval` : ""}.`);
      onAdded();
    } catch (e: any) { toast(e.message || "Add failed", "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title="Add MCP server" onClose={onClose} width={460}>
      <Field label="Name (unique, no '__')"><TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. weather" autoFocus /></Field>
      <Field label="Transport">
        <SelectInput value={transport} onChange={(e) => setTransport(e.target.value)}>
          <option value="stdio">stdio (local subprocess)</option>
          <option value="http">http (remote Streamable-HTTP)</option>
        </SelectInput>
      </Field>
      {transport === "stdio" ? (
        <>
          <Field label="Command"><TextInput value={command} onChange={(e) => setCommand(e.target.value)} placeholder="python" /></Field>
          <Field label="Arguments (space-separated)"><TextInput value={args} onChange={(e) => setArgs(e.target.value)} placeholder="servers/weather_server.py" /></Field>
          <Field label="Environment (KEY=value per line; ${VAR} expands from the gateway env)">
            <textarea value={env} onChange={(e) => setEnv(e.target.value)} rows={3}
              className="bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30 font-mono"
              placeholder={"API_URL=${WEATHER_URL}"} />
          </Field>
        </>
      ) : (
        <Field label="URL"><TextInput value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://host:port/mcp" /></Field>
      )}
      <p className="text-xs text-black/40 leading-4">The server connects immediately and persists across gateway restarts. New tools go through the normal onboarding gate.</p>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>Cancel</GhostBtn>
        <PrimaryBtn onClick={add} disabled={busy}>{busy ? "Connecting…" : "Connect server"}</PrimaryBtn>
      </div>
    </Modal>
  );
}
function Metric({ label, value }: { label: string; value: string }) {
  return <div className="bg-[#f9f9fa] rounded-[20px] p-4 flex flex-col gap-1"><span className="text-lg font-semibold text-[#1c1c1c]">{value}</span><span className="text-xs text-black/40">{label}</span></div>;
}
function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return <div className="flex items-center justify-between"><span className="text-black/60">{label}</span><span style={{ color: color || "#000" }}>{value}</span></div>;
}

function ToolsPage({ d, query }: { d: Dashboard; query: string }) {
  const rows = d.tools.filter((t) => t.tool.toLowerCase().includes(query.toLowerCase()) || t.server.toLowerCase().includes(query.toLowerCase()));
  const max = Math.max(1, ...d.tools.map((t) => t.calls));
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Tools</h1>
        <span className="text-xs text-black/40">{rows.length} of {d.tools.length} tools</span>
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label="No tools visible at your clearance." /> : (
          <table className="w-full">
            <thead><tr><Th>Tool</Th><Th>Server</Th><Th right>Calls</Th><Th right>Success</Th><Th right>Avg Duration</Th><Th>Volume</Th></tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.server + t.tool} className="hover:bg-black/[0.02]">
                  <Td>{t.tool}</Td>
                  <Td><span className="text-black/60">{t.server}</span></Td>
                  <Td right>{t.calls.toLocaleString()}</Td>
                  <Td right><span style={{ color: t.success >= 97 ? "#4AA785" : "#E5A000" }}>{t.success}%</span></Td>
                  <Td right>{t.avg}</Td>
                  <Td><div className="w-full max-w-[120px] h-[3px] bg-black/10 rounded-full overflow-hidden"><div className="h-full bg-black/60 rounded-full" style={{ width: `${(t.calls / max) * 100}%` }} /></div></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardBox>
    </>
  );
}

function LogsPage({ d, query }: { d: Dashboard; query: string }) {
  const q = query.toLowerCase();
  const rows = d.logs.filter((l) => l.client.toLowerCase().includes(q) || l.detail.toLowerCase().includes(q) || l.method.toLowerCase().includes(q));
  const codeColor = (code: number) => code < 400 ? "#4AA785" : code < 500 ? "#E5A000" : "#D9534F";
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Request Logs</h1>
        <span className="text-xs text-black/40">Live · from the audit chain</span>
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label="No recent requests." /> : (
          <table className="w-full">
            <thead><tr><Th>Time</Th><Th>Client</Th><Th>Method</Th><Th>Target</Th><Th right>Duration</Th><Th right>Status</Th></tr></thead>
            <tbody>
              {rows.map((l, i) => (
                <tr key={i} className="hover:bg-black/[0.02]">
                  <Td><span className="text-black/60">{l.time}</span></Td>
                  <Td>{l.client}</Td>
                  <Td><span className="text-black/60">{l.method}</span></Td>
                  <Td>{l.detail}</Td>
                  <Td right>{l.duration}</Td>
                  <Td right><span style={{ color: codeColor(l.code) }}>{l.code}</span></Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardBox>
    </>
  );
}

function ClientsPage({ d, query, onChanged }: { d: Dashboard; query: string; onChanged: () => void }) {
  const rows = d.clients.filter((c) => c.name.toLowerCase().includes(query.toLowerCase()));
  const terminate = async (c: Dashboard["clients"][number]) => {
    if (!c.id) return;
    try {
      await apiPost(`/api/admin/sessions/${c.id}/terminate`);
      toast(`Session ${c.id} terminated — the client must re-authenticate.`);
      onChanged();
    } catch (e: any) { toast(e.message || "Terminate failed", "err"); }
  };
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Clients</h1>
        <span className="text-xs text-black/40">{rows.filter((c) => c.status === "Online").length} connected</span>
      </div>
      {rows.length === 0 ? <CardBox><Empty label="No inbound MCP sessions." /></CardBox> : (
        <div className="flex gap-3 flex-wrap">
          {rows.map((c, i) => (
            <div key={c.name + i} className="flex-1 min-w-[220px] bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <InitialAvatar name={c.sub || c.name} bg={CLIENT_COLORS[i % CLIENT_COLORS.length]} />
                <span className="text-sm text-black font-normal flex-1">{c.name}</span>
                <StatusDot status={c.status} />
              </div>
              <div className="flex items-end justify-between">
                <div className="flex flex-col">
                  <span className="text-2xl font-semibold text-[#1c1c1c]">{c.requests.toLocaleString()}</span>
                  <span className="text-xs text-black/40">requests</span>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-xs text-black">{c.sessions} session{c.sessions > 1 ? "s" : ""}</span>
                  <span className="text-xs text-black/40">{c.lastActive}</span>
                </div>
              </div>
              {c.id && (
                <button onClick={() => terminate(c)}
                  className="text-xs px-3 py-1.5 rounded-lg border border-black/10 hover:bg-black/[0.04]" style={{ color: "#D9534F" }}>
                  Terminate session
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function RateLimitsPage({ d }: { d: Dashboard }) {
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Rate Limits</h1>
        <span className="text-xs text-black/40">Per-minute windows</span>
      </div>
      <CardBox>
        <div className="flex flex-col gap-4">
          {d.rateLimits.map((r) => (
            <div key={r.scope} className="flex items-center gap-4">
              <span className="text-sm text-black w-[140px] shrink-0">{r.scope}</span>
              <span className="text-xs text-black/40 w-[110px] shrink-0">{r.limit}</span>
              <div className="flex-1 h-[3px] bg-black/10 rounded-full overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${r.used}%`, background: r.used > 85 ? "#E5A000" : "rgba(0,0,0,0.6)" }} />
              </div>
              <span className="text-xs text-black w-9 text-right shrink-0">{r.used}%</span>
            </div>
          ))}
        </div>
      </CardBox>
    </>
  );
}

function PoliciesPage({ d }: { d: Dashboard }) {
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Policies</h1>
        <span className="text-xs text-black/40">{d.policies.length} active</span>
      </div>
      <CardBox>
        <table className="w-full">
          <thead><tr><Th>Policy</Th><Th>Applies To</Th><Th>Action</Th><Th right>Status</Th></tr></thead>
          <tbody>
            {d.policies.map((p) => (
              <tr key={p.name} className="hover:bg-black/[0.02]">
                <Td>{p.name}</Td>
                <Td><span className="text-black/60">{p.applies}</span></Td>
                <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }}>{p.action}</span></Td>
                <Td right><span className="text-black/60">{p.updated}</span></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardBox>
    </>
  );
}

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className="w-8 h-[18px] rounded-full relative transition-colors shrink-0" style={{ background: on ? "#1C1C1C" : "rgba(0,0,0,0.1)" }}>
      <span className="absolute top-[2px] w-[14px] h-[14px] rounded-full bg-white transition-all" style={{ left: on ? 16 : 2 }} />
    </button>
  );
}

const INITIAL_ALERTS = [
  { name: "Error rate above 1%", detail: "Any server · 5 min window", on: true },
  { name: "Server offline", detail: "All servers · immediate", on: true },
  { name: "p95 latency above 500 ms", detail: "Gateway-wide · 10 min", on: true },
  { name: "Rate limit reached", detail: "Any scope · immediate", on: false },
  { name: "New client connected", detail: "Gateway-wide · immediate", on: false },
];
function AlertsPage() {
  const [alerts, setAlerts] = useState(INITIAL_ALERTS);
  const toggle = (i: number) => setAlerts(alerts.map((a, j) => j === i ? { ...a, on: !a.on } : a));
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">Alerts</h1>
        <span className="text-xs text-black/40">{alerts.filter((a) => a.on).length} enabled</span>
      </div>
      <CardBox>
        <div className="flex flex-col">
          {alerts.map((a, i) => (
            <div key={a.name} className={`flex items-center gap-3 py-3 ${i > 0 ? "border-t border-black/5" : ""}`}>
              <div className="flex flex-col flex-1 min-w-0"><span className="text-sm text-black">{a.name}</span><span className="text-xs text-black/40">{a.detail}</span></div>
              <Toggle on={a.on} onClick={() => toggle(i)} />
            </div>
          ))}
        </div>
      </CardBox>
    </>
  );
}

function SettingsPage({ d }: { d: Dashboard }) {
  const [settings, setSettings] = useState(d.settings);
  const [synced, setSynced] = useState(false);
  if (!synced && d.settings.length) { setSettings(d.settings); setSynced(true); }
  const toggle = (i: number) => setSettings(settings.map((s, j) => j === i ? { ...s, on: !s.on } : s));
  return (
    <>
      <div className="flex items-center justify-between"><h1 className="text-sm font-semibold text-black">Settings</h1></div>
      <CardBox>
        <div className="flex flex-col">
          {settings.map((s, i) => (
            <div key={s.name} className={`flex items-center gap-3 py-3 ${i > 0 ? "border-t border-black/5" : ""}`}>
              <div className="flex flex-col flex-1 min-w-0"><span className="text-sm text-black">{s.name}</span><span className="text-xs text-black/40">{s.detail}</span></div>
              <Toggle on={s.on} onClick={() => toggle(i)} />
            </div>
          ))}
        </div>
      </CardBox>
    </>
  );
}

// ── Right sidebar ─────────────────────────────────────────────────────────────

function NotifIcon({ bg, children }: { bg: string; children: React.ReactNode }) {
  return <div className="w-6 h-6 rounded-lg flex items-center justify-center shrink-0" style={{ background: bg }}>{children}</div>;
}

function RightSidebarRail({ setOpen, setPage, clients, unread }: { setOpen: (v: boolean) => void; setPage: (p: Page) => void; clients: Dashboard["clients"]; unread: number }) {
  return (
    <aside className="w-[72px] h-full flex flex-col items-center overflow-y-auto border-l border-black/10 py-3 gap-1.5 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <button title="Notifications" onClick={() => setOpen(true)} className="relative p-2.5 rounded-xl hover:bg-black/[0.03] cursor-pointer">
        <Bell size={20} strokeWidth={1.5} className="text-black" />
        <BellBadge unread={unread} />
      </button>
      <button title="Activities" onClick={() => setOpen(true)} className="p-2.5 rounded-xl hover:bg-black/[0.03] cursor-pointer">
        <span className="flex items-center justify-center" style={{ transform: "scale(1.35)", width: 16, height: 16 }}><ActivitySmallIcon /></span>
      </button>
      <div className="w-7 h-px bg-black/10 my-2" />
      {clients.map((c, i) => (
        <button key={c.name + i} title={`${c.name} · ${c.status}`} onClick={() => setPage("Clients")} className="relative p-1 rounded-xl hover:bg-black/[0.03] cursor-pointer">
          <InitialAvatar name={c.name} bg={CLIENT_COLORS[i % CLIENT_COLORS.length]} size={30} />
          {c.status === "Online" && <span className="absolute bottom-0.5 right-0.5 w-2 h-2 rounded-full border border-white" style={{ background: STATUS_COLOR.Online }} />}
        </button>
      ))}
    </aside>
  );
}

function RightSidebar({ open, setOpen, setPage, d, notifs, unread, onMarkAllRead, onClearRead }: {
  open: boolean; setOpen: (v: boolean) => void; setPage: (p: Page) => void; d: Dashboard;
  notifs: Notif[]; unread: number; onMarkAllRead: () => void; onClearRead: () => void;
}) {
  if (!open) {
    return <div className="shrink-0 h-full overflow-hidden transition-all duration-200" style={{ width: 72 }}>
      <RightSidebarRail setOpen={setOpen} setPage={setPage} clients={d.clients} unread={unread} />
    </div>;
  }
  const activities = d.activities.length ? d.activities : [{ text: "No recent activity.", time: "" }];
  return (
    <div className="shrink-0 h-full overflow-hidden transition-all duration-200" style={{ width: 300 }}>
      <aside className="w-[300px] h-full border-l border-black/10 overflow-y-auto flex flex-col p-4 gap-4 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
        <NotificationFeed items={notifs} unread={unread} onMarkAllRead={onMarkAllRead} onClearRead={onClearRead} />
        <div className="flex flex-col gap-1 relative">
          <p className="text-sm text-black font-normal px-1 py-2">Activities</p>
          {activities.map((a, i) => (
            <div key={i} className="flex items-start gap-2 p-2 rounded-xl">
              <div className="rounded-full shrink-0 bg-white border border-black/10" style={{ width: 24, height: 24 }} />
              <div className="flex flex-col min-w-0"><span className="text-sm text-black leading-5">{a.text}</span><span className="text-xs text-black/40 leading-4">{a.time}</span></div>
            </div>
          ))}
        </div>
        <div className="flex flex-col gap-1">
          <p className="text-sm text-black font-normal px-1 py-2">Connected Clients</p>
          {(d.clients.length ? d.clients : []).map((c, i) => (
            <div key={c.name + i} onClick={() => setPage("Clients")} className="flex items-center gap-2 p-2 rounded-xl hover:bg-black/[0.03] cursor-pointer">
              <InitialAvatar name={c.name} bg={CLIENT_COLORS[i % CLIENT_COLORS.length]} />
              <span className="text-sm text-black flex-1">{c.name}</span>
              {c.status === "Online" && <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: STATUS_COLOR.Online }} />}
            </div>
          ))}
          {d.clients.length === 0 && <span className="text-xs text-black/30 px-2 py-1">No clients connected.</span>}
        </div>
      </aside>
    </div>
  );
}

// ── Modals ────────────────────────────────────────────────────────────────────

function LogoutModal({ onCancel, onConfirm }: { onCancel: () => void; onConfirm: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(0,0,0,0.3)" }} onClick={onCancel}>
      <div className="bg-white rounded-[20px] p-6 w-[340px] flex flex-col gap-4 shadow-xl" style={{ fontFamily: "Inter, sans-serif" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0" style={{ background: "#edeefc" }}><LogOut size={16} strokeWidth={1.5} className="text-black" /></div>
          <div className="flex flex-col gap-1">
            <span className="text-sm font-semibold text-black">Log out of MCP Gateway?</span>
            <span className="text-xs text-black/40 leading-4">Your session will end. Queued tool-call approvals stay paused until you sign back in.</span>
          </div>
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onCancel} className="text-xs text-black px-4 py-2 rounded-lg border border-black/10 hover:bg-black/[0.04]">Cancel</button>
          <button onClick={onConfirm} className="text-xs text-white px-4 py-2 rounded-lg bg-[#1C1C1C] hover:opacity-80">Log out</button>
        </div>
      </div>
    </div>
  );
}

function LoggedOutScreen({ onSignIn }: { onSignIn: () => void }) {
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="bg-[#f9f9fa] rounded-[20px] p-8 w-[360px] flex flex-col items-center gap-4 text-center">
        <div className="w-10 h-10 rounded-xl bg-[#4C98FD] flex items-center justify-center"><div className="w-4 h-4 bg-white rounded-sm opacity-90" /></div>
        <div className="flex flex-col gap-1">
          <span className="text-sm font-semibold text-black">You've been logged out</span>
          <span className="text-xs text-black/40 leading-4">Thanks for using MCP Gateway. Sign back in to keep monitoring your servers, tools and traffic.</span>
        </div>
        <button onClick={onSignIn} className="text-xs text-white px-5 py-2 rounded-lg bg-[#1C1C1C] hover:opacity-80">Sign back in</button>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

const INITIAL_PAGE = ((): Page => {
  const p = new URLSearchParams(location.search).get("p");
  const all: Page[] = ["Overview", "Servers", "Tools", "Logs", "Clients", "API Keys", "Rate Limits", "Policies", "Alerts", "Settings", "Approvals", "Audit", "Identities", "Registry", "Kill Switch", "Anomaly", "Sessions"];
  return (all.includes(p as Page) ? p : "Overview") as Page;
})();

function Dashboard_({ user, onLoggedOut }: { user: User; onLoggedOut: () => void }) {
  const [page, setPage] = useState<Page>(INITIAL_PAGE);
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [query, setQuery] = useState("");
  const [range, setRange] = useState<Range>("Last 7 days");
  const [dark, setDark] = useState(false);
  const [tick, setTick] = useState(0);
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [manage, setManage] = useState<ServerRow | null>(null);

  const onAuthExpired = useCallback(() => onLoggedOut(), [onLoggedOut]);
  const { data, refresh } = useDashboard(onAuthExpired);
  const notif = useNotifications(onAuthExpired);

  const cycleRange = () => setRange(RANGES[(RANGES.indexOf(range) + 1) % RANGES.length]);
  const onRefresh = () => { setTick((t) => t + 1); refresh(); notif.reload(); };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-white"
      style={dark ? { filter: "invert(1) hue-rotate(180deg)", background: "#fff" } : undefined}>
      {dark && <style>{`img { filter: invert(1) hue-rotate(180deg); }`}</style>}
      <SideNav page={page} setPage={setPage} open={leftOpen} onLogout={() => setLogoutOpen(true)} />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <Header page={page} setPage={setPage} query={query} setQuery={setQuery}
          leftOpen={leftOpen} setLeftOpen={setLeftOpen} rightOpen={rightOpen} setRightOpen={setRightOpen}
          dark={dark} setDark={setDark} onRefresh={onRefresh}
          notifs={notif.items} unread={notif.unread} onMarkAllRead={notif.markAllRead} />
        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4 min-w-0" style={{ fontFamily: "Inter, sans-serif" }}>
          {page === "Overview" && <OverviewPage d={data} range={range} cycleRange={cycleRange} tick={tick} />}
          {page === "Servers" && <ServersPage d={data} query={query} onManage={setManage} onChanged={onRefresh} />}
          {page === "Tools" && <ToolsPage d={data} query={query} />}
          {page === "Logs" && <LogsPage d={data} query={query} />}
          {page === "Clients" && <ClientsPage d={data} query={query} onChanged={onRefresh} />}
          {page === "API Keys" && <ApiKeysPage onAuthExpired={onAuthExpired} />}
          {page === "Rate Limits" && <RateLimitsPage d={data} />}
          {page === "Policies" && <PoliciesPage d={data} />}
          {page === "Alerts" && <AlertsPage />}
          {page === "Settings" && <SettingsPage d={data} />}
          {page === "Approvals" && <ApprovalsPage onAuthExpired={onAuthExpired} />}
          {page === "Registry" && <RegistryPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Identities" && <IdentitiesPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Anomaly" && <AnomalyPage onAuthExpired={onAuthExpired} />}
          {page === "Kill Switch" && <KillSwitchPage onAuthExpired={onAuthExpired} />}
          {page === "Audit" && <AuditPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Sessions" && <InvestigatePage query={query} onAuthExpired={onAuthExpired} />}
        </div>
      </div>
      <RightSidebar open={rightOpen} setOpen={setRightOpen} setPage={setPage} d={data}
        notifs={notif.items} unread={notif.unread} onMarkAllRead={notif.markAllRead} onClearRead={notif.clearRead} />
      {manage && <ManageDrawer server={manage} onClose={() => setManage(null)} onChanged={onRefresh} />}
      {logoutOpen && <LogoutModal onCancel={() => setLogoutOpen(false)} onConfirm={async () => { setLogoutOpen(false); await apiLogout(); onLoggedOut(); }} />}
      <Toaster />
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(getUser());
  const [loggedOut, setLoggedOut] = useState(false);
  const [needsPwChange, setNeedsPwChange] = useState<boolean>(!!getUser()?.password_change_required);

  if (loggedOut) {
    return <LoggedOutScreen onSignIn={() => { setLoggedOut(false); setUser(null); }} />;
  }
  if (!user) {
    return <LoginScreen onDone={(u) => { setUser(u); setNeedsPwChange(!!u.password_change_required); }} />;
  }
  if (needsPwChange) {
    return <ChangePasswordScreen
      onDone={() => setNeedsPwChange(false)}
      onLogout={async () => { await apiLogout(); setUser(null); setLoggedOut(true); }} />;
  }
  return <Dashboard_ user={user} onLoggedOut={() => { setUser(null); setLoggedOut(true); }} />;
}
