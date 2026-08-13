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
  EyeOff, HeartPulse,
} from "lucide-react";
import {
  GridIcon, ServerIcon, WrenchIcon, GatewayIcon, ShieldIcon, BellSmallIcon,
  GearIcon, HomeIcon, ServerSmallIcon, KeySmallIcon, WarnSmallIcon, ActivitySmallIcon,
} from "./icons";
import {
  useDashboard, RANGES, ms, type Range, type Dashboard, type ServerRow,
} from "./data";
import { useApi } from "./useApi";
import { useSessionGuard } from "./session";
import { ActivityPage, ServerHealth, GlobalSearchBox } from "./AdminExtras";
import { getUser, logout as apiLogout, apiPost, type User } from "@/api";
import { LoginScreen, ChangePasswordScreen } from "./Login";
import { LangProvider, useLang, t, dirFor } from "./i18n";
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
  | "Anomaly" | "Sessions" | "Gateway" | "DLP" | "Activity";

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

// Display-only Arabic labels for status values; the raw English string stays the
// logic key (used in `=== "Online"` checks and STATUS_COLOR lookups).
const STATUS_AR: Record<string, string> = {
  Online: "متصل", Offline: "غير متصل", Degraded: "متدهور", Stopped: "متوقف",
  Draining: "قيد التصريف", running: "يعمل", stopped: "متوقف", healthy: "سليم",
  degraded: "متدهور", pending: "قيد الانتظار",
};
function StatusDot({ status }: { status: string }) {
  const color = STATUS_COLOR[status] ?? "rgba(0,0,0,0.4)";
  return (
    <span className="flex items-center gap-1.5 text-xs whitespace-nowrap" style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: color }} />
      {t(status, STATUS_AR[status] || status)}
    </span>
  );
}

// ── Sidebar ──────────────────────────────────────────────────────────────────

const BW = 2.2;   // bold stroke for nav icons

const railItems: { page: Page; icon: React.ReactNode; label: string }[] = [
  { page: "Overview", icon: <GridIcon />, label: "نظرة عامة" },
  { page: "Servers", icon: <ServerIcon />, label: "الخوادم" },
  { page: "Tools", icon: <WrenchIcon />, label: "الأدوات" },
  { page: "Logs", icon: <GatewayIcon />, label: "حركة المرور والسجلّات" },
  { page: "Approvals", icon: <CheckCheck size={16} strokeWidth={2.2} />, label: "الموافقات" },
  { page: "Registry", icon: <PackageSearch size={16} strokeWidth={2.2} />, label: "السجل" },
  { page: "Identities", icon: <Users size={16} strokeWidth={2.2} />, label: "الهويات" },
  { page: "Anomaly", icon: <Siren size={16} strokeWidth={2.2} />, label: "رصد الشذوذ" },
  { page: "Kill Switch", icon: <ShieldBan size={16} strokeWidth={2.2} />, label: "مفتاح الإيقاف الطارئ" },
  { page: "Audit", icon: <ScrollText size={16} strokeWidth={2.2} />, label: "سجل التدقيق" },
  { page: "Sessions", icon: <SearchCheck size={16} strokeWidth={2.2} />, label: "الجلسات" },
  { page: "Settings", icon: <GearIcon />, label: "الإعدادات" },
];

function SideNavRail({ page, setPage, onLogout }: { page: Page; setPage: (p: Page) => void; onLogout: () => void }) {
  return (
    <aside className="w-[72px] h-full flex flex-col items-center overflow-y-auto no-scrollbar border-r border-black/10 py-3 gap-1.5 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="p-1 mb-2"><Avatar src={imgByewind} size={30} alt="MCP Gateway" /></div>
      {railItems.map((item) => (
        <button key={item.page} title={t(item.page, item.label)} onClick={() => setPage(item.page)}
          className={`p-2.5 rounded-xl cursor-pointer ${page === item.page ? "bg-black/[0.08] hover:bg-black/[0.09]" : "hover:bg-black/[0.08]"}`}>
          <span className="flex items-center justify-center" style={{ transform: "scale(1.35)", width: 16, height: 16 }}>{item.icon}</span>
        </button>
      ))}
      <div className="mt-auto pt-4">
        <button title={t("Logout", "تسجيل الخروج")} onClick={onLogout} className="p-2.5 rounded-xl hover:bg-black/[0.08] cursor-pointer">
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
      <aside className="w-[212px] h-full flex flex-col overflow-y-auto no-scrollbar border-r border-black/10 py-3 px-3 gap-0 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
        <div className="flex items-center gap-2 px-2 py-2 rounded-lg mb-1">
          <Avatar src={imgByewind} size={24} alt="MCP Gateway" />
          <span className="text-sm text-black font-normal">MCP Gateway</span>
        </div>
        <div className="flex gap-1 px-1 mb-1">
          <button className="text-xs text-black/40 px-3 py-1 rounded-full hover:bg-black/[0.08] hover:text-black/60">{t("Favorites", "المفضّلة")}</button>
          <button className="text-xs text-black/20 px-3 py-1 rounded-full hover:bg-black/[0.08] hover:text-black/40">{t("Recently", "مؤخراً")}</button>
        </div>
        <NavBullet label={t("Overview", "نظرة عامة")} onClick={() => setPage("Overview")} />
        <NavBullet label={t("Servers", "الخوادم")} onClick={() => setPage("Servers")} />
        <p className="text-xs text-black/40 px-3 py-1 mt-2">{t("Dashboards", "لوحات المعلومات")}</p>
        <NavItem icon={<GridIcon />} label={t("Overview", "نظرة عامة")} active={page === "Overview"} onClick={() => setPage("Overview")} />
        <NavItem icon={<ServerIcon />} label={t("Servers", "الخوادم")} active={page === "Servers"} onClick={() => setPage("Servers")} />
        <NavItem icon={<WrenchIcon />} label={t("Tools", "الأدوات")} active={page === "Tools"} onClick={() => setPage("Tools")} />
        <p className="text-xs text-black/40 px-3 py-1 mt-2">{t("Gateway", "البوابة")}</p>
        {/* Traffic — collapsible parent group with icon sub-tabs */}
        <NavGroup label={t("Traffic", "حركة المرور")} icon={<GatewayIcon />} page={page} setPage={setPage} items={[
          { page: "Logs", icon: <Activity size={15} strokeWidth={BW} /> },
          { page: "Clients", icon: <MonitorSmartphone size={15} strokeWidth={BW} /> },
          { page: "API Keys", icon: <KeyRound size={15} strokeWidth={BW} /> },
          { page: "Rate Limits", icon: <Gauge size={15} strokeWidth={BW} /> },
        ]} />

        {/* Governance — collapsible parent group */}
        <NavGroup label={t("Governance", "الحوكمة")} icon={<Scale size={16} strokeWidth={1.6} />} page={page} setPage={setPage} items={[
          { page: "Approvals", icon: <CheckCheck size={15} strokeWidth={BW} /> },
          { page: "Registry", icon: <PackageSearch size={15} strokeWidth={BW} /> },
          { page: "Identities", icon: <Users size={15} strokeWidth={BW} /> },
          { page: "Policies", icon: <ShieldCheck size={15} strokeWidth={BW} /> },
        ]} />

        {/* Security — collapsible parent group */}
        <NavGroup label={t("Security", "الأمان")} icon={<Lock size={16} strokeWidth={1.6} />} page={page} setPage={setPage} items={[
          { page: "Anomaly", icon: <Siren size={15} strokeWidth={BW} /> },
          { page: "Activity", icon: <Activity size={15} strokeWidth={BW} /> },
          { page: "Kill Switch", icon: <ShieldBan size={15} strokeWidth={BW} /> },
          { page: "DLP", icon: <EyeOff size={15} strokeWidth={BW} /> },
          { page: "Audit", icon: <ScrollText size={15} strokeWidth={BW} /> },
          { page: "Sessions", icon: <SearchCheck size={15} strokeWidth={BW} /> },
        ]} />

        <p className="text-xs text-black/40 px-3 py-1 mt-2">{t("System", "النظام")}</p>
        <NavItemChevron icon={<HeartPulse size={16} strokeWidth={1.6} className="text-black" />} label={t("Gateway", "البوابة")} active={page === "Gateway"} onClick={() => setPage("Gateway")} />
        <NavItemChevron icon={<BellSmallIcon />} label={t("Alerts", "التنبيهات")} active={page === "Alerts"} onClick={() => setPage("Alerts")} />
        <NavItemChevron icon={<GearIcon />} label={t("Settings", "الإعدادات")} active={page === "Settings"} onClick={() => setPage("Settings")} />
        <button onClick={onLogout} className="mt-auto pt-4 flex items-center gap-2 px-2 py-2 rounded-lg hover:bg-black/[0.08] text-sm text-black cursor-pointer">
          <LogOut size={16} strokeWidth={1.5} className="text-black shrink-0" />
          <span className="font-normal">{t("Logout", "تسجيل الخروج")}</span>
        </button>
      </aside>
    </div>
  );
}

function NavBullet({ label, onClick }: { label: string; onClick?: () => void }) {
  return (
    <div onClick={onClick} className="flex items-center gap-2 px-2 py-1.5 my-0.5 rounded-lg text-sm text-black hover:bg-black/[0.08] cursor-pointer">
      <span className="w-4 h-4 flex items-center justify-center">
        <svg viewBox="0 0 6 6" width="6" height="6"><circle cx="3" cy="3" r="2" fill="black" fillOpacity="0.2" /></svg>
      </span>
      {label}
    </div>
  );
}
function NavItem({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} className={`flex items-center gap-2 px-2 py-1.5 my-0.5 rounded-lg text-sm text-black cursor-pointer ${active ? "bg-black/[0.07] hover:bg-black/[0.08]" : "hover:bg-black/[0.08]"}`}>
      <span className="w-4 h-4 flex items-center justify-center opacity-0"><ChevronRight size={10} /></span>
      <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
      <span className="font-normal">{label}</span>
    </div>
  );
}
function NavItemChevron({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick?: () => void }) {
  return (
    <div onClick={onClick} className={`flex items-center gap-2 px-2 py-1.5 my-0.5 rounded-lg text-sm text-black cursor-pointer ${active ? "bg-black/[0.07] hover:bg-black/[0.08]" : "hover:bg-black/[0.08]"}`}>
      <span className="w-4 h-4 flex items-center justify-center text-black/20"><ChevronRight size={10} /></span>
      <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
      <span className="font-normal">{label}</span>
    </div>
  );
}

// Collapsible parent group (like "Traffic"): a header that expands to nested,
// icon-labelled sub-tabs. Auto-opens when the active page lives inside it.
type NavChild = { page: Page; icon: React.ReactNode };
const PAGE_AR: Record<string, string> = { Overview: "نظرة عامة", Servers: "الخوادم", Tools: "الأدوات", Gateway: "البوابة", Alerts: "التنبيهات", Settings: "الإعدادات", Logs: "السجلّات", Clients: "العملاء", "API Keys": "مفاتيح API", "Rate Limits": "حدود المعدّل", Approvals: "الموافقات", Registry: "السجل", Identities: "الهويات", Policies: "السياسات", Anomaly: "رصد الشذوذ", Activity: "النشاط", "Kill Switch": "مفتاح الإيقاف الطارئ", DLP: "منع تسرّب البيانات", Audit: "سجل التدقيق", Sessions: "الجلسات" };
function NavGroup({ label, icon, items, page, setPage }: { label: string; icon: React.ReactNode; items: NavChild[]; page: Page; setPage: (p: Page) => void }) {
  const [open, setOpen] = useState(items.some((it) => it.page === page));
  return (
    <>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1 w-full px-2 py-1.5 my-0.5 rounded-lg hover:bg-black/[0.08] text-sm">
        <span className="text-black/30 text-xs mr-1">{open ? <ChevronDown size={13} strokeWidth={2.4} /> : <ChevronRight size={13} strokeWidth={2.4} />}</span>
        <span className="w-5 h-5 flex items-center justify-center shrink-0">{icon}</span>
        <span className="text-black text-sm font-normal">{label}</span>
      </button>
      {open && items.map(({ page: p, icon: ic }) => (
        <div key={p} onClick={() => setPage(p)}
          className={`flex items-center gap-2 pl-8 pr-2 py-1 my-0.5 text-sm text-black rounded-lg cursor-pointer ${page === p ? "bg-black/[0.07] hover:bg-black/[0.08]" : "hover:bg-black/[0.08]"}`}>
          <span className="w-4 h-4 flex items-center justify-center shrink-0 text-black">{ic}</span>
          {t(p, PAGE_AR[p] || p)}
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
          <button onClick={() => setLeftOpen(!leftOpen)} title={t("Toggle navigation", "تبديل شريط التنقل")}
            className={`p-1 rounded-lg hover:bg-black/[0.08] ${leftOpen ? "" : "bg-black/[0.07]"}`}>
            <PanelLeft size={16} strokeWidth={1.5} className="text-black" />
          </button>
          <button title={t("Home", "الرئيسية")} onClick={() => setPage("Overview")} className="p-1 rounded-lg hover:bg-black/[0.08]"><HomeIcon /></button>
        </div>
        <div className="flex items-center gap-1 text-xs">
          <span onClick={() => setPage("Overview")} className="text-black/40 px-2 py-1 rounded-lg hover:bg-black/[0.08] cursor-pointer">{t("Gateway", "البوابة")}</span>
          <span className="text-black/20">/</span>
          <span className="text-black px-2 py-1 rounded-lg font-normal cursor-pointer">{t(page, PAGE_AR[page] || page)}</span>
        </div>
      </div>
      <div className="flex items-center gap-4">
        {/* Global search: looks across identities, sessions, tools, audit, keys — not just
            the current table — and jumps to the right page. The query still filters the
            current page too, so per-page filtering is unchanged. */}
        <GlobalSearchBox query={query} setQuery={setQuery}
          onNavigate={(p, target) => { setPage(p as Page); if (target) setQuery(target); }} />
        <div className="flex items-center gap-1">
          <button title={dark ? t("Light mode", "الوضع الفاتح") : t("Dark mode", "الوضع الداكن")} onClick={() => setDark(!dark)} className="p-1 rounded-lg hover:bg-black/[0.08]">
            {dark ? <Moon size={16} className="text-black" /> : <Sun size={16} className="text-black" />}
          </button>
          <button title={t("Refresh data", "تحديث البيانات")} onClick={refresh} className="p-1 rounded-lg hover:bg-black/[0.08]">
            <RotateCcw size={16} className="text-black" style={{ transition: "transform 0.5s", transform: spinning ? "rotate(-360deg)" : "none" }} />
          </button>
          <div className="relative">
            <button title={t("Notifications", "الإشعارات")} onClick={() => setBellOpen(!bellOpen)}
              className={`relative p-1 rounded-lg hover:bg-black/[0.08] ${bellOpen ? "bg-black/[0.07]" : ""}`}>
              <Bell size={16} className="text-black" />
              <BellBadge unread={unread} />
            </button>
            {bellOpen && (
              <NotificationDropdown items={notifs} unread={unread}
                onMarkAllRead={onMarkAllRead}
                onViewAll={() => { setRightOpen(true); setBellOpen(false); }} />
            )}
          </div>
          <button title={t("Fullscreen", "ملء الشاشة")} onClick={toggleFullscreen} className="p-1 rounded-lg hover:bg-black/[0.08]">
            <Maximize2 size={16} className="text-black" />
          </button>
          <button onClick={() => setRightOpen(!rightOpen)} title={t("Toggle right panel", "تبديل اللوحة اليمنى")}
            className={`p-1 rounded-lg hover:bg-black/[0.08] ${rightOpen ? "" : "bg-black/[0.07]"}`}>
            <PanelRight size={16} strokeWidth={1.5} className="text-black" />
          </button>
        </div>
      </div>
    </header>
  );
}

// ── Stat cards + charts ───────────────────────────────────────────────────────

// A delta is only shown when it was actually measured. `null` renders as "—":
// a fabricated "+11.01%" that an operator catches costs more trust than a blank.
function StatCard({ label, value, change, bg }: { label: string; value: string; change: number | null | "live"; bg: string }) {
  const up = change === "live" ? true : (change ?? 0) >= 0;
  const text = change === "live" ? t("live", "مباشر")
    : change == null ? "—"
    : `${change > 0 ? "+" : ""}${change.toFixed(2)}%`;
  return (
    <div className="flex-1 min-w-[180px] rounded-[20px] p-6 flex flex-col gap-2" style={{ background: bg }}>
      <p className="text-sm text-black font-normal">{label}</p>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="text-2xl font-semibold text-[#1c1c1c]">{value}</span>
        <div className="flex items-center gap-1">
          <span className="text-xs text-black">{text}</span>
          {change == null ? null : up
            ? <svg width="16" height="16" viewBox="0 0 12.5 8"><path d="M1 7L6 2L11 7" stroke="black" strokeWidth="1.5" strokeLinecap="round" fill="none" /></svg>
            : <svg width="16" height="16" viewBox="0 0 12.5 8"><path d="M1 1L6 6L11 1" stroke="black" strokeWidth="1.5" strokeLinecap="round" fill="none" /></svg>}
        </div>
      </div>
    </div>
  );
}

// key = stable identity (used for the active-tab comparison); en/ar = display.
const CHART_TABS: { key: string; en: string; ar: string }[] = [
  { key: "requests", en: "Requests", ar: "الطلبات" },
  { key: "toolCalls", en: "Tool Calls", ar: "استدعاءات الأدوات" },
  { key: "errors", en: "Errors", ar: "الأخطاء" },
];

// Real traffic, bucketed from the audit chain by app/insights.py. "Previous" is the
// preceding bucket — an honest period-over-period line, not current × 0.82.
function TrafficChart({ series }: { series: Dashboard["series"] }) {
  const [tab, setTab] = useState("requests");
  const data = series.length ? series : [{ label: "—", current: 0, previous: 0 }];
  return (
    <div className="flex-1 min-w-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4" style={{ minHeight: 280 }}>
      <div className="flex items-center gap-4 flex-wrap">
        {CHART_TABS.map((ct) => (
          <button key={ct.key} onClick={() => setTab(ct.key)} className={`text-sm px-2 py-0.5 -mx-2 rounded-md ${tab === ct.key ? "font-semibold text-black" : "text-black/40 font-normal hover:text-black hover:bg-black/[0.07]"}`}>{t(ct.en, ct.ar)}</button>
        ))}
        <span className="text-black/20 text-sm">|</span>
        <div className="flex items-center gap-3 ml-1">
          <span className="flex items-center gap-1.5 text-xs text-black"><span className="w-2 h-2 rounded-full bg-black inline-block" /> {t("Mediated calls", "استدعاءات موسّطة")}</span>
          <span className="flex items-center gap-1.5 text-xs text-black/40"><span className="w-2 h-2 rounded-full bg-black/30 inline-block" /> {t("Previous bucket", "الفترة السابقة")}</span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="label" tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
          <YAxis tickFormatter={formatK} tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={36} allowDecimals={false} />
          <Tooltip formatter={(v: number) => v.toLocaleString("ar")} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
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
      <p className="text-sm font-normal text-black">{t("Top Tools", "أكثر الأدوات استخداماً")}</p>
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
      <p className="text-sm font-normal text-black">{t("Tool Calls by Server", "استدعاءات الأدوات حسب الخادم")}</p>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={d} margin={{ top: 4, right: 4, left: 0, bottom: 0 }} barSize={28}>
          <XAxis dataKey="server" tick={{ fontSize: 11, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
          <YAxis tickFormatter={formatK} tick={{ fontSize: 11, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={36} />
          <Tooltip formatter={(v: number) => v.toLocaleString("ar")} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>{d.map((x) => <Cell key={x.server} fill={x.color} />)}</Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TrafficByTransport({ data }: { data: Dashboard["transport"] }) {
  return (
    <div className="w-[280px] shrink-0 bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4">
      <p className="text-sm font-normal text-black">{t("Traffic by Transport", "حركة المرور حسب وسيلة النقل")}</p>
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

// MEASURED latency: p50/p95 of real per-call durations recorded in the audit chain.
// (This chart used to be seven hardcoded weekday values that never changed.)
function GatewayPerformance({ latency }: { latency: Dashboard["latency"] }) {
  const hasData = latency.some((p) => p.p50 != null);
  return (
    <div className="flex flex-col gap-4">
      <h2 className="text-sm font-semibold text-black">{t("Gateway Performance", "أداء البوابة")}</h2>
      <div className="bg-[#f9f9fa] rounded-[20px] p-6 flex flex-col gap-4" style={{ minHeight: 240 }}>
        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-sm font-semibold text-black">{t("Latency", "زمن الاستجابة")}</span>
          <div className="flex items-center gap-3 ml-1">
            <span className="flex items-center gap-1.5 text-xs text-black"><span className="w-2 h-2 rounded-full bg-black inline-block" /> p50</span>
            <span className="flex items-center gap-1.5 text-xs text-black/40"><span className="w-2 h-2 rounded-full bg-[#A0BCE8] inline-block" /> p95</span>
          </div>
          <span className="text-xs text-black/40 ml-auto">{t("measured per mediated call", "يُقاس لكل استدعاء موسّط")}</span>
        </div>
        {hasData ? (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={latency} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gradP50" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="black" stopOpacity="0.12" />
                  <stop offset="100%" stopColor="black" stopOpacity="0" />
                </linearGradient>
              </defs>
              <XAxis dataKey="label" tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} />
              <YAxis tickFormatter={(v: number) => `${v}ms`} tick={{ fontSize: 12, fill: "rgba(0,0,0,0.4)" }} axisLine={false} tickLine={false} width={52} />
              <Tooltip formatter={(v: number) => `${v} ms`} contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid rgba(0,0,0,0.1)" }} />
              <Area type="monotone" dataKey="p95" stroke="#A0BCE8" strokeWidth={1.5} fill="none" dot={false} connectNulls />
              <Area type="monotone" dataKey="p50" stroke="black" strokeWidth={1.5} fill="url(#gradP50)" dot={false} connectNulls />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <Empty label={t("No mediated calls in this window — nothing to measure yet.", "لا توجد استدعاءات موسّطة في هذه النافذة الزمنية — لا يوجد شيء لقياسه بعد.")} />
        )}
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

function OverviewPage({ d, range, cycleRange }: { d: Dashboard; range: Range; cycleRange: () => void }) {
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Overview", "نظرة عامة")}</h1>
        <button onClick={cycleRange} className="flex items-center gap-1 text-xs text-black px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08]">
          {range} <ChevronDown size={12} className="text-black/40" />
        </button>
      </div>
      {d.maintenance && (
        <div className="rounded-[14px] px-4 py-3 bg-[#fff4e0] border border-[#e8b04b]/40 text-sm text-[#7a5410]">
          {t("Maintenance mode is ON — mediated tool calls are paused for non-admins.", "وضع الصيانة مفعّل — استدعاءات الأدوات الموسّطة متوقفة مؤقتاً لغير المسؤولين.")}
        </div>
      )}
      <div className="flex gap-3 flex-wrap">
        {/* Deltas are measured (second half vs first half of the window), never canned. */}
        <StatCard label={t("Total Requests", "إجمالي الطلبات")} value={d.stats.totalRequests} change={d.deltas.requests} bg="#edeefc" />
        <StatCard label={t("Active Servers", "الخوادم النشطة")} value={d.stats.activeServers} change="live" bg="#e6f1fd" />
        <StatCard label={t("Tool Calls", "استدعاءات الأدوات")} value={d.stats.toolCalls} change={d.deltas.toolCalls} bg="#edeefc" />
        <StatCard label={t("Error Rate", "معدّل الأخطاء")} value={d.stats.errorRate} change={d.deltas.errors} bg="#e6f1fd" />
      </div>
      <div className="flex gap-3 min-w-0">
        <TrafficChart series={d.series} />
        <TopTools data={d.topTools} />
      </div>
      <div className="flex gap-3 min-w-0">
        <CallsByServer data={d.serverCalls} />
        <TrafficByTransport data={d.transport} />
      </div>
      <GatewayPerformance latency={d.latency} />
    </>
  );
}

function ServersPage({ d, query, onManage, onChanged }: { d: Dashboard; query: string; onManage: (s: ServerRow) => void; onChanged: () => void }) {
  const rows = d.servers.filter((s) => s.name.toLowerCase().includes(query.toLowerCase()));
  const [addOpen, setAddOpen] = useState(false);
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Servers", "الخوادم")}</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-black/40">{t(`${rows.length} of ${d.servers.length} servers`, `${rows.length} من ${d.servers.length} خادم`)}</span>
          <button onClick={() => setAddOpen(true)}
            className="text-xs text-white px-3 py-1.5 rounded-lg bg-[#1C1C1C] hover:opacity-80">{t("+ Add server", "+ إضافة خادم")}</button>
        </div>
      </div>
      {addOpen && <AddServerModal onClose={() => setAddOpen(false)} onAdded={() => { setAddOpen(false); onChanged(); }} />}
      <CardBox>
        {rows.length === 0 ? <Empty label={t("No servers connected.", "لا توجد خوادم متصلة.")} /> : (
          <table className="w-full">
            <thead><tr>
              <Th>{t("Server", "خادم")}</Th><Th>{t("Status", "الحالة")}</Th><Th>{t("Transport", "وسيلة النقل")}</Th><Th right>{t("Tools", "الأدوات")}</Th><Th right>{t("Version", "الإصدار")}</Th><Th right>{t("Latency", "زمن الاستجابة")}</Th><Th right>{t("Uptime", "مدة التشغيل")}</Th><Th right></Th>
            </tr></thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.name} className="hover:bg-black/[0.04]">
                  <Td>{s.name}</Td>
                  <Td><StatusDot status={s.status} /></Td>
                  <Td>{s.transport}</Td>
                  <Td right>{s.tools}</Td>
                  <Td right>{s.version}</Td>
                  <Td right>{s.latency}</Td>
                  <Td right>{s.uptime}</Td>
                  <Td right>
                    <button onClick={() => onManage(s)} className="text-xs text-black px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08]">{t("Manage", "إدارة")}</button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardBox>
      {/* Is the BACKEND reachable, not just "process running"? (A2am-blind-spot fix) */}
      <ServerHealth />
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
  const [editOpen, setEditOpen] = useState(false);
  const stopped = det.state === "stopped";
  const drained = !!det.drained;

  const act = async (action: string, label: string) => {
    setBusy(action);
    try {
      await apiPost(`/api/admin/servers/${server.name}/${action}`);
      toast(label);
      onChanged();
      onClose();
    } catch (e: any) { toast(e.message || t(`${action} failed`, `فشل: ${action}`), "err"); }
    finally { setBusy(null); }
  };
  const doRemove = async () => {
    setRemoveOpen(false);
    setBusy("remove");
    try {
      await apiPost(`/api/admin/servers/${server.name}/remove`);
      toast(t(`Server ${server.name} removed.`, `تمت إزالة الخادم ${server.name}.`));
      onChanged();
      onClose();
    } catch (e: any) { toast(e.message || t("Remove failed", "فشلت الإزالة"), "err"); }
    finally { setBusy(null); }
  };
  const Btn = ({ action, label, busyLabel, danger }: { action: string; label: string; busyLabel: string; danger?: boolean }) => (
    <button onClick={() => act(action, `${server.name}: ${busyLabel}`)} disabled={!!busy}
      className="text-xs px-3 py-2 rounded-lg border border-black/10 hover:bg-black/[0.08] disabled:opacity-40 flex-1 min-w-[100px]"
      style={danger ? { color: "#D9534F" } : undefined}>
      {busy === action ? t("Working…", "جارٍ التنفيذ…") : label}
    </button>
  );

  return (
    <div className="fixed inset-0 z-50 flex justify-end" style={{ background: "rgba(0,0,0,0.3)" }} onClick={onClose}>
      <div className="h-full w-[360px] bg-white p-6 flex flex-col gap-5 overflow-y-auto" style={{ fontFamily: "Inter, sans-serif" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold text-black">{t("Manage", "إدارة")} · {server.name}</span>
          <button onClick={onClose} className="text-xs text-black/40 hover:text-black">{t("Close", "إغلاق")}</button>
        </div>
        <div className="flex items-center gap-2"><StatusDot status={server.status} /><span className="text-xs text-black/40">{server.transport}</span></div>

        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-3">
          <span className="text-sm font-normal text-black">{t("Server actions", "إجراءات الخادم")}</span>
          <div className="flex gap-2 flex-wrap">
            {stopped
              ? <Btn action="start" label={t("▶ Start", "▶ بدء")} busyLabel={t("started", "تم التشغيل")} />
              : <>
                  <Btn action="restart" label={t("↻ Restart", "↻ إعادة تشغيل")} busyLabel={t("restarted", "تمت إعادة التشغيل")} />
                  <Btn action="stop" label={t("■ Stop", "■ إيقاف")} busyLabel={t("stopped", "تم الإيقاف")} danger />
                </>}
            {!stopped && (drained
              ? <Btn action="undrain" label={t("Resume traffic", "استئناف حركة المرور")} busyLabel={t("traffic resumed", "استؤنفت حركة المرور")} />
              : <Btn action="drain" label={t("Drain", "تصريف")} busyLabel={t("draining — new calls refused", "قيد التصريف — تُرفض الاستدعاءات الجديدة")} />)}
            {(det.breaker_open || (det.fails ?? 0) > 0) &&
              <Btn action="breaker_reset" label={t("Reset breaker", "إعادة ضبط القاطع")} busyLabel={t("breaker force-closed", "أُغلق القاطع قسراً")} />}
          </div>
          {/* Edit in place (A16): changing an env var used to mean remove + re-add, which
              dropped every pinned hash for the server and forced its tools back through
              onboarding approval. */}
          <button onClick={() => setEditOpen(true)} disabled={!!busy}
            className="text-xs px-3 py-2 rounded-lg border border-black/10 hover:bg-black/[0.08] disabled:opacity-40">
            {t("Edit configuration…", "تعديل الإعداد…")}
          </button>
          <button onClick={() => setRemoveOpen(true)} disabled={!!busy}
            className="text-xs px-3 py-2 rounded-lg border border-black/10 hover:bg-black/[0.08] disabled:opacity-40" style={{ color: "#D9534F" }}>
            {t("Remove server from gateway…", "إزالة الخادم من البوابة…")}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Metric label={t("Tools", "الأدوات")} value={String(server.tools)} />
          <Metric label={t("Active", "نشِطة")} value={String(det.active ?? "—")} />
          <Metric label={t("Pending", "قيد الانتظار")} value={String(det.pending ?? "—")} />
          <Metric label={t("Quarantined", "معزولة")} value={String(det.quarantined ?? "—")} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Metric label={t("Calls", "الاستدعاءات")} value={String(det.calls ?? 0)} />
          <Metric label={t("Errors", "الأخطاء")} value={String(det.errors ?? 0)} />
          <Metric label={t("Avg latency", "متوسط زمن الاستجابة")} value={server.latency} />
          <Metric label={t("p95 latency", "زمن استجابة p95")} value={ms(det.p95_ms)} />
        </div>
        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-3">
          <span className="text-sm font-normal text-black">{t("Risk tiers", "مستويات المخاطر")}</span>
          {[0, 1, 2, 3].map((tier) => (
            <div key={tier} className="flex items-center justify-between text-xs">
              <span className="text-black/60">{t("Tier", "المستوى")} {tier} · {[t("read", "قراءة"), t("reversible write", "كتابة قابلة للتراجع"), t("human approval", "موافقة بشرية"), t("two-person", "شخصان")][tier]}</span>
              <span className="text-black">{tiers[String(tier)] ?? 0}</span>
            </div>
          ))}
        </div>
        <div className="bg-[#f9f9fa] rounded-[20px] p-5 flex flex-col gap-2 text-xs">
          <Row label={t("State", "الحالة")} value={det.state === "stopped" ? t("Stopped", "متوقف") : drained ? t("Draining", "قيد التصريف") : t("Running", "قيد التشغيل")} color={det.state === "stopped" ? "#787878" : drained ? "#E5A000" : "#4AA785"} />
          <Row label={t("Version", "الإصدار")} value={server.version} />
          <Row label={t("MCP protocol", "بروتوكول MCP")} value={det.protocol_version || "—"} />
          <Row label={t("Uptime", "مدة التشغيل")} value={server.uptime} />
          <Row label={t("Rate limit", "حد المعدّل")} value={det.rate_limit ? t(`${det.rate_limit}/min`, `${det.rate_limit}/دقيقة`) : "—"} />
          <Row label={t("Circuit breaker", "قاطع الدائرة")} value={det.breaker_open ? t("Open (quarantined)", "مفتوح (معزول)") : t("Closed", "مغلق")} color={det.breaker_open ? "#D9534F" : "#4AA785"} />
          <Row label={t("Recent failures", "الإخفاقات الأخيرة")} value={String(det.fails ?? 0)} />
          <Row label={t("Managed credentials", "بيانات اعتماد مُدارة")} value={det.managed_credentials ? t("Yes", "نعم") : t("No", "لا")} />
        </div>
        {removeOpen && (
          <ConfirmModal title={t(`Remove ${server.name}?`, `إزالة ${server.name}؟`)}
            body={<>{t("The server disconnects immediately and stays removed across gateway restarts (its registry entries are kept in case it is re-added). Tool calls to it will fail.", "يُقطَع اتصال الخادم فوراً ويبقى مُزالاً عبر عمليات إعادة تشغيل البوابة (تُحفظ مدخلاته في السجل في حال إعادة إضافته). ستفشل استدعاءات الأدوات الموجهة إليه.")}</>}
            confirmLabel={t("Remove server", "إزالة الخادم")} onCancel={() => setRemoveOpen(false)} onConfirm={doRemove} />
        )}
        {editOpen && (
          <EditServerModal server={server.name} onClose={() => setEditOpen(false)}
            onSaved={() => { setEditOpen(false); onChanged(); onClose(); }} />
        )}
      </div>
    </div>
  );
}

// Edit a server's connection spec in place. The registry survives the edit and
// re-checks definitions, so a server whose tools genuinely changed still quarantines
// on drift — the governance gate is not bypassed by an edit.
function EditServerModal({ server, onClose, onSaved }: {
  server: string; onClose: () => void; onSaved: () => void;
}) {
  const { data: spec } = useApi<any>(`/api/admin/servers/${server}/spec`);
  const [transport, setTransport] = useState("stdio");
  const [command, setCommand] = useState("");
  const [args, setArgs] = useState("");
  const [url, setUrl] = useState("");
  const [env, setEnv] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);

  if (spec && !loaded) {
    setTransport(spec.transport || "stdio");
    setCommand(spec.command || "");
    setArgs((spec.args || []).join(" "));
    setUrl(spec.url || "");
    // Env VALUES are redacted server-side (they hold secrets); re-supply any you change.
    setEnv((spec.env_keys || []).map((k: string) => `${k}=`).join("\n"));
    setLoaded(true);
  }

  const save = async () => {
    const envObj: Record<string, string> = {};
    for (const line of env.split("\n")) {
      const [k, ...v] = line.split("=");
      if (k.trim() && v.length && v.join("=").trim()) envObj[k.trim()] = v.join("=").trim();
    }
    setBusy(true);
    try {
      const r: any = await apiPost(`/api/admin/servers/${server}/edit`, {
        transport, command: command.trim(), args: args.split(/\s+/).filter(Boolean),
        url: url.trim(), env: envObj,
      });
      toast(t(`${server} reconnected · ${r.tools} tool(s)`, `${server} — أُعيد الاتصال به · ${r.tools} أداة`) +
        (r.drift_quarantined ? t(` · ${r.drift_quarantined} quarantined on drift`, ` · ${r.drift_quarantined} معزولة بسبب انحراف`) : ""));
      onSaved();
    } catch (e: any) {
      toast(e?.message || t("Edit failed — the server is still running on its old spec", "فشل التعديل — لا يزال الخادم يعمل وفق إعداده القديم"), "err");
    } finally { setBusy(false); }
  };

  return (
    <Modal title={t(`Edit · ${server}`, `تعديل · ${server}`)} onClose={onClose} width={460}>
      {!spec ? <Empty label={t("Loading spec…", "جارٍ تحميل الإعداد…")} /> : (
        <>
          <Field label={t("Transport", "وسيلة النقل")}>
            <SelectInput value={transport} onChange={(e) => setTransport(e.target.value)}>
              <option value="stdio">stdio</option>
              <option value="http">http</option>
            </SelectInput>
          </Field>
          {transport === "stdio" ? (
            <>
              <Field label={t("Command", "الأمر")}><TextInput value={command} onChange={(e) => setCommand(e.target.value)} /></Field>
              <Field label={t("Arguments (space-separated)", "المعطيات (مفصولة بمسافات)")}><TextInput value={args} onChange={(e) => setArgs(e.target.value)} /></Field>
            </>
          ) : (
            <Field label="URL"><TextInput value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
          )}
          <Field label={t("Environment (KEY=value per line)", "متغيرات البيئة (KEY=value في كل سطر)")}>
            <textarea value={env} onChange={(e) => setEnv(e.target.value)} rows={4}
              className="bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30 font-mono" />
          </Field>
          <p className="text-xs text-black/40">
            {t("Existing env values are hidden (they may hold secrets) — a key left blank keeps nothing, so re-enter any value you want to keep. The new connection must start before the old one is dropped: a bad edit leaves the server running.",
              "قيم البيئة الحالية مخفية (قد تحتوي أسراراً) — أي مفتاح يُترك فارغاً لا يحتفظ بشيء، لذا أعد إدخال أي قيمة تريد الإبقاء عليها. يجب أن يبدأ الاتصال الجديد قبل إسقاط القديم: التعديل الخاطئ يترك الخادم يعمل كما هو.")}
          </p>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={onClose}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={save} disabled={busy}>{busy ? t("Reconnecting…", "جارٍ إعادة الاتصال…") : t("Save & reconnect", "حفظ وإعادة الاتصال")}</PrimaryBtn>
          </div>
        </>
      )}
    </Modal>
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
    if (!name.trim()) { toast(t("Server name is required", "اسم الخادم مطلوب"), "err"); return; }
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
      toast(t(`Server ${r.server} connected — ${r.tools} tool(s) discovered${r.pending_tools ? `, ${r.pending_tools} pending approval` : ""}.`,
        `تم الاتصال بالخادم ${r.server} — تم اكتشاف ${r.tools} أداة${r.pending_tools ? `، ${r.pending_tools} قيد انتظار الموافقة` : ""}.`));
      onAdded();
    } catch (e: any) { toast(e.message || t("Add failed", "فشلت الإضافة"), "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title={t("Add MCP server", "إضافة خادم MCP")} onClose={onClose} width={460}>
      <Field label={t("Name (unique, no '__')", "الاسم (فريد، بدون '__')")}><TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. weather", "مثلاً: weather")} autoFocus /></Field>
      <Field label={t("Transport", "وسيلة النقل")}>
        <SelectInput value={transport} onChange={(e) => setTransport(e.target.value)}>
          <option value="stdio">{t("stdio (local subprocess)", "stdio (عملية فرعية محلية)")}</option>
          <option value="http">{t("http (remote Streamable-HTTP)", "http (Streamable-HTTP عن بُعد)")}</option>
        </SelectInput>
      </Field>
      {transport === "stdio" ? (
        <>
          <Field label={t("Command", "الأمر")}><TextInput value={command} onChange={(e) => setCommand(e.target.value)} placeholder="python" /></Field>
          <Field label={t("Arguments (space-separated)", "المعطيات (مفصولة بمسافات)")}><TextInput value={args} onChange={(e) => setArgs(e.target.value)} placeholder="servers/weather_server.py" /></Field>
          <Field label={t("Environment (KEY=value per line; ${VAR} expands from the gateway env)", "متغيرات البيئة (KEY=value في كل سطر؛ يتم توسيع ${VAR} من بيئة البوابة)")}>
            <textarea value={env} onChange={(e) => setEnv(e.target.value)} rows={3}
              className="bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30 font-mono"
              placeholder={"API_URL=${WEATHER_URL}"} />
          </Field>
        </>
      ) : (
        <Field label="URL"><TextInput value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://host:port/mcp" /></Field>
      )}
      <p className="text-xs text-black/40 leading-4">{t("The server connects immediately and persists across gateway restarts. New tools go through the normal onboarding gate.", "يتصل الخادم فوراً ويستمر عبر عمليات إعادة تشغيل البوابة. تمرّ الأدوات الجديدة عبر بوابة الإدماج المعتادة.")}</p>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>{t("Cancel", "إلغاء")}</GhostBtn>
        <PrimaryBtn onClick={add} disabled={busy}>{busy ? t("Connecting…", "جارٍ الاتصال…") : t("Connect server", "توصيل الخادم")}</PrimaryBtn>
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
        <h1 className="text-sm font-semibold text-black">{t("Tools", "الأدوات")}</h1>
        <span className="text-xs text-black/40">{t(`${rows.length} of ${d.tools.length} tools`, `${rows.length} من ${d.tools.length} أداة`)}</span>
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label={t("No tools visible at your clearance.", "لا توجد أدوات مرئية ضمن صلاحيتك.")} /> : (
          <table className="w-full">
            <thead><tr><Th>{t("Tool", "أداة")}</Th><Th>{t("Server", "خادم")}</Th><Th right>{t("Calls", "الاستدعاءات")}</Th><Th right>{t("Success", "نسبة النجاح")}</Th><Th right>{t("Avg Duration", "متوسط المدة")}</Th><Th>{t("Volume", "الحجم")}</Th></tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.server + t.tool} className="hover:bg-black/[0.04]">
                  <Td>{t.tool}</Td>
                  <Td><span className="text-black/60">{t.server}</span></Td>
                  <Td right>{t.calls.toLocaleString("ar")}</Td>
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
        <h1 className="text-sm font-semibold text-black">{t("Request Logs", "سجلّات الطلبات")}</h1>
        <span className="text-xs text-black/40">{t("Live · from the audit chain", "مباشر · من سلسلة التدقيق")}</span>
      </div>
      <CardBox>
        {rows.length === 0 ? <Empty label={t("No recent requests.", "لا توجد طلبات حديثة.")} /> : (
          <table className="w-full">
            <thead><tr><Th>{t("Time", "الوقت")}</Th><Th>{t("Client", "العميل")}</Th><Th>{t("Method", "الطريقة")}</Th><Th>{t("Target", "الهدف")}</Th><Th right>{t("Duration", "المدة")}</Th><Th right>{t("Status", "الحالة")}</Th></tr></thead>
            <tbody>
              {rows.map((l, i) => (
                <tr key={i} className="hover:bg-black/[0.04]">
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
      toast(t(`Session ${c.id} terminated — the client must re-authenticate.`, `تم إنهاء الجلسة ${c.id} — يجب على العميل إعادة المصادقة.`));
      onChanged();
    } catch (e: any) { toast(e.message || t("Terminate failed", "فشل إنهاء الجلسة"), "err"); }
  };
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Clients", "العملاء")}</h1>
        <span className="text-xs text-black/40">{t(`${rows.filter((c) => c.status === "Online").length} connected`, `${rows.filter((c) => c.status === "Online").length} متصل`)}</span>
      </div>
      {rows.length === 0 ? <CardBox><Empty label={t("No inbound MCP sessions.", "لا توجد جلسات MCP واردة.")} /></CardBox> : (
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
                  <span className="text-2xl font-semibold text-[#1c1c1c]">{c.requests.toLocaleString("ar")}</span>
                  <span className="text-xs text-black/40">{t("requests", "طلبات")}</span>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-xs text-black">{t(`${c.sessions} session${c.sessions > 1 ? "s" : ""}`, `${c.sessions} جلسة`)}</span>
                  <span className="text-xs text-black/40">{c.lastActive}</span>
                </div>
              </div>
              {c.id && (
                <button onClick={() => terminate(c)}
                  className="text-xs px-3 py-1.5 rounded-lg border border-black/10 hover:bg-black/[0.08]" style={{ color: "#D9534F" }}>
                  {t("Terminate session", "إنهاء الجلسة")}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

// LIVE consumption (the bars used to be hardcoded to 0), and the ceilings are editable
// here — retuning a limit mid-incident is now a click, not an SSH + restart.
function RateLimitsPage({ onChanged }: { onChanged: () => void }) {
  const { data: st, reload } = useApi<any>("/api/admin/settings");
  const { data: live, reload: reloadLive } = useApi<any>("/api/admin/ratelimits");
  const [edit, setEdit] = useState<{ key: string; label: string; value: number } | null>(null);
  const [srv, setSrv] = useState<{ name: string; value: number } | null>(null);
  const lim = st?.effective?.rate_limits;

  const save = async (patch: any) => {
    try {
      await apiPost("/api/admin/settings", { section: "rate_limits", patch });
      setEdit(null); setSrv(null); reload(); reloadLive(); onChanged();
      toast(t("Rate limit updated — effective on the next request.", "تم تحديث حدّ المعدّل — يسري اعتباراً من الطلب التالي."));
    } catch (e: any) { toast(e?.message || t("Could not save", "تعذّر الحفظ"), "err"); }
  };

  const rows = [
    { key: "per_user_per_minute", label: t("Global (per user)", "عام (لكل مستخدم)"), live: live?.per_user },
    { key: "per_tool_per_minute", label: t("Per tool", "لكل أداة"), live: live?.per_tool },
    { key: "per_server_per_minute", label: t("Per server", "لكل خادم"), live: live?.per_server },
  ];

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Rate Limits", "حدود المعدّل")}</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-black/40">{t("60-second sliding window · live usage", "نافذة منزلقة مدتها 60 ثانية · استخدام مباشر")}</span>
          <GhostBtn onClick={reloadLive}>{t("Refresh", "تحديث")}</GhostBtn>
        </div>
      </div>
      <CardBox title={t("Ceilings", "الحدود القصوى")}>
        <div className="flex flex-col gap-4">
          {rows.map((r) => {
            const limit = lim?.[r.key];
            const peak = r.live?.[0];
            const pct = peak && peak.limit ? Math.min(100, Math.round((peak.used / peak.limit) * 100)) : 0;
            return (
              <div key={r.key} className="flex items-center gap-4">
                <span className="text-sm text-black w-[140px] shrink-0">{r.label}</span>
                <span className="text-xs text-black/40 w-[90px] shrink-0">{t(`${limit ?? "—"} req/min`, `${limit ?? "—"} طلب/دقيقة`)}</span>
                <div className="flex-1 h-[3px] bg-black/10 rounded-full overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${pct}%`, background: pct > 85 ? "#E5A000" : "rgba(0,0,0,0.6)" }} />
                </div>
                <span className="text-xs text-black/60 w-[200px] text-right truncate shrink-0">
                  {peak ? `${peak.used}/${peak.limit} · ${peak.key}` : t("idle", "خامل")}
                </span>
                <GhostBtn onClick={() => setEdit({ key: r.key, label: r.label, value: limit ?? 30 })}>{t("Edit", "تعديل")}</GhostBtn>
              </div>
            );
          })}
        </div>
      </CardBox>

      <CardBox title={t("Per-server overrides", "تجاوزات لكل خادم")}>
        <table className="w-full">
          <thead><tr><Th>{t("Server", "خادم")}</Th><Th>{t("Effective limit", "الحد الفعّال")}</Th><Th>{t("Source", "المصدر")}</Th><Th right>{t("Action", "الإجراء")}</Th></tr></thead>
          <tbody>
            {(st?.servers || []).map((name: string) => {
              const ov = lim?.per_server_overrides?.[name];
              return (
                <tr key={name} className="hover:bg-black/[0.04]">
                  <Td>{name}</Td>
                  <Td>{t(`${ov ?? lim?.per_server_per_minute ?? "—"} req/min`, `${ov ?? lim?.per_server_per_minute ?? "—"} طلب/دقيقة`)}</Td>
                  <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: ov ? "#edeefc" : "rgba(0,0,0,0.05)" }}>
                    {ov ? t("override", "تجاوز") : t("global default", "افتراضي عام")}</span></Td>
                  <Td right>
                    <div className="flex gap-2 justify-end">
                      <GhostBtn onClick={() => setSrv({ name, value: ov ?? lim?.per_server_per_minute ?? 60 })}>{t("Set", "ضبط")}</GhostBtn>
                      {ov != null && (
                        <GhostBtn onClick={() => {
                          const next = { ...(lim?.per_server_overrides || {}) };
                          delete next[name];
                          save({ per_server_overrides: next });
                        }}>{t("Clear", "مسح")}</GhostBtn>
                      )}
                    </div>
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </CardBox>

      {edit && (
        <Modal title={t(`Edit — ${edit.label}`, `تعديل — ${edit.label}`)} onClose={() => setEdit(null)}>
          <Field label={t("Calls per minute", "عدد الاستدعاءات في الدقيقة")}>
            <TextInput type="number" min={1} max={10000} value={edit.value}
              onChange={(e) => setEdit({ ...edit, value: Number(e.target.value) })} />
          </Field>
          <p className="text-xs text-black/40">{t("Applies to the next request — no restart.", "يسري على الطلب التالي — دون إعادة تشغيل.")}</p>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setEdit(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={() => save({ [edit.key]: edit.value })}>{t("Save", "حفظ")}</PrimaryBtn>
          </div>
        </Modal>
      )}
      {srv && (
        <Modal title={t(`Per-server limit — ${srv.name}`, `حد لكل خادم — ${srv.name}`)} onClose={() => setSrv(null)}>
          <Field label={t("Calls per minute for this server", "عدد الاستدعاءات في الدقيقة لهذا الخادم")}>
            <TextInput type="number" min={1} max={100000} value={srv.value}
              onChange={(e) => setSrv({ ...srv, value: Number(e.target.value) })} />
          </Field>
          <p className="text-xs text-black/40">{t(`Overrides the global per-server ceiling for ${srv.name}.`, `يتجاوز الحد الأقصى العام لكل خادم بالنسبة إلى ${srv.name}.`)}</p>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setSrv(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={() => save({
              per_server_overrides: { ...(lim?.per_server_overrides || {}), [srv.name]: srv.value },
            })}>{t("Save", "حفظ")}</PrimaryBtn>
          </div>
        </Modal>
      )}
    </>
  );
}

function PoliciesPage({ d }: { d: Dashboard }) {
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Policies", "السياسات")}</h1>
        <span className="text-xs text-black/40">{t(`${d.policies.length} active`, `${d.policies.length} نشطة`)}</span>
      </div>
      <CardBox>
        <table className="w-full">
          <thead><tr><Th>{t("Policy", "السياسة")}</Th><Th>{t("Applies To", "تُطبَّق على")}</Th><Th>{t("Action", "الإجراء")}</Th><Th right>{t("Status", "الحالة")}</Th></tr></thead>
          <tbody>
            {d.policies.map((p) => (
              <tr key={p.name} className="hover:bg-black/[0.04]">
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

// Every rule here maps to a real detector in app/anomaly.py, and the toggle PERSISTS.
// (These switches used to be local React state: they looked functional, changed nothing,
// and quietly told the admin alerting was configured when it wasn't.)
// Bilingual — rendered via t(x.en, x.ar) at the use sites (module-level map).
const ALERT_RULE_META: Record<string, { name: { en: string; ar: string }; detail: { en: string; ar: string } }> = {
  breaker_open: { name: { en: "Circuit breaker opened", ar: "انفتح قاطع الدائرة" }, detail: { en: "A server failed repeatedly and was quarantined · immediate", ar: "فشل خادم بشكل متكرر وتم عزله · فوري" } },
  login_failures: { name: { en: "Repeated login failures", ar: "محاولات تسجيل دخول فاشلة متكررة" }, detail: { en: "Possible credential stuffing / brute force · threshold below", ar: "احتمال هجوم حشو بيانات الاعتماد / القوة الغاشمة · الحد أدناه" } },
  error_rate: { name: { en: "Elevated tool error rate", ar: "ارتفاع معدّل أخطاء الأدوات" }, detail: { en: "A backend or agent is misbehaving · threshold below", ar: "خلل في أداء خلفي أو وكيل · الحد أدناه" } },
  approval_sla: { name: { en: "Approval breaching SLA", ar: "موافقة تتجاوز اتفاقية مستوى الخدمة" }, detail: { en: "A held action is stalling in the queue · SLA below", ar: "إجراء معلّق يتعطل في قائمة الانتظار · اتفاقية مستوى الخدمة أدناه" } },
  tool_quarantine: { name: { en: "Tool quarantined (drift / rug-pull)", ar: "أداة معزولة (انحراف / سحب مفاجئ)" }, detail: { en: "A tool's definition changed after pinning · immediate", ar: "تغيّر تعريف أداة بعد تثبيته · فوري" } },
  lockout: { name: { en: "Identity locked out", ar: "تم قفل الهوية" }, detail: { en: "Anti-hammering fired on an operator · immediate", ar: "آلية مكافحة المحاولات المتكررة استُدعيت على مشغّل · فوري" } },
};

function AlertsPage() {
  const { data: st, reload } = useApi<any>("/api/admin/settings");
  const rules: Record<string, boolean> = st?.effective?.alerts?.rules || {};
  const an = st?.effective?.anomaly || {};
  const [busy, setBusy] = useState("");
  const [thr, setThr] = useState<{ key: string; label: string; value: number; step?: number } | null>(null);

  const toggle = async (rule: string, on: boolean) => {
    setBusy(rule);
    try {
      await apiPost("/api/admin/settings", { section: "alerts", patch: { rules: { [rule]: on } } });
      reload();
      toast(t(`${ALERT_RULE_META[rule]?.name.en || rule} ${on ? "enabled" : "disabled"}.`, `${ALERT_RULE_META[rule]?.name.ar || rule} ${on ? "مفعّلة" : "معطّلة"}.`));
    } catch (e: any) {
      toast(e?.message || t("Could not save", "تعذّر الحفظ"), "err");
    } finally { setBusy(""); }
  };

  const saveThreshold = async () => {
    if (!thr) return;
    try {
      await apiPost("/api/admin/settings", { section: "anomaly", patch: { [thr.key]: thr.value } });
      setThr(null); reload();
      toast(t("Threshold updated.", "تم تحديث الحد."));
    } catch (e: any) { toast(e?.message || t("Could not save", "تعذّر الحفظ"), "err"); }
  };

  const enabled = Object.values(rules).filter(Boolean).length;
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Alerts", "التنبيهات")}</h1>
        <span className="text-xs text-black/40">{t(`${enabled}/${Object.keys(rules).length} rules enabled`, `${enabled}/${Object.keys(rules).length} قاعدة مفعّلة`)}</span>
      </div>
      <CardBox title={t("Detection rules", "قواعد الاكتشاف")}>
        <div className="flex flex-col">
          {Object.keys(rules).map((rule, i) => {
            const meta = ALERT_RULE_META[rule] || { name: { en: rule, ar: rule }, detail: { en: "", ar: "" } };
            return (
              <div key={rule} className={`flex items-center gap-3 py-3 ${i > 0 ? "border-t border-black/5" : ""}`}>
                <div className="flex flex-col flex-1 min-w-0">
                  <span className="text-sm text-black">{t(meta.name.en, meta.name.ar)}</span>
                  <span className="text-xs text-black/40">{t(meta.detail.en, meta.detail.ar)}</span>
                </div>
                {busy === rule && <span className="text-xs text-black/30">{t("saving…", "جارٍ الحفظ…")}</span>}
                <Toggle on={rules[rule]} onClick={() => toggle(rule, !rules[rule])} />
              </div>
            );
          })}
        </div>
      </CardBox>
      <CardBox title={t("Thresholds", "الحدود")}>
        <table className="w-full">
          <thead><tr><Th>{t("Threshold", "الحد")}</Th><Th>{t("Value", "القيمة")}</Th><Th right>{t("Action", "الإجراء")}</Th></tr></thead>
          <tbody>
            {[
              { key: "login_fail_threshold", label: t("Failed sign-ins before alerting", "محاولات تسجيل الدخول الفاشلة قبل التنبيه"), suffix: t("attempts", "محاولة") },
              { key: "error_rate_threshold", label: t("Tool error rate", "معدّل أخطاء الأدوات"), suffix: "(0–1)", step: 0.01 },
              { key: "approval_sla_seconds", label: t("Approval SLA", "اتفاقية مستوى خدمة الموافقة"), suffix: t("seconds", "ثانية") },
              { key: "window", label: t("Detection window", "نافذة الاكتشاف"), suffix: t("audit records", "سجلّات تدقيق") },
            ].map((th) => (
              <tr key={th.key} className="hover:bg-black/[0.04]">
                <Td>{th.label}</Td>
                <Td><span className="text-black/60">{an[th.key] ?? "—"} {th.suffix}</span></Td>
                <Td right><GhostBtn onClick={() => setThr({ key: th.key, label: th.label, value: an[th.key], step: th.step })}>{t("Edit", "تعديل")}</GhostBtn></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardBox>
      <p className="text-xs text-black/40 -mt-2">
        {t("Alerts surface in the notification panel and the Anomaly page. External delivery (email / webhook) arrives with the SIEM integration.",
          "تظهر التنبيهات في لوحة الإشعارات وصفحة رصد الشذوذ. سيتوفر التسليم الخارجي (البريد الإلكتروني / webhook) مع تكامل SIEM.")}
      </p>
      {thr && (
        <Modal title={t(`Edit — ${thr.label}`, `تعديل — ${thr.label}`)} onClose={() => setThr(null)}>
          <Field label={t("Value", "القيمة")}>
            <TextInput type="number" step={thr.step || 1} value={thr.value}
              onChange={(e) => setThr({ ...thr, value: Number(e.target.value) })} />
          </Field>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setThr(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={saveThreshold}>{t("Save", "حفظ")}</PrimaryBtn>
          </div>
        </Modal>
      )}
    </>
  );
}

// Session policy (A12): the console used to sign you out at ~10-15 minutes with no warning
// and no setting anywhere. These are the knobs behind that.
function SessionPolicy() {
  const { data: st, reload } = useApi<any>("/api/admin/settings");
  const [edit, setEdit] = useState<{ key: string; label: string; hint: string; value: number } | null>(null);
  const s = st?.effective?.session;
  if (!s) return null;

  const save = async () => {
    if (!edit) return;
    try {
      await apiPost("/api/admin/settings", { section: "session", patch: { [edit.key]: edit.value } });
      setEdit(null); reload();
      toast(t("Session policy updated — applies to the next sign-in or renewal.", "تم تحديث سياسة الجلسة — تسري على تسجيل الدخول أو التجديد التالي."));
    } catch (e: any) { toast(e?.message || t("Could not save", "تعذّر الحفظ"), "err"); }
  };

  const mins = (sec: number) => sec >= 3600 ? t(`${(sec / 3600).toFixed(sec % 3600 ? 1 : 0)} hours`, `${(sec / 3600).toFixed(sec % 3600 ? 1 : 0)} ساعة`)
    : sec >= 60 ? t(`${Math.round(sec / 60)} minutes`, `${Math.round(sec / 60)} دقيقة`) : t(`${sec} seconds`, `${sec} ثانية`);

  const rows = [
    { key: "ttl_seconds", label: t("Idle timeout", "مهلة الخمول"), value: s.ttl_seconds,
      hint: t("How long a session survives with no activity. While you are working it renews silently, so this only bites when you stop.",
        "المدة التي تبقى فيها الجلسة قائمة دون أي نشاط. أثناء عملك تتجدد الجلسة بصمت، لذا لا يؤثر هذا إلا عند توقفك.") },
    { key: "absolute_seconds", label: t("Maximum session length", "الحد الأقصى لمدة الجلسة"), value: s.absolute_seconds,
      hint: t("A hard cap regardless of activity. Past it, you must sign in again — no amount of clicking extends it.",
        "سقف صارم بصرف النظر عن النشاط. بعد تجاوزه يجب عليك تسجيل الدخول مجدداً — لا يمدّده أي قدر من النقر.") },
    { key: "warn_seconds", label: t("Expiry warning", "تنبيه انتهاء الصلاحية"), value: s.warn_seconds,
      hint: t("How long before expiry the console warns you, with a countdown and a Stay-signed-in button.",
        "المدة التي تسبق انتهاء الصلاحية والتي تنبّهك خلالها وحدة التحكم، مع عدّاد تنازلي وزر البقاء مسجّلاً الدخول.") },
  ];

  return (
    <>
      <CardBox title={t("Session policy", "سياسة الجلسة")}>
        <table className="w-full">
          <thead><tr><Th>{t("Setting", "الإعداد")}</Th><Th>{t("Value", "القيمة")}</Th><Th right>{t("Action", "الإجراء")}</Th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className="hover:bg-black/[0.04]">
                <Td><div className="flex flex-col">
                  <span>{r.label}</span>
                  <span className="text-xs text-black/40">{r.hint}</span>
                </div></Td>
                <Td><span className="text-black/60 whitespace-nowrap">{mins(r.value)}</span></Td>
                <Td right><GhostBtn onClick={() => setEdit({ ...r })}>{t("Edit", "تعديل")}</GhostBtn></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardBox>
      {edit && (
        <Modal title={t(`Edit — ${edit.label}`, `تعديل — ${edit.label}`)} onClose={() => setEdit(null)}>
          <Field label={t("Seconds", "الثواني")}>
            <TextInput type="number" min={15} value={edit.value}
              onChange={(e) => setEdit({ ...edit, value: Number(e.target.value) })} />
          </Field>
          <p className="text-xs text-black/40">{edit.hint}</p>
          <div className="flex gap-2 justify-end">
            <GhostBtn onClick={() => setEdit(null)}>{t("Cancel", "إلغاء")}</GhostBtn>
            <PrimaryBtn onClick={save}>{t("Save", "حفظ")}</PrimaryBtn>
          </div>
        </Modal>
      )}
    </>
  );
}

function SettingsPage({ d, onChanged }: { d: Dashboard; onChanged: () => void }) {
  const [busy, setBusy] = useState("");
  const { lang, setLang } = useLang();

  // A toggle either writes to the settings overlay, or is explicitly marked read-only
  // (deploy-time config). Nothing in between — no switch that silently does nothing.
  const toggle = async (s: (typeof d.settings)[number]) => {
    if (s.readOnly || !s.section) return;
    setBusy(s.name);
    try {
      const patch = s.rule ? { detectors: { [s.rule]: !s.on } } : { [s.key!]: !s.on };
      await apiPost("/api/admin/settings", { section: s.section, patch });
      onChanged();
      toast(t(`${s.name} ${!s.on ? "enabled" : "disabled"}.`, `${s.name} ${!s.on ? "مفعّل" : "معطّل"}.`));
    } catch (e: any) {
      toast(e?.message || t("Could not save", "تعذّر الحفظ"), "err");
    } finally { setBusy(""); }
  };
  const settings = d.settings;
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Settings", "الإعدادات")}</h1>
        <span className="text-xs text-black/40">{t("Changes apply to the next request", "تسري التغييرات على الطلب التالي")}</span>
      </div>
      <CardBox>
        <div className="flex items-center gap-3 py-1">
          <div className="flex flex-col flex-1 min-w-0">
            <span className="text-sm text-black">{t("Language", "اللغة")}</span>
            <span className="text-xs text-black/40">{t("Switches the whole dashboard and its direction", "تبدّل لغة لوحة التحكم واتجاهها بالكامل")}</span>
          </div>
          <div className="flex rounded-full p-0.5 shrink-0" style={{ background: "#f0f0f2" }}>
            <button onClick={() => setLang("ar")}
              className={`text-xs px-4 py-1.5 rounded-full transition-colors ${lang === "ar" ? "bg-white text-black shadow-sm font-medium" : "text-black/50 hover:text-black"}`}>{t("Arabic", "العربية")}</button>
            <button onClick={() => setLang("en")}
              className={`text-xs px-4 py-1.5 rounded-full transition-colors ${lang === "en" ? "bg-white text-black shadow-sm font-medium" : "text-black/50 hover:text-black"}`}>English</button>
          </div>
        </div>
      </CardBox>
      <CardBox>
        <div className="flex flex-col">
          {settings.map((s, i) => (
            <div key={s.name} className={`flex items-center gap-3 py-3 ${i > 0 ? "border-t border-black/5" : ""}`}>
              <div className="flex flex-col flex-1 min-w-0">
                <span className="text-sm text-black">{s.name}</span>
                <span className="text-xs text-black/40">{s.detail}</span>
              </div>
              {busy === s.name && <span className="text-xs text-black/30">{t("saving…", "جارٍ الحفظ…")}</span>}
              {s.readOnly ? (
                <span className="text-xs px-2 py-0.5 rounded-full shrink-0"
                  style={{ background: "rgba(0,0,0,0.05)", color: "rgba(0,0,0,0.5)" }}
                  title={t("Set at deploy time in config.yaml — not editable from the console.", "يُضبط وقت النشر في config.yaml — غير قابل للتعديل من وحدة التحكم.")}>
                  {s.on ? t("on · config", "مفعّل · إعداد") : t("off · config", "معطّل · إعداد")}
                </span>
              ) : (
                <Toggle on={s.on} onClick={() => toggle(s)} />
              )}
            </div>
          ))}
        </div>
      </CardBox>
      <p className="text-xs text-black/40 -mt-2">
        {t("Toggles write to the runtime settings overlay and take effect immediately. Items marked", "تكتب المفاتيح إلى طبقة إعدادات وقت التشغيل وتصبح سارية فوراً. العناصر المعلَّمة بـ")}
        <span className="text-black/60">{t("config", "إعداد")}</span> {t("are deploy-time settings in config.yaml and are shown read-only rather than as a switch that does nothing.", "هي إعدادات وقت النشر في config.yaml وتُعرض للقراءة فقط بدلاً من مفتاح لا يفعل شيئاً.")}
      </p>
      <SessionPolicy />
    </>
  );
}

// ── Gateway self-page (A10/A11/A13/A23) ──────────────────────────────────────
// The gateway watched every server, tool, identity and call — and knew nothing about
// itself: no version, no uptime, no idea whether last night's backup ran, no warning
// that the TLS certificates it depends on expire in three weeks.

function bytes(n?: number): string {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}
function secs(n?: number | null): string {
  if (n == null) return "—";
  if (n < 60) return `${Math.round(n)}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m`;
  if (n < 86400) return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`;
  return `${Math.floor(n / 86400)}d ${Math.floor((n % 86400) / 3600)}h`;
}
function Pill({ tone, children }: { tone: "ok" | "warn" | "bad" | "mute"; children: React.ReactNode }) {
  const bg = { ok: "#e3f4ec", warn: "#fdf3e0", bad: "#fbe6e6", mute: "rgba(0,0,0,0.05)" }[tone];
  const fg = { ok: "#1F7A5C", warn: "#8a6100", bad: "#B03A36", mute: "rgba(0,0,0,0.5)" }[tone];
  return <span className="text-xs px-2 py-0.5 rounded-full whitespace-nowrap" style={{ background: bg, color: fg }}>{children}</span>;
}

function GatewayPage({ onChanged }: { onChanged: () => void }) {
  const { data: g, reload } = useApi<any>("/api/admin/gateway");
  const [maint, setMaint] = useState<boolean | null>(null);
  const [showCfg, setShowCfg] = useState(false);

  if (!g) return <Empty label={t("Loading gateway status…", "جارٍ تحميل حالة البوابة…")} />;

  const setMaintenance = async (enabled: boolean) => {
    try {
      await apiPost("/api/admin/gateway/maintenance", {
        enabled, message: enabled ? t("Scheduled maintenance — tool calls are paused.", "صيانة مجدولة — استدعاءات الأدوات متوقفة مؤقتاً.") : "",
      });
      setMaint(null); reload(); onChanged();
      toast(enabled ? t("Maintenance mode ON — tool calls paused for non-admins.", "وضع الصيانة مفعّل — استدعاءات الأدوات متوقفة مؤقتاً لغير المسؤولين.")
                    : t("Maintenance mode OFF — tool calls resumed.", "وضع الصيانة معطّل — استؤنفت استدعاءات الأدوات."));
    } catch (e: any) { toast(e?.message || t("Could not change maintenance mode", "تعذّر تغيير وضع الصيانة"), "err"); }
  };

  const b = g.backups || {};
  const s = g.storage || {};
  const certs: any[] = g.certificates || [];
  const worstCert = certs[0];

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("Gateway", "البوابة")}</h1>
        <div className="flex items-center gap-2">
          <GhostBtn onClick={reload}>{t("Refresh", "تحديث")}</GhostBtn>
          {g.maintenance?.enabled
            ? <PrimaryBtn danger onClick={() => setMaintenance(false)}>{t("Exit maintenance", "الخروج من وضع الصيانة")}</PrimaryBtn>
            : <GhostBtn danger onClick={() => setMaint(true)}>{t("Enter maintenance", "الدخول في وضع الصيانة")}</GhostBtn>}
        </div>
      </div>

      {g.maintenance?.enabled && (
        <div className="rounded-[14px] px-4 py-3 bg-[#fff4e0] border border-[#e8b04b]/40 text-sm text-[#7a5410]">
          <b>{t("Maintenance mode is ON.", "وضع الصيانة مفعّل.")}</b> {g.maintenance.message} {t("Engaged by", "بدأه")} {g.maintenance.by}.
          {t("Admins can still call tools; everyone else is paused.", "لا يزال بإمكان المسؤولين استدعاء الأدوات؛ أما البقية فمتوقفون مؤقتاً.")}
        </div>
      )}

      <div className="flex gap-3 flex-wrap">
        <StatCard label={t("Version", "الإصدار")} value={g.version} change={null} bg="#edeefc" />
        <StatCard label={t("Uptime", "مدة التشغيل")} value={secs(g.uptime_seconds)} change="live" bg="#e6f1fd" />
        <StatCard label={t("Servers", "الخوادم")} value={`${g.server_count}`} change={null} bg="#edeefc" />
        <StatCard label={t("Tools", "الأدوات")} value={`${g.tool_count}`} change={null} bg="#e6f1fd" />
      </div>

      <div className="flex gap-3 flex-wrap items-start">
        <div className="flex-1 min-w-[320px] flex flex-col gap-3">
          <CardBox title={t("Backups", "النسخ الاحتياطية")}>
            {b.configured ? (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-black">{t("Last run", "آخر تشغيل")}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-black/60">{b.latest} · {t(`${secs(b.age_hours * 3600)} ago`, `منذ ${secs(b.age_hours * 3600)}`)}</span>
                    {b.status === "ok" ? <Pill tone="ok">{t("healthy", "سليم")}</Pill> : <Pill tone="bad">{t("stale", "قديم")}</Pill>}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-black">{t("Size / retained", "الحجم / المحتفظ به")}</span>
                  <span className="text-sm text-black/60">{t(`${bytes(b.size_bytes)} · ${b.retained_runs} runs`, `${bytes(b.size_bytes)} · ${b.retained_runs} تشغيلة`)}</span>
                </div>
                <span className="text-xs text-black/40 break-all">{b.location}</span>
                {b.status !== "ok" && (
                  <p className="text-xs" style={{ color: "#B03A36" }}>
                    {t("No backup in over 36 hours — the daily job may have stopped. A silently failing backup is discovered on the day it is needed.",
                      "لم يُنجز أي نسخ احتياطي منذ أكثر من 36 ساعة — قد تكون المهمة اليومية توقفت. نسخ احتياطي فاشل بصمت يُكتشف يوم الحاجة إليه.")}
                  </p>
                )}
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                <Pill tone="warn">{t("no backup runs found", "لم يُعثر على عمليات نسخ احتياطي")}</Pill>
                <span className="text-xs text-black/40">{b.detail}</span>
              </div>
            )}
          </CardBox>

          <CardBox title={t("Certificates", "الشهادات")}>
            {certs.length ? (
              <table className="w-full">
                <thead><tr><Th>{t("Certificate", "الشهادة")}</Th><Th>{t("Expires in", "تنتهي خلال")}</Th><Th right>{t("Status", "الحالة")}</Th></tr></thead>
                <tbody>
                  {certs.map((c) => (
                    <tr key={c.name} className="hover:bg-black/[0.04]">
                      <Td><div className="flex flex-col"><span>{c.name}</span>
                        <span className="text-xs text-black/40 truncate">{c.subject}</span></div></Td>
                      <Td><span className="text-black/60">{c.days_left < 0 ? t("expired", "منتهية الصلاحية") : t(`${Math.round(c.days_left)} days`, `${Math.round(c.days_left)} يوم`)}</span></Td>
                      <Td right>{c.status === "ok" ? <Pill tone="ok">{t("ok", "سليمة")}</Pill>
                        : c.status === "expiring" ? <Pill tone="warn">{t("expiring", "تقترب من الانتهاء")}</Pill>
                        : <Pill tone="bad">{t("EXPIRED", "منتهية الصلاحية")}</Pill>}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <Empty label={t("No certificates found on disk.", "لم يُعثر على شهادات على القرص.")} />}
            {worstCert && worstCert.status !== "ok" && (
              <p className="text-xs" style={{ color: "#B03A36" }}>
                {t("An expiring certificate is an outage with a known date. Rotate before it lands.", "الشهادة القريبة من الانتهاء هي انقطاع بموعد معلوم. جدّدها قبل حلول الموعد.")}
              </p>
            )}
          </CardBox>
        </div>

        <div className="flex-1 min-w-[320px] flex flex-col gap-3">
          <CardBox title={t("Storage & log growth", "التخزين ونمو السجلّات")}>
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-black">{t("Disk", "القرص")}</span>
                <span className="text-sm text-black/60">
                  {t(`${bytes(s.disk?.free_bytes)} free of ${bytes(s.disk?.total_bytes)} (${s.disk?.used_pct}% used)`,
                    `${bytes(s.disk?.free_bytes)} متاح من ${bytes(s.disk?.total_bytes)} (استخدام ${s.disk?.used_pct}%)`)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-black">{t("Gateway data", "بيانات البوابة")}</span>
                <span className="text-sm text-black/60">{bytes(s.data_bytes)}</span>
              </div>
              {s.audit_growth && (
                <>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-black">{t("Audit chain growth", "نمو سلسلة التدقيق")}</span>
                    <span className="text-sm text-black/60">
                      {t(`${bytes(s.audit_growth.bytes_per_day)}/day · ${s.audit_growth.days_of_history}d history`,
                        `${bytes(s.audit_growth.bytes_per_day)}/يوم · ${s.audit_growth.days_of_history} يوم من السجل`)}
                    </span>
                  </div>
                  {s.audit_growth.days_until_full != null && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-black">{t("Projected disk exhaustion", "الاستنفاد المتوقع لسعة القرص")}</span>
                      {/* Precision here is false comfort: at the current growth rate the
                          honest answer is usually "not a concern". Only a real deadline
                          deserves a number. */}
                      {s.audit_growth.days_until_full < 90
                        ? <Pill tone="warn">{t(`${s.audit_growth.days_until_full} days`, `${s.audit_growth.days_until_full} يوم`)}</Pill>
                        : s.audit_growth.days_until_full < 365 * 3
                          ? <span className="text-sm text-black/60">
                              {t(`~${Math.round(s.audit_growth.days_until_full / 30)} months`, `~${Math.round(s.audit_growth.days_until_full / 30)} شهر`)}
                            </span>
                          : <span className="text-sm text-black/60">{t("not a concern at this rate", "غير مقلق بهذا المعدّل")}</span>}
                    </div>
                  )}
                </>
              )}
              <div className="mt-2 flex flex-col gap-1">
                {(s.files || []).slice(0, 6).map((f: any) => (
                  <div key={f.name} className="flex items-center justify-between">
                    <span className="text-xs text-black/50 truncate">{f.name}</span>
                    <span className="text-xs text-black/40">{bytes(f.bytes)}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardBox>

          <CardBox title={t("Runtime", "بيئة التشغيل")}>
            <div className="flex flex-col gap-2">
              {[
                [t("Environment", "البيئة"), g.env],
                ["Python", g.python],
                ["PID", String(g.pid)],
                [t("Started", "بدأ التشغيل"), new Date(g.started_at * 1000).toLocaleString("ar")],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center justify-between">
                  <span className="text-sm text-black">{k}</span>
                  <span className="text-sm text-black/60">{v}</span>
                </div>
              ))}
              <div className="flex items-center justify-between">
                <span className="text-sm text-black">{t("Settings overrides", "تجاوزات الإعدادات")}</span>
                <span className="text-sm text-black/60">
                  {Object.keys(g.settings_overrides || {}).length || t("none", "لا شيء")}
                </span>
              </div>
              <div className="flex justify-end mt-1">
                <GhostBtn onClick={() => setShowCfg(true)}>{t("View effective config", "عرض الإعداد الفعّال")}</GhostBtn>
              </div>
            </div>
          </CardBox>
        </div>
      </div>

      {showCfg && (
        <Modal title={t("Effective configuration", "الإعداد الفعّال")} onClose={() => setShowCfg(false)} width={640}>
          <p className="text-xs text-black/50">
            {t("What the gateway actually loaded — including any runtime overrides. Secret-shaped values are redacted.",
              "ما حمّلته البوابة فعلياً — بما في ذلك أي تجاوزات وقت التشغيل. القيم التي تشبه الأسرار مُنقّحة.")}
          </p>
          <pre className="text-xs bg-black/[0.03] rounded-lg p-3 overflow-auto max-h-[50vh] font-mono">
            {JSON.stringify(g.effective_config, null, 2)}
          </pre>
        </Modal>
      )}
      {maint && (
        <ConfirmModal
          title={t("Enter maintenance mode?", "الدخول في وضع الصيانة؟")}
          body={<>{t("Mediated tool calls will be", "ستكون استدعاءات الأدوات الموسّطة")} <b>{t("paused for all non-admin users", "متوقفة مؤقتاً لجميع المستخدمين غير المسؤولين")}</b>. {t("Admins keep working so they can finish the patch or migration. The console stays up.", "يواصل المسؤولون العمل لإنهاء الرقعة أو الترحيل. تبقى وحدة التحكم متاحة.")}</>}
          confirmLabel={t("Enter maintenance", "الدخول في وضع الصيانة")}
          onCancel={() => setMaint(null)}
          onConfirm={() => setMaintenance(true)} />
      )}
    </>
  );
}

// ── DLP activity (A17) ───────────────────────────────────────────────────────
// Every masking event was already in the audit chain; nothing had ever aggregated them,
// so an admin could not answer "which tool leaks the most PII?" without grepping the log.

function DlpPage() {
  const { data, reload } = useApi<any>("/api/admin/dlp?hours=168");
  if (!data) return <Empty label={t("Loading DLP activity…", "جارٍ تحميل نشاط منع تسرّب البيانات…")} />;
  const has = data.total_detections > 0;
  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("DLP Activity", "نشاط منع تسرّب البيانات")}</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-black/40">{t("last 7 days", "آخر 7 أيام")}</span>
          <GhostBtn onClick={reload}>{t("Refresh", "تحديث")}</GhostBtn>
        </div>
      </div>
      <div className="flex gap-3 flex-wrap">
        <StatCard label={t("Detections", "الاكتشافات")} value={String(data.total_detections)} change={null} bg="#edeefc" />
        <StatCard label={t("Calls with PII", "الاستدعاءات المتضمنة PII")} value={String(data.detected_calls)} change={null} bg="#e6f1fd" />
        <StatCard label={t("Masked", "مقنّعة")} value={String(data.masked_calls)} change={null} bg="#edeefc" />
        <StatCard label={t("Released to cleared callers", "أُطلقت لمستدعين مصرَّح لهم")} value={String(data.unmasked_calls)} change={null} bg="#e6f1fd" />
      </div>
      {!has ? (
        <CardBox><Empty label={t("No PII detected in this window.", "لم يُكتشف أي PII في هذه النافذة الزمنية.")} /></CardBox>
      ) : (
        <div className="flex gap-3 flex-wrap items-start">
          <div className="flex-1 min-w-[300px]">
            <CardBox title={t("By detector", "حسب الكاشف")}>
              <table className="w-full">
                <thead><tr><Th>{t("Detector", "الكاشف")}</Th><Th right>{t("Detections", "الاكتشافات")}</Th></tr></thead>
                <tbody>
                  {data.by_detector.map((r: any) => (
                    <tr key={r.type} className="hover:bg-black/[0.04]">
                      <Td>{r.type}</Td><Td right>{r.count}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardBox>
          </div>
          <div className="flex-1 min-w-[300px]">
            <CardBox title={t("Top tools by PII exposure", "أكثر الأدوات تعرّضاً لـPII")}>
              <table className="w-full">
                <thead><tr><Th>{t("Tool", "أداة")}</Th><Th right>{t("Detections", "الاكتشافات")}</Th></tr></thead>
                <tbody>
                  {data.by_tool.map((r: any) => (
                    <tr key={r.tool} className="hover:bg-black/[0.04]">
                      <Td>{r.tool}</Td><Td right>{r.count}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardBox>
          </div>
          <div className="flex-1 min-w-[300px]">
            <CardBox title={t("Top callers", "أكثر المستدعين نشاطاً")}>
              <table className="w-full">
                <thead><tr><Th>{t("Operator", "المشغّل")}</Th><Th right>{t("Detections", "الاكتشافات")}</Th></tr></thead>
                <tbody>
                  {data.by_user.map((r: any) => (
                    <tr key={r.user} className="hover:bg-black/[0.04]">
                      <Td>{r.user}</Td><Td right>{r.count}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardBox>
          </div>
        </div>
      )}
      <p className="text-xs text-black/40 -mt-2">
        {t(`"Released to cleared callers" means the PII was detected but the caller's clearance dominated the data's classification, so it was not masked — the ABAC decision, working as designed. Detectors are configured on the Settings page.`,
          `"أُطلقت لمستدعين مصرَّح لهم" تعني أنه تم اكتشاف PII لكن تصنيف المستدعي الأمني غلب على تصنيف البيانات، فلم تُقنَّع — وهو قرار ABAC يعمل كما صُمم. تُضبط الكاشفات من صفحة الإعدادات.`)}
      </p>
    </>
  );
}

// ── Right sidebar ─────────────────────────────────────────────────────────────

function NotifIcon({ bg, children }: { bg: string; children: React.ReactNode }) {
  return <div className="w-6 h-6 rounded-lg flex items-center justify-center shrink-0" style={{ background: bg }}>{children}</div>;
}

function RightSidebarRail({ setOpen, setPage, clients, unread }: { setOpen: (v: boolean) => void; setPage: (p: Page) => void; clients: Dashboard["clients"]; unread: number }) {
  return (
    <aside className="w-[72px] h-full flex flex-col items-center overflow-y-auto no-scrollbar border-l border-black/10 py-3 gap-1.5 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <button title={t("Notifications", "الإشعارات")} onClick={() => setOpen(true)} className="relative p-2.5 rounded-xl hover:bg-black/[0.08] cursor-pointer">
        <Bell size={20} strokeWidth={1.5} className="text-black" />
        <BellBadge unread={unread} />
      </button>
      <button title={t("Activities", "الأنشطة")} onClick={() => setOpen(true)} className="p-2.5 rounded-xl hover:bg-black/[0.08] cursor-pointer">
        <span className="flex items-center justify-center" style={{ transform: "scale(1.35)", width: 16, height: 16 }}><ActivitySmallIcon /></span>
      </button>
      <div className="w-7 h-px bg-black/10 my-2" />
      {clients.map((c, i) => (
        <button key={c.name + i} title={`${c.name} · ${c.status}`} onClick={() => setPage("Clients")} className="relative p-1 rounded-xl hover:bg-black/[0.08] cursor-pointer">
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
  const activities = d.activities.length ? d.activities : [{ text: t("No recent activity.", "لا يوجد نشاط حديث."), time: "" }];
  return (
    <div className="shrink-0 h-full overflow-hidden transition-all duration-200" style={{ width: 300 }}>
      <aside className="w-[300px] h-full border-l border-black/10 overflow-y-auto flex flex-col p-4 gap-4 bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
        <NotificationFeed items={notifs} unread={unread} onMarkAllRead={onMarkAllRead} onClearRead={onClearRead} />
        <div className="flex flex-col gap-1 relative">
          <p className="text-sm text-black font-normal px-1 py-2">{t("Activities", "الأنشطة")}</p>
          {activities.map((a, i) => (
            <div key={i} className="flex items-start gap-2 p-2 rounded-xl">
              <div className="rounded-full shrink-0 bg-white border border-black/10" style={{ width: 24, height: 24 }} />
              <div className="flex flex-col min-w-0"><span className="text-sm text-black leading-5">{a.text}</span><span className="text-xs text-black/40 leading-4">{a.time}</span></div>
            </div>
          ))}
        </div>
        <div className="flex flex-col gap-1">
          <p className="text-sm text-black font-normal px-1 py-2">{t("Connected Clients", "العملاء المتصلون")}</p>
          {(d.clients.length ? d.clients : []).map((c, i) => (
            <div key={c.name + i} onClick={() => setPage("Clients")} className="flex items-center gap-2 p-2 rounded-xl hover:bg-black/[0.08] cursor-pointer">
              <InitialAvatar name={c.name} bg={CLIENT_COLORS[i % CLIENT_COLORS.length]} />
              <span className="text-sm text-black flex-1">{c.name}</span>
              {c.status === "Online" && <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: STATUS_COLOR.Online }} />}
            </div>
          ))}
          {d.clients.length === 0 && <span className="text-xs text-black/30 px-2 py-1">{t("No clients connected.", "لا يوجد عملاء متصلون.")}</span>}
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
            <span className="text-sm font-semibold text-black">{t("Log out of MCP Gateway?", "تسجيل الخروج من MCP Gateway؟")}</span>
            <span className="text-xs text-black/40 leading-4">{t("Your session will end. Queued tool-call approvals stay paused until you sign back in.", "ستنتهي جلستك. تبقى موافقات استدعاء الأدوات المعلّقة متوقفة حتى تسجّل الدخول مجدداً.")}</span>
          </div>
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onCancel} className="text-xs text-black px-4 py-2 rounded-lg border border-black/10 hover:bg-black/[0.08]">{t("Cancel", "إلغاء")}</button>
          <button onClick={onConfirm} className="text-xs text-white px-4 py-2 rounded-lg bg-[#1C1C1C] hover:opacity-80">{t("Log out", "تسجيل الخروج")}</button>
        </div>
      </div>
    </div>
  );
}

function LoggedOutScreen({ onSignIn, reason }: { onSignIn: () => void; reason?: string }) {
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-white" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="bg-[#f9f9fa] rounded-[20px] p-8 w-[360px] flex flex-col items-center gap-4 text-center">
        <div className="w-10 h-10 rounded-xl bg-[#4C98FD] flex items-center justify-center"><div className="w-4 h-4 bg-white rounded-sm opacity-90" /></div>
        <div className="flex flex-col gap-1">
          <span className="text-sm font-semibold text-black">{t("You've been logged out", "تم تسجيل خروجك")}</span>
          {/* Say WHY. Being dumped on a login screen with no explanation is how an admin
              loses trust in a console (and their place in an approval queue). */}
          <span className="text-xs text-black/40 leading-4">
            {reason || t("Thanks for using MCP Gateway. Sign back in to keep monitoring your servers, tools and traffic.", "شكراً لاستخدامك MCP Gateway. سجّل الدخول مجدداً لمواصلة مراقبة خوادمك وأدواتك وحركة المرور.")}
          </span>
        </div>
        <button onClick={onSignIn} className="text-xs text-white px-5 py-2 rounded-lg bg-[#1C1C1C] hover:opacity-80">{t("Sign back in", "تسجيل الدخول مرة أخرى")}</button>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

const INITIAL_PAGE = ((): Page => {
  const p = new URLSearchParams(location.search).get("p");
  const all: Page[] = ["Overview", "Servers", "Tools", "Logs", "Clients", "API Keys", "Rate Limits", "Policies", "Alerts", "Settings", "Approvals", "Audit", "Identities", "Registry", "Kill Switch", "Anomaly", "Sessions", "Gateway", "DLP", "Activity"];
  return (all.includes(p as Page) ? p : "Overview") as Page;
})();

function Dashboard_({ user, onLoggedOut }: { user: User; onLoggedOut: (reason?: string) => void }) {
  const { lang } = useLang();
  const [page, setPage] = useState<Page>(INITIAL_PAGE);
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [query, setQuery] = useState("");
  const [range, setRange] = useState<Range>("Last 7 days");
  const [dark, setDark] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [manage, setManage] = useState<ServerRow | null>(null);

  const onAuthExpired = useCallback(() => onLoggedOut("Your session expired. Please sign in again."),
                                    [onLoggedOut]);
  // Renews silently while you work (so the TTL is an idle timeout), warns with a countdown
  // when you are idle, and explains itself when the absolute cap forces a re-login (A12).
  const session = useSessionGuard(onLoggedOut);
  // The range now drives a real query window against the audit chain (not a curve shape).
  const { data, refresh } = useDashboard(onAuthExpired, range);
  const notif = useNotifications(onAuthExpired);

  const cycleRange = () => setRange(RANGES[(RANGES.indexOf(range) + 1) % RANGES.length]);
  const onRefresh = () => { refresh(); notif.reload(); };

  return (
    <div dir={dirFor(lang)} className="flex h-screen w-screen overflow-hidden bg-white"
      style={dark ? { filter: "invert(1) hue-rotate(180deg)", background: "#fff" } : undefined}>
      {dark && <style>{`img { filter: invert(1) hue-rotate(180deg); }`}</style>}
      <SideNav page={page} setPage={setPage} open={leftOpen} onLogout={() => setLogoutOpen(true)} />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <Header page={page} setPage={setPage} query={query} setQuery={setQuery}
          leftOpen={leftOpen} setLeftOpen={setLeftOpen} rightOpen={rightOpen} setRightOpen={setRightOpen}
          dark={dark} setDark={setDark} onRefresh={onRefresh}
          notifs={notif.items} unread={notif.unread} onMarkAllRead={notif.markAllRead} />
        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4 min-w-0" style={{ fontFamily: "Inter, sans-serif" }}>
          {page === "Overview" && <OverviewPage d={data} range={range} cycleRange={cycleRange} />}
          {page === "Servers" && <ServersPage d={data} query={query} onManage={setManage} onChanged={onRefresh} />}
          {page === "Tools" && <ToolsPage d={data} query={query} />}
          {page === "Logs" && <LogsPage d={data} query={query} />}
          {page === "Clients" && <ClientsPage d={data} query={query} onChanged={onRefresh} />}
          {page === "API Keys" && <ApiKeysPage onAuthExpired={onAuthExpired} />}
          {page === "Rate Limits" && <RateLimitsPage onChanged={onRefresh} />}
          {page === "Policies" && <PoliciesPage d={data} />}
          {page === "Alerts" && <AlertsPage />}
          {page === "Settings" && <SettingsPage d={data} onChanged={onRefresh} />}
          {page === "Gateway" && <GatewayPage onChanged={onRefresh} />}
          {page === "DLP" && <DlpPage />}
          {page === "Approvals" && <ApprovalsPage onAuthExpired={onAuthExpired} />}
          {page === "Registry" && <RegistryPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Identities" && <IdentitiesPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Anomaly" && <AnomalyPage onAuthExpired={onAuthExpired} />}
          {page === "Kill Switch" && <KillSwitchPage onAuthExpired={onAuthExpired} />}
          {page === "Audit" && <AuditPage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Sessions" && <InvestigatePage query={query} onAuthExpired={onAuthExpired} />}
          {page === "Activity" && <ActivityPage query={query} onAuthExpired={onAuthExpired} />}
        </div>
      </div>
      <RightSidebar open={rightOpen} setOpen={setRightOpen} setPage={setPage} d={data}
        notifs={notif.items} unread={notif.unread} onMarkAllRead={notif.markAllRead} onClearRead={notif.clearRead} />
      {manage && <ManageDrawer server={manage} onClose={() => setManage(null)} onChanged={onRefresh} />}
      {logoutOpen && <LogoutModal onCancel={() => setLogoutOpen(false)} onConfirm={async () => { setLogoutOpen(false); await apiLogout(); onLoggedOut("Signed out."); }} />}
      {session.modal}
      <Toaster />
    </div>
  );
}

export default function App() {
  return <LangProvider><AppInner /></LangProvider>;
}
function AppInner() {
  const [user, setUser] = useState<User | null>(getUser());
  const [loggedOut, setLoggedOut] = useState(false);
  const [logoutReason, setLogoutReason] = useState<string>("");
  const [needsPwChange, setNeedsPwChange] = useState<boolean>(!!getUser()?.password_change_required);

  const signOut = useCallback((reason = "") => {
    setLogoutReason(reason);
    setUser(null);
    setLoggedOut(true);
  }, []);

  if (loggedOut) {
    return <LoggedOutScreen reason={logoutReason}
      onSignIn={() => { setLoggedOut(false); setLogoutReason(""); setUser(null); }} />;
  }
  if (!user) {
    return <LoginScreen onDone={(u) => { setUser(u); setNeedsPwChange(!!u.password_change_required); }} />;
  }
  if (needsPwChange) {
    return <ChangePasswordScreen
      onDone={() => setNeedsPwChange(false)}
      onLogout={async () => { await apiLogout(); signOut(); }} />;
  }
  return <Dashboard_ user={user} onLoggedOut={signOut} />;
}
