// Notification center — the dashboard's delivery channel for gateway events.
// Polls /api/admin/notifications, exposes unread count for the header/rail bells,
// and renders the right-panel feed with severity accents and read/unread state.
import { useCallback, useEffect, useRef, useState } from "react";
import { CircleAlert, TriangleAlert, Info, CheckCheck, Trash2 } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/api";

export type Notif = {
  id: string; ts: number; severity: "critical" | "warning" | "info";
  title: string; detail: string; source: string; read: boolean; count: number;
};

const SEV_COLOR = { critical: "#D9534F", warning: "#E5A000", info: "#6B9FD4" } as const;
const SEV_BG = { critical: "#fbe6e6", warning: "#fdf3e0", info: "#e6f1fd" } as const;

export function useNotifications(onAuthExpired: () => void, intervalMs = 12000) {
  const [items, setItems] = useState<Notif[]>([]);
  const [unread, setUnread] = useState(0);
  const timer = useRef<number | null>(null);

  const load = useCallback(() => {
    apiGet<{ notifications: Notif[]; unread: number }>("/api/admin/notifications?limit=100")
      .then((d) => { if (d) { setItems(d.notifications); setUnread(d.unread); } })
      .catch((e) => { if (e instanceof ApiError && e.status === 401) onAuthExpired(); });
  }, [onAuthExpired]);

  useEffect(() => {
    load();
    timer.current = window.setInterval(load, intervalMs);
    return () => { if (timer.current) window.clearInterval(timer.current); };
  }, [load, intervalMs]);

  const markAllRead = useCallback(async () => {
    try { await apiPost("/api/admin/notifications/read", { all: true }); load(); } catch { /* noop */ }
  }, [load]);

  const clearRead = useCallback(async () => {
    try { await apiPost("/api/admin/notifications/clear"); load(); } catch { /* noop */ }
  }, [load]);

  return { items, unread, reload: load, markAllRead, clearRead };
}

export function relTime(ts?: number): string {
  if (!ts) return "";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function SevIcon({ severity, size = 14 }: { severity: Notif["severity"]; size?: number }) {
  const c = SEV_COLOR[severity] ?? SEV_COLOR.info;
  if (severity === "critical") return <CircleAlert size={size} style={{ color: c }} />;
  if (severity === "warning") return <TriangleAlert size={size} style={{ color: c }} />;
  return <Info size={size} style={{ color: c }} />;
}

export function BellBadge({ unread }: { unread: number }) {
  if (!unread) return null;
  return (
    <span className="absolute -top-1 -right-1 min-w-[15px] h-[15px] px-0.5 rounded-full text-white flex items-center justify-center"
      style={{ background: "#D9534F", fontSize: 9, fontWeight: 600, lineHeight: 1 }}>
      {unread > 99 ? "99+" : unread}
    </span>
  );
}

function NotifRow({ n, compact }: { n: Notif; compact?: boolean }) {
  return (
    <div className={`flex items-start gap-2.5 p-2 rounded-xl ${n.read ? "opacity-55" : ""} hover:bg-black/[0.03]`}>
      <div className="w-6 h-6 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
        style={{ background: SEV_BG[n.severity] ?? SEV_BG.info }}>
        <SevIcon severity={n.severity} size={13} />
      </div>
      <div className="flex flex-col min-w-0 flex-1">
        <span className="text-sm text-black leading-5">
          {n.title}
          {n.count > 1 && <span className="ml-1.5 text-xs px-1.5 py-px rounded-full align-middle"
            style={{ background: SEV_BG[n.severity], color: SEV_COLOR[n.severity], fontWeight: 600 }}>×{n.count}</span>}
        </span>
        {!compact && n.detail && <span className="text-xs text-black/50 leading-4">{n.detail}</span>}
        <span className="text-xs text-black/30 leading-4">{relTime(n.ts)}</span>
      </div>
      {!n.read && <span className="w-1.5 h-1.5 rounded-full mt-2 shrink-0" style={{ background: "#4C98FD" }} />}
    </div>
  );
}

// The right-panel feed: grouped New / Earlier with mark-all-read + clear controls.
export function NotificationFeed({ items, unread, onMarkAllRead, onClearRead }: {
  items: Notif[]; unread: number; onMarkAllRead: () => void; onClearRead: () => void;
}) {
  const fresh = items.filter((n) => !n.read);
  const earlier = items.filter((n) => n.read);
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between px-1 py-2">
        <p className="text-sm text-black font-normal">
          Notifications{unread > 0 && <span className="ml-2 text-xs px-1.5 py-0.5 rounded-full text-white" style={{ background: "#D9534F", fontWeight: 600 }}>{unread}</span>}
        </p>
        <div className="flex items-center gap-1">
          {unread > 0 && (
            <button onClick={onMarkAllRead} title="Mark all read" className="p-1 rounded-lg hover:bg-black/[0.04]">
              <CheckCheck size={14} className="text-black/40" />
            </button>
          )}
          {earlier.length > 0 && (
            <button onClick={onClearRead} title="Clear read notifications" className="p-1 rounded-lg hover:bg-black/[0.04]">
              <Trash2 size={14} className="text-black/40" />
            </button>
          )}
        </div>
      </div>
      {items.length === 0 && <span className="text-xs text-black/30 px-2 py-1">All quiet — nothing needs you.</span>}
      {fresh.map((n) => <NotifRow key={n.id} n={n} />)}
      {fresh.length > 0 && earlier.length > 0 && (
        <p className="text-xs text-black/30 px-2 pt-2 pb-1">Earlier</p>
      )}
      {earlier.slice(0, 20).map((n) => <NotifRow key={n.id} n={n} />)}
    </div>
  );
}

// Compact dropdown used by the header bell.
export function NotificationDropdown({ items, unread, onMarkAllRead, onViewAll }: {
  items: Notif[]; unread: number; onMarkAllRead: () => void; onViewAll: () => void;
}) {
  const shown = items.slice(0, 7);
  return (
    <div className="absolute right-0 top-8 w-[300px] bg-white border border-black/10 rounded-2xl shadow-lg p-2 z-50 flex flex-col gap-1">
      <div className="flex items-center justify-between px-2 py-2">
        <p className="text-sm text-black font-normal">Notifications</p>
        {unread > 0 && (
          <button onClick={onMarkAllRead} className="text-xs text-black/40 hover:text-black flex items-center gap-1">
            <CheckCheck size={12} /> Mark all read
          </button>
        )}
      </div>
      {shown.length === 0 && <span className="text-xs text-black/30 px-2 py-2">All quiet — nothing needs you.</span>}
      {shown.map((n) => <NotifRow key={n.id} n={n} compact />)}
      <button onClick={onViewAll} className="text-xs text-black/40 hover:text-black px-2 py-2 text-left">
        View all in panel →
      </button>
    </div>
  );
}
