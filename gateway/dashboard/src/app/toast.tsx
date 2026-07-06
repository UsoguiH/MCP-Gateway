import { useEffect, useState } from "react";

type Toast = { id: number; msg: string; kind: "ok" | "err" };
let seq = 0;
const listeners = new Set<(t: Toast[]) => void>();
let toasts: Toast[] = [];

function emit() { listeners.forEach((l) => l(toasts)); }

export function toast(msg: string, kind: "ok" | "err" = "ok") {
  const t = { id: ++seq, msg, kind };
  toasts = [...toasts, t];
  emit();
  setTimeout(() => { toasts = toasts.filter((x) => x.id !== t.id); emit(); }, 3200);
}

export function Toaster() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => { listeners.add(setItems); return () => { listeners.delete(setItems); }; }, []);
  return (
    <div className="fixed bottom-5 right-5 z-[60] flex flex-col gap-2" style={{ fontFamily: "Inter, sans-serif" }}>
      {items.map((t) => (
        <div key={t.id} className="text-sm text-white px-4 py-2 rounded-xl shadow-lg"
          style={{ background: t.kind === "err" ? "#D9534F" : "#1C1C1C", maxWidth: 340 }}>
          {t.msg}
        </div>
      ))}
    </div>
  );
}
