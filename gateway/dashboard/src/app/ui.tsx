// Shared dashboard primitives: modals, form fields, one-time secret reveal.
// Matches the SnowUI tokens used across the app (rounded-[20px], #f9f9fa, Inter).
import { useState } from "react";
import { Copy, Check, TriangleAlert } from "lucide-react";

export function Modal({ title, onClose, children, width = 420 }: {
  title: string; onClose: () => void; children: React.ReactNode; width?: number;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(0,0,0,0.3)" }} onClick={onClose}>
      <div className="bg-white rounded-[20px] p-6 flex flex-col gap-4 shadow-xl max-h-[85vh] overflow-y-auto"
        style={{ width, fontFamily: "Inter, sans-serif" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold text-black">{title}</span>
          <button onClick={onClose} className="text-xs text-black/40 hover:text-black">Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs text-black/50">{label}</span>
      {children}
    </label>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={"bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30 " + (props.className || "")} />;
}

export function SelectInput(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={"bg-white border border-black/10 rounded-lg px-3 py-2 text-sm outline-none focus:border-black/30 " + (props.className || "")} />;
}

export function PrimaryBtn({ children, onClick, disabled, danger }: {
  children: React.ReactNode; onClick?: () => void; disabled?: boolean; danger?: boolean;
}) {
  return (
    <button onClick={onClick} disabled={disabled}
      className="text-xs text-white px-4 py-2 rounded-lg hover:opacity-80 disabled:opacity-40"
      style={{ background: danger ? "#D9534F" : "#1C1C1C" }}>
      {children}
    </button>
  );
}

export function GhostBtn({ children, onClick, danger }: { children: React.ReactNode; onClick?: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick} className="text-xs px-4 py-2 rounded-lg border border-black/10 hover:bg-black/[0.04]"
      style={danger ? { color: "#D9534F" } : { color: "#000" }}>
      {children}
    </button>
  );
}

export function ConfirmModal({ title, body, confirmLabel = "Confirm", danger = true, onCancel, onConfirm }: {
  title: string; body: React.ReactNode; confirmLabel?: string; danger?: boolean;
  onCancel: () => void; onConfirm: () => void;
}) {
  return (
    <Modal title={title} onClose={onCancel} width={380}>
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0" style={{ background: danger ? "#fbe6e6" : "#edeefc" }}>
          <TriangleAlert size={16} style={{ color: danger ? "#D9534F" : "#1C1C1C" }} />
        </div>
        <div className="text-xs text-black/60 leading-5">{body}</div>
      </div>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onCancel}>Cancel</GhostBtn>
        <PrimaryBtn danger={danger} onClick={onConfirm}>{confirmLabel}</PrimaryBtn>
      </div>
    </Modal>
  );
}

export function CopyRow({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); } catch { /* http context */ }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-black/50">{label}</span>
      <div className="flex items-center gap-2 bg-black/[0.03] rounded-lg px-3 py-2">
        <span className={`text-xs text-black break-all flex-1 ${mono ? "font-mono" : ""}`}>{value}</span>
        <button onClick={copy} title="Copy" className="p-1 rounded hover:bg-black/[0.06] shrink-0">
          {copied ? <Check size={13} style={{ color: "#4AA785" }} /> : <Copy size={13} className="text-black/40" />}
        </button>
      </div>
    </div>
  );
}

// One-time secret handover (temp passwords, TOTP enrollment, API key tokens).
export function SecretModal({ title, note, rows, onClose }: {
  title: string; note: string; rows: { label: string; value: string }[]; onClose: () => void;
}) {
  return (
    <Modal title={title} onClose={onClose} width={460}>
      <div className="rounded-xl p-3 text-xs leading-5" style={{ background: "#fdf3e0", color: "#8a6100" }}>
        {note} <b>This is shown once and cannot be retrieved again.</b>
      </div>
      {rows.map((r) => <CopyRow key={r.label} label={r.label} value={r.value} />)}
      <div className="flex justify-end"><PrimaryBtn onClick={onClose}>Done — stored safely</PrimaryBtn></div>
    </Modal>
  );
}
