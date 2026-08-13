// Access credentials — REAL API key management (issue/revoke against the gateway)
// and the OAuth client inventory (every registered MCP client, revocable).
import { useState } from "react";
import { KeyRound, Ban, Plus } from "lucide-react";
import { useApi } from "./useApi";
import { apiPost } from "@/api";
import { toast } from "./toast";
import { ConfirmModal, Field, GhostBtn, Modal, PrimaryBtn, SecretModal, SelectInput, TextInput } from "./ui";
import { t } from "./i18n";

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
function fmtDate(ts?: number | null) { return ts ? new Date(ts * 1000).toLocaleDateString(t("en", "ar")) : "—"; }
function relTime(ts?: number | null): string {
  if (!ts) return t("never", "أبدًا");
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 90) return t("just now", "الآن");
  if (s < 3600) return t(`${Math.floor(s / 60)}m ago`, `منذ ${Math.floor(s / 60)} د`);
  if (s < 86400) return t(`${Math.floor(s / 3600)}h ago`, `منذ ${Math.floor(s / 3600)} س`);
  return t(`${Math.floor(s / 86400)}d ago`, `منذ ${Math.floor(s / 86400)} يوم`);
}

// Bilingual: rendered via t(v.en, v.ar) at the use site (a module-level map can't
// call t() directly — it would freeze to the import-time language).
const SCOPE_DESC: Record<string, { en: string; ar: string }> = {
  read: { en: "Read-only · tier-0 tools", ar: "قراءة فقط · أدوات المستوى 0" },
  standard: { en: "Read + reversible writes · tier ≤ 1", ar: "قراءة + كتابة قابلة للتراجع · المستوى ≤ 1" },
  full: { en: "Full ceiling of the operator's role", ar: "الحد الأقصى الكامل لدور المشغّل" },
};
function scopeDesc(scope: string): string { const d = SCOPE_DESC[scope]; return d ? t(d.en, d.ar) : scope; }

type KeyRow = {
  kid: string; name: string; sub: string; scope: string; prefix: string;
  created: number; created_by: string; expires: number | null;
  last_used: number | null; revoked: boolean;
};

export function ApiKeysPage({ onAuthExpired }: { onAuthExpired: () => void }) {
  const keys = useApi<{ keys: KeyRow[] }>("/api/admin/apikeys", onAuthExpired);
  const clients = useApi<{ clients: any[] }>("/api/admin/oauth/clients", onAuthExpired);
  const ops = useApi<{ operators: any[] }>("/api/admin/operators", onAuthExpired);
  const [createOpen, setCreateOpen] = useState(false);
  const [minted, setMinted] = useState<{ name: string; token: string } | null>(null);
  const [revokeKey, setRevokeKey] = useState<KeyRow | null>(null);
  const [revokeClient, setRevokeClient] = useState<any | null>(null);

  const rows = keys.data?.keys ?? [];
  const clientRows = clients.data?.clients ?? [];

  const doRevokeKey = async () => {
    if (!revokeKey) return;
    try {
      await apiPost(`/api/admin/apikeys/${revokeKey.kid}/revoke`);
      toast(t(`Key "${revokeKey.name}" revoked — it stops working immediately.`, `تم إبطال المفتاح "${revokeKey.name}" — سيتوقف عن العمل فورًا.`));
      setRevokeKey(null); keys.reload();
    } catch (e: any) { toast(e.message || t("Revoke failed", "فشل الإبطال"), "err"); }
  };

  const doRevokeClient = async () => {
    if (!revokeClient) return;
    try {
      const r = await apiPost(`/api/admin/oauth/clients/${revokeClient.client_id}/revoke`);
      toast(t(`Client revoked — ${r.refresh_tokens_revoked} refresh token(s) killed.`, `تم إبطال العميل — تم إنهاء ${r.refresh_tokens_revoked} من رموز التحديث.`));
      setRevokeClient(null); clients.reload();
    } catch (e: any) { toast(e.message || t("Revoke failed", "فشل الإبطال"), "err"); }
  };

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">{t("API Keys", "مفاتيح API")}</h1>
        <button onClick={() => setCreateOpen(true)}
          className="text-xs text-white px-3 py-1.5 rounded-lg bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1">
          <Plus size={13} /> {t("Create key", "إنشاء مفتاح")}
        </button>
      </div>
      <CardBox title={t("Gateway API keys", "مفاتيح API الخاصة بالبوابة")} right={<span className="text-xs text-black/40">{rows.filter((k) => !k.revoked).length} {t("active", "نشط")}</span>}>
        {rows.length === 0 ? <Empty label={t("No API keys issued yet.", "لم يتم إصدار أي مفاتيح API بعد.")} /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>{t("Name", "الاسم")}</Th><Th>{t("Token", "الرمز")}</Th><Th>{t("Acts as", "يعمل بصفة")}</Th><Th>{t("Scope", "النطاق")}</Th><Th>{t("Created", "تاريخ الإنشاء")}</Th><Th>{t("Expires", "تاريخ الانتهاء")}</Th><Th>{t("Last used", "آخر استخدام")}</Th><Th right></Th></tr></thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k.kid} className={`hover:bg-black/[0.04] ${k.revoked ? "opacity-45" : ""}`}>
                  <Td><span className="flex items-center gap-1.5"><KeyRound size={13} className="text-black/30" />{k.name}</span></Td>
                  <Td><span className="text-black/50 text-xs font-mono">{k.prefix}</span></Td>
                  <Td>{k.sub}</Td>
                  <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }} title={scopeDesc(k.scope)}>{k.scope}</span></Td>
                  <Td><span className="text-black/60">{fmtDate(k.created)}</span></Td>
                  <Td><span className="text-black/60">{k.expires ? fmtDate(k.expires) : t("never", "أبدًا")}</span></Td>
                  <Td><span className="text-black/60">{relTime(k.last_used)}</span></Td>
                  <Td right>
                    {k.revoked
                      ? <span className="text-xs" style={{ color: "#D9534F" }}>{t("revoked", "مُبطَل")}</span>
                      : <button onClick={() => setRevokeKey(k)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1 ml-auto" style={{ color: "#D9534F" }}><Ban size={12} /> {t("Revoke", "إبطال")}</button>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>

      <CardBox title={t("OAuth clients (Connect-your-AI)", "عملاء OAuth (Connect-your-AI)")} right={<span className="text-xs text-black/40">{clientRows.length} {t("registered", "مسجَّل")}</span>}>
        {clientRows.length === 0 ? <Empty label={t("No OAuth clients registered.", "لم يتم تسجيل أي عملاء OAuth.")} /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>{t("Client", "العميل")}</Th><Th>{t("Client ID", "معرّف العميل")}</Th><Th>{t("Authorized by", "صرّح به")}</Th><Th right>{t("Refresh tokens", "رموز التحديث")}</Th><Th>{t("Registered", "تاريخ التسجيل")}</Th><Th>{t("Last used", "آخر استخدام")}</Th><Th right></Th></tr></thead>
            <tbody>
              {clientRows.map((c) => (
                <tr key={c.client_id} className="hover:bg-black/[0.04]">
                  <Td>{c.client_name || <span className="text-black/40">{t("(unnamed)", "(بدون اسم)")}</span>}</Td>
                  <Td><span className="text-black/50 text-xs font-mono">{c.client_id}</span></Td>
                  <Td><span className="text-black/60 text-xs">{(c.subjects || []).join(", ") || "—"}</span></Td>
                  <Td right>{c.active_refresh_tokens}</Td>
                  <Td><span className="text-black/60">{fmtDate(c.created)}</span></Td>
                  {/* A dead registration that should be revoked — or one that woke up after
                      six months — is only visible if we show when it was last used (A21). */}
                  <Td><span className="text-black/60">{relTime(c.last_used)}</span></Td>
                  <Td right>
                    <button onClick={() => setRevokeClient(c)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.08] flex items-center gap-1 ml-auto" style={{ color: "#D9534F" }}><Ban size={12} /> {t("Revoke", "إبطال")}</button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>

      {createOpen && (
        <CreateKeyModal operators={(ops.data?.operators ?? []).map((o) => o.sub)}
          onClose={() => setCreateOpen(false)}
          onCreated={(name, token) => { setCreateOpen(false); setMinted({ name, token }); keys.reload(); }} />
      )}
      {minted && (
        <SecretModal title={t(`API key "${minted.name}" created`, `تم إنشاء مفتاح API "${minted.name}"`)}
          note={t("Copy the token into your CI secret manager or client config now.", "انسخ الرمز الآن إلى مدير أسرار CI أو إعدادات العميل.")}
          rows={[{ label: t("API key token", "رمز مفتاح API"), value: minted.token }]}
          onClose={() => setMinted(null)} />
      )}
      {revokeKey && (
        <ConfirmModal title={t("Revoke API key?", "إبطال مفتاح API؟")}
          body={<>{t("The key ", "المفتاح ")}<b>{revokeKey.name}</b> ({revokeKey.prefix}){t(" stops working immediately. Anything using it will start failing auth. This cannot be undone.", " سيتوقف عن العمل فورًا. أي شيء يستخدمه سيبدأ بالفشل في المصادقة. لا يمكن التراجع عن هذا الإجراء.")}</>}
          confirmLabel={t("Revoke key", "إبطال المفتاح")} onCancel={() => setRevokeKey(null)} onConfirm={doRevokeKey} />
      )}
      {revokeClient && (
        <ConfirmModal title={t("Revoke OAuth client?", "إبطال عميل OAuth؟")}
          body={<>{t("Client ", "سيتم حذف العميل ")}<b>{revokeClient.client_name || revokeClient.client_id}</b>{t(" is deleted and all ", " وستُلغى جميع رموز التحديث البالغ عددها ")}{revokeClient.active_refresh_tokens}{t(" of its refresh token(s) die. Connected AI clients must re-authorize from scratch.", ". يجب على عملاء الذكاء الاصطناعي المتصلين إعادة التفويض من جديد.")}</>}
          confirmLabel={t("Revoke client", "إبطال العميل")} onCancel={() => setRevokeClient(null)} onConfirm={doRevokeClient} />
      )}
    </>
  );
}

function CreateKeyModal({ operators, onClose, onCreated }: {
  operators: string[]; onClose: () => void; onCreated: (name: string, token: string) => void;
}) {
  const [name, setName] = useState("");
  const [sub, setSub] = useState(operators[0] || "");
  const [scope, setScope] = useState("read");
  const [ttl, setTtl] = useState("90");
  const [busy, setBusy] = useState(false);
  const create = async () => {
    if (!name.trim()) { toast(t("Give the key a name", "أدخل اسمًا للمفتاح"), "err"); return; }
    setBusy(true);
    try {
      const r = await apiPost("/api/admin/apikeys", {
        name: name.trim(), sub, scope,
        ttl_days: ttl === "never" ? null : Number(ttl),
      });
      onCreated(name.trim(), r.token);
    } catch (e: any) { toast(e.message || t("Create failed", "فشل الإنشاء"), "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title={t("Create API key", "إنشاء مفتاح API")} onClose={onClose}>
      <Field label={t("Name (what will use this key?)", "الاسم (ما الذي سيستخدم هذا المفتاح؟)")}>
        <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. ci-pipeline", "مثلاً: ci-pipeline")} autoFocus />
      </Field>
      <Field label={t("Acts as operator (the key inherits their role, capped by scope)", "يعمل بصفة المشغّل (يرث المفتاح دوره، محدودًا بالنطاق)")}>
        <SelectInput value={sub} onChange={(e) => setSub(e.target.value)}>
          {operators.map((o) => <option key={o} value={o}>{o}</option>)}
        </SelectInput>
      </Field>
      <Field label={t("Scope", "النطاق")}>
        <SelectInput value={scope} onChange={(e) => setScope(e.target.value)}>
          {Object.entries(SCOPE_DESC).map(([s, d]) => <option key={s} value={s}>{s} — {t(d.en, d.ar)}</option>)}
        </SelectInput>
      </Field>
      <Field label={t("Expiry", "تاريخ الانتهاء")}>
        <SelectInput value={ttl} onChange={(e) => setTtl(e.target.value)}>
          <option value="30">{t("30 days", "30 يومًا")}</option>
          <option value="90">{t("90 days", "90 يومًا")}</option>
          <option value="365">{t("1 year", "سنة واحدة")}</option>
          <option value="never">{t("Never (not recommended)", "أبدًا (غير موصى به)")}</option>
        </SelectInput>
      </Field>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>{t("Cancel", "إلغاء")}</GhostBtn>
        <PrimaryBtn onClick={create} disabled={busy}>{busy ? t("Creating…", "جارٍ الإنشاء…") : t("Create key", "إنشاء مفتاح")}</PrimaryBtn>
      </div>
    </Modal>
  );
}
