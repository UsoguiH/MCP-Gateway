// Access credentials — REAL API key management (issue/revoke against the gateway)
// and the OAuth client inventory (every registered MCP client, revocable).
import { useState } from "react";
import { KeyRound, Ban, Plus } from "lucide-react";
import { useApi } from "./useApi";
import { apiPost } from "@/api";
import { toast } from "./toast";
import { ConfirmModal, Field, GhostBtn, Modal, PrimaryBtn, SecretModal, SelectInput, TextInput } from "./ui";

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
function fmtDate(ts?: number | null) { return ts ? new Date(ts * 1000).toLocaleDateString() : "—"; }
function relTime(ts?: number | null): string {
  if (!ts) return "never";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const SCOPE_DESC: Record<string, string> = {
  read: "Read only · tier 0 tools",
  standard: "Read + reversible writes · tier ≤ 1",
  full: "Operator's full role ceiling",
};

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
      toast(`Key "${revokeKey.name}" revoked — it stops working immediately.`);
      setRevokeKey(null); keys.reload();
    } catch (e: any) { toast(e.message || "Revoke failed", "err"); }
  };

  const doRevokeClient = async () => {
    if (!revokeClient) return;
    try {
      const r = await apiPost(`/api/admin/oauth/clients/${revokeClient.client_id}/revoke`);
      toast(`Client revoked — ${r.refresh_tokens_revoked} refresh token(s) killed.`);
      setRevokeClient(null); clients.reload();
    } catch (e: any) { toast(e.message || "Revoke failed", "err"); }
  };

  return (
    <>
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-black">API Keys</h1>
        <button onClick={() => setCreateOpen(true)}
          className="text-xs text-white px-3 py-1.5 rounded-lg bg-[#1C1C1C] hover:opacity-80 flex items-center gap-1">
          <Plus size={13} /> Create key
        </button>
      </div>
      <CardBox title="Gateway API keys" right={<span className="text-xs text-black/40">{rows.filter((k) => !k.revoked).length} active</span>}>
        {rows.length === 0 ? <Empty label="No API keys issued yet." /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>Name</Th><Th>Token</Th><Th>Acts as</Th><Th>Scope</Th><Th>Created</Th><Th>Expires</Th><Th>Last used</Th><Th right></Th></tr></thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k.kid} className={`hover:bg-black/[0.02] ${k.revoked ? "opacity-45" : ""}`}>
                  <Td><span className="flex items-center gap-1.5"><KeyRound size={13} className="text-black/30" />{k.name}</span></Td>
                  <Td><span className="text-black/50 text-xs font-mono">{k.prefix}</span></Td>
                  <Td>{k.sub}</Td>
                  <Td><span className="text-xs px-2 py-0.5 rounded-full" style={{ background: "#edeefc" }} title={SCOPE_DESC[k.scope]}>{k.scope}</span></Td>
                  <Td><span className="text-black/60">{fmtDate(k.created)}</span></Td>
                  <Td><span className="text-black/60">{k.expires ? fmtDate(k.expires) : "never"}</span></Td>
                  <Td><span className="text-black/60">{relTime(k.last_used)}</span></Td>
                  <Td right>
                    {k.revoked
                      ? <span className="text-xs" style={{ color: "#D9534F" }}>revoked</span>
                      : <button onClick={() => setRevokeKey(k)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1 ml-auto" style={{ color: "#D9534F" }}><Ban size={12} /> Revoke</button>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </CardBox>

      <CardBox title="OAuth clients (Connect-your-AI)" right={<span className="text-xs text-black/40">{clientRows.length} registered</span>}>
        {clientRows.length === 0 ? <Empty label="No OAuth clients registered." /> : (
          <div className="overflow-x-auto"><table className="w-full">
            <thead><tr><Th>Client</Th><Th>Client ID</Th><Th>Authorized by</Th><Th right>Refresh tokens</Th><Th>Registered</Th><Th>Last used</Th><Th right></Th></tr></thead>
            <tbody>
              {clientRows.map((c) => (
                <tr key={c.client_id} className="hover:bg-black/[0.02]">
                  <Td>{c.client_name || <span className="text-black/40">(unnamed)</span>}</Td>
                  <Td><span className="text-black/50 text-xs font-mono">{c.client_id}</span></Td>
                  <Td><span className="text-black/60 text-xs">{(c.subjects || []).join(", ") || "—"}</span></Td>
                  <Td right>{c.active_refresh_tokens}</Td>
                  <Td><span className="text-black/60">{fmtDate(c.created)}</span></Td>
                  {/* A dead registration that should be revoked — or one that woke up after
                      six months — is only visible if we show when it was last used (A21). */}
                  <Td><span className="text-black/60">{relTime(c.last_used)}</span></Td>
                  <Td right>
                    <button onClick={() => setRevokeClient(c)} className="text-xs px-3 py-1 rounded-lg border border-black/10 hover:bg-black/[0.04] flex items-center gap-1 ml-auto" style={{ color: "#D9534F" }}><Ban size={12} /> Revoke</button>
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
        <SecretModal title={`API key "${minted.name}" created`}
          note="Copy the token into your CI secret manager or client config now."
          rows={[{ label: "API key token", value: minted.token }]}
          onClose={() => setMinted(null)} />
      )}
      {revokeKey && (
        <ConfirmModal title="Revoke API key?"
          body={<>The key <b>{revokeKey.name}</b> ({revokeKey.prefix}) stops working immediately. Anything using it will start failing auth. This cannot be undone.</>}
          confirmLabel="Revoke key" onCancel={() => setRevokeKey(null)} onConfirm={doRevokeKey} />
      )}
      {revokeClient && (
        <ConfirmModal title="Revoke OAuth client?"
          body={<>Client <b>{revokeClient.client_name || revokeClient.client_id}</b> is deleted and all {revokeClient.active_refresh_tokens} of its refresh token(s) die. Connected AI clients must re-authorize from scratch.</>}
          confirmLabel="Revoke client" onCancel={() => setRevokeClient(null)} onConfirm={doRevokeClient} />
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
    if (!name.trim()) { toast("Give the key a name", "err"); return; }
    setBusy(true);
    try {
      const r = await apiPost("/api/admin/apikeys", {
        name: name.trim(), sub, scope,
        ttl_days: ttl === "never" ? null : Number(ttl),
      });
      onCreated(name.trim(), r.token);
    } catch (e: any) { toast(e.message || "Create failed", "err"); }
    finally { setBusy(false); }
  };
  return (
    <Modal title="Create API key" onClose={onClose}>
      <Field label="Name (what will use this key?)">
        <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. ci-pipeline" autoFocus />
      </Field>
      <Field label="Acts as operator (the key inherits their role, capped by scope)">
        <SelectInput value={sub} onChange={(e) => setSub(e.target.value)}>
          {operators.map((o) => <option key={o} value={o}>{o}</option>)}
        </SelectInput>
      </Field>
      <Field label="Scope">
        <SelectInput value={scope} onChange={(e) => setScope(e.target.value)}>
          {Object.entries(SCOPE_DESC).map(([s, d]) => <option key={s} value={s}>{s} — {d}</option>)}
        </SelectInput>
      </Field>
      <Field label="Expiry">
        <SelectInput value={ttl} onChange={(e) => setTtl(e.target.value)}>
          <option value="30">30 days</option>
          <option value="90">90 days</option>
          <option value="365">1 year</option>
          <option value="never">Never (not recommended)</option>
        </SelectInput>
      </Field>
      <div className="flex gap-2 justify-end">
        <GhostBtn onClick={onClose}>Cancel</GhostBtn>
        <PrimaryBtn onClick={create} disabled={busy}>{busy ? "Creating…" : "Create key"}</PrimaryBtn>
      </div>
    </Modal>
  );
}
