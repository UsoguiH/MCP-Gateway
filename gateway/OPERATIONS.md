# Secure MCP Gateway — Operations Runbook

For the platform/SecOps team of a ~200-person government entity. Covers day-2 operation
of the gateway control plane. Architecture and threat model: `../MCP-Security-Blueprint.md`;
completion status: `GATEWAY-COMPLETION-PLAN.md`.

## 1. Run

```bash
pip install -r requirements.txt
# dev (mock LLM, builtin TPM+PIN auth, dev PKI auto-generated)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8800
# container
docker build -t mcp-gateway . && docker run -p 8800:8800 \
  -e MCP_GATEWAY_KEK=... -e MCP_AUDIT_KEY=... -e MCP_VAULT_KEY=... \
  -v gw-data:/app/data -v gw-pki:/app/pki mcp-gateway
```

## 2. Secrets (supply at runtime, never in the image)
| Env var | Protects | Production source |
|---|---|---|
| `MCP_GATEWAY_KEK` | CA + token-signing keys at rest | HSM / secret store |
| `MCP_AUDIT_KEY` | HMAC audit chain | HSM / secret store |
| `MCP_VAULT_KEY` | dynamic credential derivation | OpenBao |

## 3. Config (`config.yaml`) — validated on startup, fails fast
- `llm.provider`: `mock` → `openai_compat` (point `base_url` at vLLM) when GPUs land.
- `auth.mode`: `builtin` (TPM+PIN, dev) → `oidc` (validate Keycloak JWTs via `auth.oidc.jwks_url`).
- `registry.require_approval`: set **true** in production (Risk-Board gates new tools).
- `audit.siem_export`: mirror events to the SIEM feed (`data/siem_stream.jsonl` → Wazuh/OpenSearch).
- Rate limits (`rate_limit_*`), lockout, breaker, `allowed_origins`: tune per environment.

## 4. Routine operations
| Task | How |
|---|---|
| **Watch health** | `GET /api/health` (status, servers, tools, pending tools, audit chain ok) |
| **Metrics / dashboards** | `GET /api/metrics` (event counts, breaker, active leases, pending onboarding) — admin |
| **Verify audit integrity** | `GET /api/admin/audit` → `chain_ok` must be true |
| **Onboard a new tool** | it lands `pending` → review → `POST /api/admin/registry/{server}/{tool}/approve` |
| **Tool definition drift** | auto-quarantines → review → `.../approve_drift` to re-pin |
| **Kill switch** | `POST /api/admin/killswitch/engage {"scope":"global｜server:X｜tool:X:Y｜user:Z"}` |
| **Revoke an identity** | `POST /api/admin/revoke {"sub":"..."}` (blocks in-flight tokens <1s; survives restart) |
| **Clear a lockout** | `POST /api/admin/unlock {"sub":"..."}` after out-of-band verification |
| **Active credential leases** | `GET /api/admin/vault` |

## 5. Backup & rotation
- **Back up:** `data/` (audit log, registry, approvals, revocations) and `pki/` (or the HSM/CA).
- **Rotate token-signing key:** publish new public key, overlap window ≥ token TTL, then cut over
  (prod: OpenBao Transit rotate). **Rotate audit HMAC key:** start a new chain segment, archive the old.
- **Retention:** audit ≥ 2 years, in-Kingdom, immutable (NDMO). Ship WORM copies off the gateway host.

## 6. Incident response (first move = contain at the gateway)
1. **Compromised agent/identity:** `POST /api/admin/revoke`; `killswitch user:<sub>`.
2. **Compromised/misbehaving server:** `killswitch server:<name>` (the circuit breaker also auto-opens
   after repeated failures); pull its registry entry.
3. **Injection suspected:** taint + HITL already gate writes; review `credential_injected` and
   `approval_*` events; rotate any exposed backend credentials (leases are short-lived).
4. Reconstruct via correlation ids in the SIEM stream. Run ≥1 tabletop/year (injection → HR/finance
   read → exfil attempt via the actions server).

## 7. Production readiness — operator-provided (see `GATEWAY-COMPLETION-PLAN.md` §B)
Real vLLM+GPU; HSM + workstation TPM; Keycloak host (`auth.mode: oidc`); TLS 1.3 + mTLS terminator
+ SPIFFE; SIEM product; DR site + offline backups; air-gap network + admission control; Arabic NER
model. The gateway software is complete and seams are ready for each.
