# Secure MCP Gateway — Operations Runbook

For the platform/SecOps team of a ~200-person government entity. Covers day-2 operation
of the gateway control plane. Architecture and threat model: `../MCP-Security-Blueprint.md`;
completion status: `GATEWAY-COMPLETION-PLAN.md`.

## 1. Run

```bash
pip install -r requirements.txt
# dev (no model — clients drive tools via POST /mcp; username+password+TOTP login, dev PKI auto-generated)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8800
# container
docker build -t mcp-gateway . && docker run -p 8800:8800 \
  -e MCP_GATEWAY_KEK=... -e MCP_AUDIT_KEY=... -e MCP_VAULT_KEY=... \
  -v gw-data:/app/data -v gw-pki:/app/pki mcp-gateway
```

### 1a. First-boot bootstrap (REQUIRED — a fresh volume has no operators)
Login is username + strong password + a TOTP authenticator code (`auth.require_mfa: true`).
A fresh `data/` volume has no `credentials.json`, so **no one can log in until you seed at
least one admin**. Run inside the container (or from the repo root) once per operator:

```bash
# set a password AND enroll the authenticator in one step (prints the otpauth:// URI once)
python scripts/seed_credentials.py admin --generate
# password only (MFA auto-enrolls if missing), or re-enroll MFA alone:
python scripts/seed_credentials.py noura --stdin        # reads password from stdin
python scripts/seed_credentials.py noura --mfa          # rotate authenticator only
python scripts/seed_credentials.py --list               # who has a credential + authenticator
```
Scan the printed `otpauth://` URI (or type the base32 secret) into the operator's
authenticator app; the secret is shown **once**, then stored AES-256-GCM-encrypted under
`MCP_GATEWAY_KEK` in `data/mfa_secrets.json`. Restart the gateway to load new password hashes
(authenticator secrets are picked up immediately). Admins can also enroll/rotate via
`POST /api/admin/mfa/{user}/enroll` and audit coverage via `GET /api/admin/mfa`.

Seeded passwords are **must-change on first login** by default (pass `--no-force` only for
service accounts). A user who owes a rotation gets a token flagged `password_change_required`
and is **blocked from the tool surface** (`/mcp` → 403) until they rotate via
`POST /api/auth/password {"old_password","new_password"}`. Passwords also expire after
`auth.password_max_age_days` (default 90). Status: `GET /api/auth/password/status`.

### 1b. Production transport — mTLS terminator (REQUIRED before any network exposure)
The gateway speaks plain HTTP and must run **only** behind the mTLS-terminating proxy; it must
never be directly reachable. Enable `auth.trusted_proxy.enabled: true` and give it the shared
secret (`MCP_PROXY_SHARED_SECRET_FILE`) that the proxy injects — the gateway then refuses any
`/api` or `/mcp` request that didn't traverse the proxy (direct hits → 403). The full path is
wired in `docker-compose.tls.yml` + `deploy/nginx.conf`:

```bash
./deploy/gen_tls_certs.sh                                   # dev CA + server + client certs
printf '%s' "$(openssl rand -hex 32)" > deploy/proxy_secret # proxy↔gateway shared secret
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
# reach it ONLY via HTTPS + client cert:
curl --cacert deploy/tls/ca.crt --cert deploy/tls/client.crt \
     --key deploy/tls/client.key https://localhost:8443/api/health
```
nginx terminates TLS 1.3, verifies the client cert, **strips** any client-supplied
`X-Client-Cert-Thumbprint` and re-injects the TLS-verified one, and adds the proxy secret.
Production: swap the dev CA/server cert for your internal PKI / step-ca and issue per-workstation
client certs (TPM-resident keys).

## 2. Secrets (supply at runtime, never in the image)
| Env var | Protects | Production source |
|---|---|---|
| `MCP_GATEWAY_KEK` | CA + token-signing keys at rest | HSM / secret store |
| `MCP_AUDIT_KEY` | HMAC audit chain | HSM / secret store |
| `MCP_VAULT_KEY` | dynamic credential derivation | OpenBao |
| `MCP_PROXY_SHARED_SECRET` | proves a request came via the mTLS terminator | secret store / K8s secret |
| `POSTGRES_URL` | postgres-mcp backend DSN (user/pass inside) | OpenBao dynamic DB creds |
| `GITEA_URL` / `GITEA_TOKEN` | gitea-mcp API endpoint + access token | secret store, least-privilege token |

**File-based secrets (production).** Every `MCP_*` secret above also accepts a `${NAME}_FILE`
form that reads the value from a mounted file (Docker/Kubernetes secrets), so secrets never
appear on the command line or in `docker inspect`. Resolution: `${NAME}_FILE` → `${NAME}` →
dev default. A `_FILE` path that is set but unreadable is a **hard startup error** (fail closed —
never silently fall back to a dev default). `MCP_ENV=production` turns the dev-default and
dev-flag checks into hard boot failures.

Server `env:` blocks in `config.yaml` expand `${VAR}` from the gateway's environment
at spawn time, so backend secrets never appear in the config file or in model context.
Both production servers boot without their env set (tools then return structured
connection errors), so a missing secret degrades, never crashes, the gateway.

### Production MCP servers (postgres-mcp, gitea-mcp)
- **postgres-mcp** (83 tools): read tools run in `READ ONLY` transactions; every
  statement is identifier-quoted + parameterized and runs under
  `POSTGRES_STATEMENT_TIMEOUT_MS`; `update_rows`/`delete_rows` require a WHERE;
  `drop_database`/`terminate_backend` stay disabled unless `POSTGRES_ALLOW_DANGEROUS=1`.
- **gitea-mcp** (116 tools): `delete_repo` requires `confirm=true`; all writes go to
  the Gitea audit trail under the token's identity — use a **dedicated machine account with a
  scoped (non-admin) token**. Set `GITEA_SUDO=<user>` to attribute actions to a specific Gitea
  account (requires an admin token).
- **Least privilege at the database (Tier-1 defense-in-depth):** never point postgres-mcp at a
  superuser. Run `deploy/postgres_least_privilege.sql` to create a bounded `mcp_app` role, then
  set `POSTGRES_ROLE=mcp_app` — the server assumes that role at connect and physically cannot
  exceed its grants (DDL/admin tools return "permission denied"), regardless of the login user.
  `POSTGRES_APPNAME` tags the connection in `pg_stat_activity` for DBA-side attribution.
- Risk tiers are assigned on first discovery by the registry heuristic
  (reads → 0, reversible writes → 1, merge/grant/export → 2, delete/drop/truncate → 3)
  and pinned in `data/tool_registry.json`; override any tool from the Registry view
  (**Re-tier** button) or `POST /api/admin/registry/{server}/{tool}/tier {"tier": N}`,
  and confirm at onboarding review.
- E2E verification: `tests/test_mcp_servers.py` drives both servers against real
  backends (`docker run postgres:17` on :15432, `gitea/gitea:1.24` on :13000;
  set `TEST_GITEA_TOKEN`). Tests skip when backends are absent.

## 3. Config (`config.yaml`) — validated on startup, fails fast
- No `llm.*` block: the gateway runs no model. Each colleague's own LLM connects to the
  inbound MCP endpoint (`POST /mcp`, Streamable HTTP) and drives tool calls through the pipeline.
- `auth.mode`: `builtin` (username + password + TOTP MFA) → `oidc` (validate Keycloak JWTs via `auth.oidc.jwks_url`).
- `auth.require_mfa`: **true** (default) enforces the TOTP authenticator as a second factor; every operator must be enrolled (§1a) or they cannot log in. Do not set false in production.
- `registry.require_approval`: set **true** in production (Risk-Board gates new tools).
- `audit.siem_export`: mirror events to the SIEM feed (`data/siem_stream.jsonl` → Wazuh/OpenSearch).
- Rate limits (`rate_limit_*`), lockout, breaker, `allowed_origins`: tune per environment.
- **Pre-deploy tripwires — never ship with:** `auth.dev_login_enabled: true`, `auth.require_mfa: false`, `registry.require_approval: false`, or the `dev-*-change-me` values for `MCP_GATEWAY_KEK`/`MCP_AUDIT_KEY`/`MCP_VAULT_KEY` (the KEK also protects the at-rest CA keys and TOTP secrets).

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
Client LLM hosts + a brokered confidential-compute GPU (inference is client-side, off the gateway);
HSM + workstation TPM; Keycloak host (`auth.mode: oidc`); TLS 1.3 + mTLS terminator
+ SPIFFE; SIEM product; DR site + offline backups; air-gap network + admission control; Arabic NER
model. The gateway software is complete and seams are ready for each.
