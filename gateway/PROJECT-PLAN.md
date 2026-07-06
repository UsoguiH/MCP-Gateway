# MCP Gateway — Project Plan (the road to production)

_As of 2026-07-06. This is the real plan; earlier design/research documents are background._

## The destination

A security control plane that lets **300+ staff use their own local AI** against internal
systems, safely. Every tool call the AI proposes is authenticated, authorized against role
and clearance, inspected for prompt-injection and sensitive data, gated for human approval
when it is destructive, and written to a tamper-evident log — **entirely on our own
infrastructure, so no prompt or datum ever leaves the building.**

**Deployment context (decided):** 300+ users; employees connect **their own local AI** to the
gateway (pure Policy-Enforcement-Point — the gateway runs no model); on-prem with controlled
internet; data sources = **PostgreSQL databases + Git repositories + internal documents/file
shares**; operated by a **small IT team (2–4)**; built with Claude Code.

## Where we are: two numbers

- **Work to production ≈ 45%.** The control-plane software (the security engine) is ~90%
  complete and covered by 90+ automated tests, but a production system for a 300-person org is
  more than software — it is connectors + infrastructure + operations, and those are early.
  (The _code_ is 90%; the _system_ is ~45%.)
- **Plan maturity ≈ 90%** after this revision. The first draft had the destination, status and
  roadmap but lacked a risk register, the external decisions we depend on, and measurable
  targets — all added below. The last ~10% is the seven **Decisions we need from you**, which
  only your org can answer; until then parts of Phases 0–3 can't start.

| Layer | Status | Notes |
|---|---:|---|
| Control-plane software (the security engine) | **90%** | MFA, ABAC, taint/injection, DLP, HITL tiers, kill switch, hash-pinned registry, HMAC audit, anomaly engine, admin console |
| Data connectors (the MCP servers) | **55%** | postgres-mcp ✓, gitea-mcp ✓, internal-docs/file-share server = **not built** (test fixture only) |
| Production infrastructure (TLS/mTLS, secrets, DB, HA) | **20%** | configs/seams exist; almost nothing deployed for real |
| Operations & governance (backups, SIEM, runbooks, sign-off) | **25%** | partial runbooks; no live backups/DR/SIEM; no accreditation |

## The four pillars — honest assessment

- **Security — Partial.** Architecture is excellent (full defense pipeline built); current
  running posture is dev-grade (plain HTTP, placeholder secrets, superuser DB). Closing the
  gap is deployment work, not new design.
- **Privacy — Strong.** The AI runs on the employee's own machine and connects in, so prompts
  and data never reach a cloud model. Results are DLP-masked, access is clearance-gated, the
  audit log stores digests not raw content. Gap: an Arabic-language PII detector.
- **Works with local AI — Strong.** This is the core design: each employee's local AI connects
  to the inbound `/mcp` endpoint and drives tools through the pipeline. Remaining work is
  client onboarding (a short guide + config).
- **Performance — Not yet proven.** Single instance, in-memory sessions, flat-file state.
  Fine for a demo, unproven at 300+ concurrent. Needs state in a DB, multiple instances behind
  a load balancer, and a real load test.

## What we haven't built yet

**Critical (blocks a real deployment)**
1. Internal docs / file-share connector — the third data source; current one is a test fixture.
2. Real, persistent database — the AI-facing Postgres is a throwaway container as superuser.
3. TLS everywhere + mTLS terminator deployed in front (config exists, not deployed).
4. Real secret custody — signing/audit/MFA keys still use dev defaults (seam is ready).

**Scale & SecOps (before org-wide rollout)**
5. Move gateway state (audit, credentials, approvals) out of JSON files into the database.
6. High availability (2+ instances + load balancer) and a load test to 300+ concurrent.
7. SIEM integration + alert delivery (export hook + anomaly engine exist; nothing receives them).
8. Backups & disaster recovery (automated backup + restore drills + DR plan).

**Rollout & governance**
9. Client onboarding for staff (guide + config template).
10. Independent penetration test + formal risk acceptance / compliance sign-off.

## Risks we're carrying

1. **The gateway trusts the person, not their AI model (residual, critical).** We authenticate
   the employee, but their local model runs with that person's full clearance. A jailbroken or
   backdoored model acts as them. Injection/taint defenses stop malicious _content_ and approval
   tiers stop _destructive_ actions, but a compromised model doing _permitted_ reads within the
   user's clearance is bounded only by ABAC, not prevented. **Mitigate:** tight least-privilege
   clearances, stricter approval tiers on sensitive servers, per-session rate limits, anomaly
   detection, and (future) an approved-model list / client attestation. This is the defining
   residual risk of "bring your own AI" and must be **formally accepted**.
2. **A docs/file-share connector can over-expose (Phase 1).** Pointed at a share it can surface
   more than intended. **Mitigate:** read-only default, path allow-lists, clearance-gating, DLP
   on results, per-share least-privilege account. Build narrow, widen deliberately.
3. **Flat-file state races under concurrency (until Phase 2).** Concurrent writes to the
   audit/approvals JSON files can race/corrupt — caps safe pilot size. **Mitigate:** keep the
   early pilot small; DB migration is the fix.
4. **Nobody owns data classification (dependency).** DLP masks known PII, but who decides which
   tables/documents are Secret vs Restricted? **Mitigate:** assign a data steward; start
   conservative (deny-up).
5. **Arabic free-text PII blind spot (privacy).** DLP catches structured IDs/IBANs, not names or
   addresses in Arabic prose. **Mitigate:** add an Arabic NER detector; mask conservatively meanwhile.
6. **Small team + controlled-internet patching (operations).** 2–4 people carry key-person risk;
   patches need a deliberate path. **Mitigate:** monthly patch window, CI dependency/vuln scanning,
   runbooks so no one is irreplaceable.

## Decisions we need from you

I can build all of it, but not decide these — they depend on your environment and policy. Each
blocks the phase in brackets; answering them is the last ~10% of plan maturity.

- **[P0]** Which CA / PKI issues our certificates (server + per-workstation client certs), or do
  we start with a self-signed internal CA?
- **[P0–1]** Which PostgreSQL is the real system-of-record, and can we get a dedicated
  least-privilege service account (not superuser)?
- **[P1]** Where do the internal documents live — Windows/SMB shares, SharePoint, NFS, or a DMS?
- **[P1]** Who owns data classification (which tables/documents are which sensitivity)?
- **[P2]** What hardware for HA — 2+ Linux nodes + load balancer, and later a DR site?
- **[P3]** Which SIEM receives the audit stream — Wazuh, OpenSearch, Splunk, Sentinel?
- **[P5]** Is an HSM required for key custody, or is a software secret store acceptable at launch?

## Roadmap — six phases (dependency order)

Sequenced by what unblocks what. Effort tags (S/M/L) are _build_ size; the IT team operates
and decides, Claude Code does the hand-coding. **You don't have to build everything before real
feedback:** a closed pilot with a handful of users can run right after Phase 1, before full HA.

- **Phase 0 — Make it real, not a demo (✅ DONE 2026-07-06, M).** Persistent DB + least-privilege
  role; replace all dev secrets and flip production config flags; deploy mTLS terminator + real TLS;
  push to self-hosted Gitea; enable backups.
  → _Done when: zero dev secrets in the running config, all traffic over TLS, boots clean under
  `MCP_ENV=production`, and the database survives a restart._
  → **Verified 2026-07-06:** boots clean under `MCP_ENV=production` (tripwires are hard errors —
  zero dev secrets); mTLS terminator live on :8443 (valid client cert → 200, no cert → rejected,
  :8080 → 308 redirect, proxy bypass → 403); Postgres restart preserved data, gateway reconnects
  as `mcp_login`→`mcp_app` (non-superuser); repo pushed to self-hosted Gitea; daily backups
  scheduled 02:00 (`scripts/backup.ps1`: pg_dump + gw-data/gw-pki volumes + Gitea DB/repos,
  14-day retention, restore-tested). Remaining caveat: backups are same-disk (D:) — move offsite
  in Phase 2+; TLS material is the dev CA — swap for org PKI per the [P0] decision when answered.
- **Phase 1 — Complete the connectors (✅ DONE 2026-07-06, M).** Build the internal-docs/file-share
  server; connect the DB and Git servers to real systems with least-privilege creds, each onboarded
  via the registry gate. → _Outcome: the AI can safely reach all three data sources._
  → **Verified 2026-07-06:** `servers/files_server.py` (files-mcp) built — read-only, path
  allow-lists with per-root NDMO classification, traversal/hidden-entry refusal, size+time
  budgets, txt/md/docx (stdlib) + optional pdf/xlsx extraction; 21 dedicated tests incl.
  traversal attacks; full suite 121 passed. Prod stack: `D:\Shares` mounted read-only (write
  refused from container), 3 roots (public/restricted/secret); gitea-mcp now points at the real
  self-hosted Gitea via Docker-secret token (full lifecycle test green against it); postgres-mcp
  on appdb as `mcp_login→mcp_app` since Phase 0. All 6 files tools discovered tier-0 and held
  **pending Risk-Board approval** in the registry (approve in the admin console to activate).
  Caveats: Gitea token is currently an all-scope admin token — replace with a dedicated
  machine account + scoped token; the org's system-of-record Postgres still awaits [P0–1].
- **Phase 2 — Scale & resilience (L).** Move gateway state into the DB; run 2+ instances behind
  a load balancer; load-test to 300+ and tune limits/timeouts/breaker.
  → _Done when: 300 concurrent sessions sustained within your latency budget, and killing one
  gateway node drops zero sessions._
- **Phase 3 — See & respond, SecOps (M).** Wire audit → SIEM; turn anomaly alerts into
  email/webhook notifications; audit retention + immutable store; incident runbooks +
  kill-switch drill. → _Done when: an induced brute-force shows up as a SIEM alert within
  minutes, and a kill-switch drill completes clean._
- **Phase 4 — Pilot, then roll out (S).** Onboard 10–20 staff with their local AI; measure
  latency, approval friction, false positives; expand department by department.
  → _Outcome: real users, tuned thresholds, repeatable onboarding._
- **Phase 5 — Harden & certify (M).** Independent pen test; DR site; HSM for keys if required;
  formal risk acceptance + compliance mapping. → _Outcome: production sign-off._

## Do now (Phase 0 ✅ + Phase 1 ✅ + client access layer ✅ — next: Phase 2 scale)

1. **Employee-zero smoke test** — on a real client machine, add the gateway to an
   OAuth-capable MCP client (e.g. `claude mcp add --transport http company-gateway
   https://gateway.internal:8443/mcp`), sign in with a live authenticator, and run a
   `files__search_content` call end-to-end (login → OAuth → `/mcp` → DLP mask → approval).
2. **Approve the files-mcp tools in the admin console** (they sit `pending` per governance).
3. **Swap the Gitea token for a dedicated machine account + scoped token** (least privilege).
4. **Begin Phase 2** — move gateway state (audit/approvals/sessions) into the DB, then HA.
3. **Client access layer (✅ DONE 2026-07-06).** Pulled forward from Phase 4 so the pilot
   has easy onboarding.
   - **MCP OAuth 2.1 authorization endpoints** — `app/oauth.py` + `/.well-known/*`,
     `/oauth/register` (DCR), `/oauth/authorize` (login+consent page = the existing
     password+MFA login), `/oauth/token` (code+PKCE S256 exchange, rotated refresh).
     `/mcp` now accepts EITHER a cert-bound console session token OR an OAuth bearer, and
     a 401 advertises `WWW-Authenticate: resource_metadata=...` so compliant clients
     (Claude Code, etc.) self-onboard. OAuth access tokens are bearer (not cert-bound):
     protected by PKCE + short TTL + rotated refresh + revocation over the mTLS channel.
   - **"Connect your AI" page** — `ui/connect.html` at `/connect`: sign in, choose
     Automatic (OAuth) or Manual token, copy the generated MCP config, live "connected"
     indicator (`/api/connect/status`, `/api/connect/token`).
   - **Verified 2026-07-06:** 14 new tests (`tests/test_oauth.py`), full suite **135 passed**;
     through the live mTLS proxy — metadata advertises the correct external URL
     (nginx now forwards Host), 401 discovery hint present, and an OAuth bearer token
     drives a real `tools/list` with no cert header. Employee-zero smoke test remains as
     the last step (needs a real enrolled authenticator on a client machine).
