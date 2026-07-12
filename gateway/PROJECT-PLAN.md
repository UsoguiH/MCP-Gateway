# MCP Gateway — Project Plan

_As of 2026-07-12. Supersedes the 2026-07-06 revision (kept in git history). This is the
canonical plan; the root-level design/research documents are background inputs, reconciled
here in §2 and §11._

---

## 0. How to read this plan

- **§1–§4** — what we are building and where we honestly stand today.
- **§5–§7b** — current-state assessment: built / partial / missing / debt, including the
  ranked admin-console gap register (§7b).
- **§8–§9** — risks we carry and decisions only the organization can make.
- **§10** — the roadmap: five remaining phases with tasks, deliverables, and exit criteria.
- **§11** — the extension track: capabilities from the larger architecture documents that are
  **formally descoped**, each with the trigger that would re-activate it.
- **§12** — milestones and measurable targets (SLOs and operating cadences).
- **§13** — do-now list (next two weeks).

---

## 1. The destination

A security control plane that lets **300+ staff use their own local AI** against internal
systems, safely. Every tool call the AI proposes is authenticated, authorized against role
and clearance, inspected for prompt injection and sensitive data, gated for human approval
when destructive, and written to a tamper-evident log — **entirely on our own
infrastructure, so no prompt or datum ever leaves the building.** (One scoped exception:
the opendata connector queries the public Saudi Open Data portal — public-data search terms
only, never internal data.)

**Deployment context (decided):** 300+ users; employees connect **their own local AI** to the
gateway (a pure Policy-Enforcement-Point — the gateway runs no model); on-prem with controlled
internet; data sources = **PostgreSQL + Git repositories + internal documents/file shares**
(+ the public Saudi Open Data portal); operated by a **small IT team (2–4)**; built with
Claude Code.

## 2. The architecture fork — decided

The research corpus contains **two divergent end-states** and the previous plan never said
which one we are building:

- **Vision A — air-gapped platform** (v10 BuildSpec, Platform-Build-Plan): self-hosted
  vLLM/GPU inference, server-side sandboxed agents, thin clients, media-ingress station,
  ~14-month / ~9–11 FTE program.
- **Vision B — BYO-AI control plane** (what is actually built): employees bring their own
  local model; the gateway is a pure PEP; controlled internet, not air-gapped; 2–4 operators.

**Decision: this project builds Vision B.** Vision A is not cancelled — its still-relevant
controls are inventoried in the extension track (§11), each with an explicit trigger. The
defining consequence of Vision B is **Risk R1** (§8): we authenticate the *person*, not their
*model*. That trade-off must be **formally risk-accepted in writing** during Phase 6 — it is
the single most important sentence an accreditor will read in this document.

## 3. Where we are: two numbers

- **Work to production ≈ 55%** (was 45% on 2026-07-06). Since then: the client access layer
  (MCP OAuth 2.1 + Connect-your-AI page), the admin control surface (API keys, OAuth clients,
  operator lifecycle, server lifecycle, notifications — live-QA-verified 2026-07-09), and the
  reports connector all shipped. The remaining 45% is dominated by infrastructure (database-
  backed state, HA) and operations (SIEM, DR, accreditation) — not by control-plane features.
- **Plan maturity ≈ 95%** after this revision: the architecture fork is now decided (§2), the
  descope register exists (§11), hygiene/test debt is scheduled (Phase 2), and every phase has
  measurable exit criteria. The last 5% is the open decisions in §9, which only the
  organization can answer.

| Layer | 07-06 | Now | What moved |
|---|---:|---:|---|
| Control-plane software (the security engine) | 90% | **95%** | + OAuth 2.1 AS, admin control surface, notifications, and the Phase-2 console/insights/settings layer. Remaining: DB-backed state (Phase 3) |
| Data connectors (MCP servers) | 55% | **80%** | postgres ✓ gitea ✓ files ✓ reports ✓ opendata ✓. Remaining: scoped Gitea machine token, org system-of-record DB [D2], activate pending files tools |
| Production infrastructure (TLS/mTLS, secrets, DB, HA) | 20% | **35%** | Prod compose stack live (postgres:17 + nginx mTLS + Docker secrets). Remaining: HA, DB state, org PKI, offsite backups, secret manager |
| Operations & governance (backups, SIEM, runbooks, sign-off) | 25% | **38%** | Admin console (complete), live QA, backup schedule + backup/cert/disk visibility. Remaining: SIEM, alert delivery, DR drills, IR playbooks, accreditation |

## 4. What exists today (verified inventory, 2026-07-12)

**Control plane** — `app/`, 22 Python modules, ~5,700 LOC, ~80 HTTP routes. Every inbound
`/mcp` tool call passes an **18-stage enforcement pipeline**: edge guard (proxy secret, size
cap, Origin allow-list) → bearer auth (cert-bound session | OAuth | API key) → MCP session
ownership → kill switch → 3-key rate limits → server entitlement → registry lookup → circuit
breaker → drain check → API-key tier cap → Unicode sanitize → size limits → strict schema
validation → taint check → ABAC decision → HITL approval (tier 2 = 1 signer, tier 3 = 2 + SoD)
→ vault credential injection at dispatch → result governance (truncate, sanitize, taint,
clearance-gated DLP mask) — with a hash-chained audit record at every step.

**Identity & access** — password (PBKDF2 600k) + TOTP MFA primary; cert+PIN (TPM model)
retained as upgrade path; ES256 tokens, ≤600 s TTL; OAuth 2.1 authorization server (DCR,
PKCE S256, rotated refresh) for MCP clients; scoped API keys; OIDC/Keycloak mode staged but
off; operator lifecycle (create/offboard/role/MFA/reset/sign-out-everywhere) in the console.

**Connectors** — 7 MCP servers, 222 tools:

| Server | Tools | Access | Real system | Status |
|---|---:|---|---|---|
| postgres-mcp | 83 | R/W | appdb as `mcp_login→mcp_app` (least-priv) | live; org DB awaits [D2] |
| gitea-mcp | 116 | R/W | self-hosted Gitea | live; token is admin-scoped — needs machine account |
| files-mcp | 6 | RO | `D:\Shares` (3 classified roots, ro-mount) | built + tested; tools pending Risk-Board approval |
| reports-mcp | 2 | RO→HTML | demo.sales | demo connector |
| opendata-mcp | 9 | RO | Saudi Open Data portal (public) | live; 2 tools quarantined on drift — needs review |
| docs / actions | 2 / 4 | fixtures | in-code | pilot fixtures — retire before rollout |

**Console** — React 18/Vite/Tailwind 4 SPA (**19 pages**) served by the gateway. Every
governance surface is wired to a real API (approvals, registry, identities, kill switch,
audit, anomaly, sessions, API keys/OAuth clients, servers, notifications) and, since Phase 2,
**every number shown is measured and every control does something**: real traffic/latency
charts from recorded per-call durations, live rate-limit consumption, persisted settings, a
Gateway self-page (version, uptime, backups, certificate expiry, disk growth, maintenance
mode) and a DLP activity page.

**Deployment** — `docker-compose.prod.yml`: postgres:17 (pgdata volume) + gateway
(`MCP_ENV=production`, tripwires make dev secrets fatal) + nginx mTLS terminator (:8443 only
entry; :8080 redirects). Secrets are Docker file-secrets under `deploy/secrets/`. Dev CA
(`deploy/gen_tls_certs.sh`) issues server/client certs. Daily 02:00 backups
(`scripts/backup.ps1`: pg_dump + gw-data + gw-pki + Gitea; 14-day retention;
**same-disk — offsite pending**).

**Verification** — **193 test functions across 13 files**, all green (security units, auth,
hardening, fuzz, OAuth, admin controls, approvals lifecycle, files server, the console
back-end + settings overlay, the server-import guard, the artifact purge, live e2e, and the
38/35-step postgres/gitea lifecycle against `mcp-test-pg`/`mcp-test-gitea` docker fixtures).

## 5. The four pillars — honest assessment

- **Security — Strong architecture, dev-grade edges.** The full defense pipeline is built and
  tested; the prod stack runs with real secrets and mTLS. Edges still dev-grade: dev CA (not
  org PKI), file-based secrets on the same disk, admin-scoped Gitea token, jsonschema
  validation fails open if the library is absent (`gateway.py:433`).
- **Privacy — Strong.** AI runs on the employee's machine and connects in; results are
  DLP-masked by clearance; audit stores digests. Gap: DLP catches structured Saudi PII
  (National ID/Iqama/IBAN) but **not Arabic free-text names/addresses** — Arabic NER is now a
  scheduled deliverable (Phase 4), not just a risk note.
- **Works with local AI — Strong, one step from proven.** OAuth 2.1 self-onboarding + the
  `/connect` wizard exist and are tested through the live mTLS proxy. The **employee-zero
  smoke test on a real client machine is still outstanding** — it is do-now item #1.
- **Performance — Now measurable, still unproven at scale.** Phase 2 added per-call duration
  to the audit chain, so latency is observable for the first time (early figures on the docs
  connector: p50 7 ms, p95 14 ms of gateway-mediated overhead). It also removed a real
  bottleneck: `/api/health` was re-verifying the entire audit chain on every request (3.6 s of
  CPU at 6.5k records, growing linearly). Still single-instance with in-memory
  sessions/rate-windows/breaker state and flat-file persistence; no 300-concurrent run has
  been recorded. Fixed by Phase 3.

## 6. What we haven't built yet

**Critical (blocks a real deployment)**
1. Gateway state in a real database — audit, approvals, registry, credentials, OAuth,
   operators, notifications are all JSON files with in-process locks; concurrent writes can
   race and nothing is shareable across instances (also blocks HA).
2. Org PKI + real secret custody — dev CA and file secrets everywhere; [D1]/[D7] decide the
   target; the code seams (`*_FILE`, OpenBao provider in `vault.py`) are ready.
3. Org system-of-record PostgreSQL with a least-privilege service account [D2] — current
   appdb is our own container.
4. Employee-zero end-to-end proof on a real workstation (login → OAuth → `/mcp` → DLP →
   approval).

**Scale & SecOps (before org-wide rollout)**
5. High availability — 2+ instances behind a load balancer; shared session/rate/breaker
   state; load test to 300+ concurrent.
6. SIEM integration + alert **delivery** (export stream exists; nothing receives it; the
   notification center is in-dashboard only).
7. Immutable/WORM audit retention (≥2 years, in-Kingdom per NDMO) + offsite backups + a
   restore/DR drill that is actually executed.
8. Arabic NER DLP detector (the free-text PII blind spot).

**Rollout & governance**
9. Staff-facing connect guide (net-new document; the `/connect` wizard and
   `/api/connect/token` config generator are the assets to wrap).
10. IR playbooks + drill cadence; canary-approval program (anti-rubber-stamp).
11. Independent penetration test; compliance traceability matrix (ECC-2/CSCC-1/DCC/NCS,
    PDPL, NDMO, SDAIA, DGA); formal residual-risk acceptance — especially R1.

## 7. Technical debt & hygiene register

Found in the 2026-07-12 full-repo sweep. None of these blocks a demo; several would embarrass
a production review. All are scheduled in Phase 2.

| # | Item | Where |
|---|---|---|
| H1 | Stray artifacts: 3.7 MB `OpenData_Frontend` webpack bundle (`gateway/main.js`), 70 MB `mcp-gateway-image.tar`, repo-root clutter (`Google Gemini.html` + `_files/`, `mcp-gateway-dashboard-v2.zip`, `mcp-project.bundle`) | `gateway/`, repo root |
| H2 | `.env` on disk holds a live-looking OpenRouter API key + Postgres app password | `gateway/.env` (untracked) |
| H3 | Test-data pollution: 2 `pytest-echo.*` tools pending in registry, 7 `pytest-mcp` OAuth clients, unit-test noise in notifications | `data/*.json` |
| H4 | Dashboard presents fabricated numbers as real: canned +11.01% deltas, hardcoded Mon–Sun latency chart, synthetic trend series, rate-limit usage always 0 | `App.tsx:416,482`, `data.ts:90` |
| H5 | Alerts + Settings toggles are UI-only (no persistence) — behaviorally inert controls look functional | `App.tsx:882`, SettingsPage |
| H6 | README test counts stale ("85 green"; reality 148 test functions); doc counts drift across files | `README.md:82-85,121` |
| H7 | Zero test coverage: `anomaly.py`, `vault.py` (unit), `apikeys.py`, `notifications.py`, `mcp_manager.py` (unit), `reports_server.py`, entire dashboard | `tests/` |
| H8 | Dead code retained: `ui.backup-vanilla/` (tracked, referenced nowhere), `Login-page.txt` (design source), `qwen_chat.py` ("do NOT ship") | `gateway/` |
| H9 | Pilot fixtures (`docs`, `actions`) still registered in config + their state files | `config.yaml`, `data/` |
| H10 | Registry re-tier uses `window.prompt()`; server edit = remove + re-add; Version/Latency columns never populated (all → Phase 2 tasks 3–4) | `AdminPages.tsx:480`, ServersPage |
| H11 | Console session dies at ~10–15 min with no warning and no configurable TTL/idle setting | `auth.py` |
| H12 | Built `ui/` bundle is committed — can silently drift from `dashboard/src` (no CI rebuild check) | `gateway/ui/` |
| H13 | Gitea machine token is an all-scope admin token | `deploy/secrets/gitea_token` |
| H14 | `_validate_args` fails open if jsonschema missing/malformed (documented, but should be a startup tripwire in production) | `gateway.py:433-440` |
| H15 | Backups land on the same physical disk (D:) as the data they protect | `scripts/backup.ps1` |
| H16 | TOTP enrollment QR images on disk (MFA seed material): `admin-mfa-qr.png`, `admin-aegis-qr.png` (repo root), `sara-totp-qr.png` (`data/`) | repo root, `gateway/data/` |

## 7b. Admin console gap register (2026-07-12 admin walkthrough)

Everything an admin should see in the console but can't, ranked by criticality. Produced by
sitting in the `ciadmin` chair against the live-QA findings and the full code sweep. Every
row is scheduled; the register is the checklist Phase 2 task 4 works down.

**🔴 Critical — blind or being lied to on security-relevant things**

| # | Gap | Fixed in |
|---|---|---|
| A1 | Alerts never leave the console — no email/webhook; detection dead-ends in a bell icon | Phase 4 task 2 (needs [D6]/[D10]) |
| A2 | Audit page can't investigate: no export, no real filters, no pagination — incident forensics = SSH + grep | Phase 2 task 4 |
| A3 | Controls that pretend to work: Alerts rule toggles + Settings switches persist nothing (`App.tsx:882`) | Phase 2 task 3 |
| A4 | Fabricated numbers shown as real: canned +11.01% deltas, hardcoded latency chart, transport pie | Phase 2 task 3 |
| A5 | Per-call duration never recorded — Tools/Logs/Servers latency all "—"; blind on degradation and slow-drip exfiltration | Phase 2 task 3 |
| A6 | Zero tuning from the UI — rate limits, tiers, DLP/anomaly thresholds need SSH + file edit + restart | Phase 2 task 4 |
| A7 | Kill switch has no guardrails: no confirm, no reason, no auto-expiry on the most powerful button | Phase 2 task 4 |
| A8 | Tool approval is blind: no schema view before approve; no reject/ban; no manual quarantine | Phase 2 task 4 |

**🟠 High — operational blindness**

| # | Gap | Fixed in |
|---|---|---|
| A9 | Rate-limit consumption invisible (bars hardcoded 0) — can't see who's near a limit or being throttled | Phase 2 task 3 |
| A10 | No backup status — a silently failing backup is discovered the day it's needed | Phase 2 task 4 (self-page) |
| A11 | No gateway self-page: version, uptime, effective config, maintenance mode | Phase 2 task 4 |
| A12 | Session dies at ~10–15 min, no warning, no TTL/idle setting | Phase 2 task 5 |
| A13 | Nothing tracks certificate expiry (CA, server, client, mTLS material) — a guaranteed future outage | Phase 2 task 4 (self-page) |

**🟡 Medium — governance & hygiene**

| # | Gap | Fixed in |
|---|---|---|
| A14 | Vault leases have an API (`/api/admin/vault/leases`) but no page | Phase 2 task 4 |
| A15 | No per-server rate override; no per-role entitlement editing | Phase 2 task 4 |
| A16 | Server edit-in-place missing; Version/uptime columns always "—" | Phase 2 tasks 3–4 |
| A17 | No DLP activity rollup (masks by user/tool/detector) — events exist in audit, no view | Phase 2 task 4 |
| A18 | No approval-aging/SLA view (time-to-approve, requests nearing TTL) | Phase 2 task 4 |
| A19 | No real traffic time-series (backend keeps lifetime counters only) — derive by bucketing audit timestamps | Phase 2 task 3 |
| A20 | No live lockout list with one-click unlock (lockouts surface only as anomaly alerts) | Phase 2 task 4 |
| A21 | No last-used timestamps on API keys / OAuth clients — dead or newly-awakened credentials invisible | Phase 2 task 4 |
| A22 | Notification read-state is global, not per-operator | Phase 2 task 4 |
| A23 | No disk/capacity/log-growth view (audit chain already ~2 MB and growing) | Phase 2 task 4 (self-page) |
| A24 | Drift quarantine shows *that* a tool changed, not *what* changed — no before/after schema diff | Phase 2 task 4 |
| A25 | No SIEM export health — nothing shows whether anything consumes `siem_stream.jsonl` | Phase 4 task 1 |

## 8. Risk register

R1–R6 carried forward (renumbered); R7–R10 new this revision.

1. **R1 — The gateway trusts the person, not their AI model (residual, critical, accepted-pending).**
   A jailbroken or backdoored local model acts with its owner's full clearance. Injection/taint
   defenses stop malicious *content*; approval tiers stop *destructive* actions; a compromised
   model doing *permitted reads* is bounded only by ABAC, rate limits, and anomaly detection.
   **Mitigate:** least-privilege clearances, stricter tiers on sensitive servers, per-session
   rate limits, anomaly detection; (extension track) client attestation / approved-model list.
   **Must be formally accepted in writing at Phase 6.** This is the defining risk of Vision B.
2. **R2 — A docs/file-share connector can over-expose.** Mitigated by design (read-only, path
   allow-lists, per-root classification, DLP on results) — but widening the share list is a
   governance act, not a config edit. Keep the Risk-Board gate on every new root.
3. **R3 — Flat-file state races under concurrency (until Phase 3).** Concurrent writes to
   audit/approvals/registry JSON can corrupt; caps safe pilot size to a handful of users.
   **Mitigate:** keep pilot small; the Phase 3 DB migration is the fix.
4. **R4 — Nobody owns data classification [D4].** DLP masks known PII, but which tables/
   documents are Secret vs Restricted is an org decision. **Mitigate:** appoint a data
   steward; default deny-up until then.
5. **R5 — Arabic free-text PII blind spot.** Structured detectors only. **Mitigate:** Arabic
   NER detector scheduled (Phase 4); conservative masking meanwhile.
6. **R6 — Small team + controlled-internet patching.** 2–4 people is key-person risk; patches
   need a deliberate path. **Mitigate:** monthly patch window, `check_deps.py` allowlist gate
   in CI, runbooks so no one is irreplaceable.
7. **R7 — OAuth access tokens are bearer, not cert-bound.** Deliberate (local AI clients
   cannot do mTLS); protected by PKCE, ≤600 s TTL, rotated refresh, revocation. **Mitigate:**
   monitor for token replay via anomaly engine; re-evaluate sender-constrained tokens
   (RFC 8705) if the client ecosystem gains mTLS support.
8. **R8 — Secret sprawl on one machine.** Docker file-secrets, dev CA keys, `.env`, and
   backups all live on the same Windows host/disk. **Mitigate:** Phase 2 hygiene (H2, H15),
   Phase 6 custody decision [D7].
9. **R9 — Windows-host dependencies.** `D:\Shares` mount, `host.docker.internal` Gitea,
   Task-Scheduler backups. Fine for the pilot; the Phase 3 HA target is Linux nodes — plan the
   migration, don't discover it.
10. **R10 — Dashboard fabrications erode operator trust (H4/H5).** An operator who catches one
    fake number stops believing the real ones. Fixed by the Phase 2 truth pass.

## 9. Decisions we need from the organization

Unchanged asks renumbered D1–D7; D8–D10 new. Each blocks the phase in brackets.

- **[D1 / P-6, answer early]** Which CA/PKI issues certificates (server + per-workstation
  client certs)? The dev CA can carry the pilot; the swap lands in Phase 6, but certificate
  issuance has lead time — answer during Phase 2–3.
- **[D2 / P-3]** Which PostgreSQL is the real system-of-record, and can we get a dedicated
  least-privilege service account?
- **[D3 / P-5]** Where do internal documents actually live — SMB shares, SharePoint, NFS, DMS?
  (Demo runs on `D:\Shares`; the answer gates pointing files-mcp at real shares for the pilot.)
- **[D4 / P-5]** Who owns data classification (which tables/documents are which sensitivity)?
  Gates widening any share or table exposure beyond the demo roots (see R4).
- **[D5 / P-3]** What hardware for HA — 2+ Linux nodes + load balancer; later a DR site?
- **[D6 / P-4]** Which SIEM receives the audit stream — Wazuh, OpenSearch, Splunk, Sentinel?
- **[D7 / P-6]** Is an HSM required for key custody, or is a software secret store acceptable
  at launch? (Note: if the org classifies this system under NCS-1:2020 ADVANCED, software-only
  signing keys are not permitted — the answer may not be optional.)
- **[D8 / P-6]** Formal written acceptance of R1 (BYO-AI residual risk) — who signs it?
- **[D9 / P-2]** Console session policy — TTL/idle timeout values and whether a pre-expiry
  warning is required.
- **[D10 / P-4]** Alert delivery channel for security notifications — SMTP relay, webhook to
  an existing chat/ticket system, or SIEM-native alerting only?

_Staffing note: if NCA ECC-2:2024 applies to this system, cybersecurity roles must be filled
by qualified Saudi nationals — a hiring constraint to surface alongside [D8], not a build item._

## 10. Roadmap

Phases 0–1 of the previous plan are **done** (kept below as the done-log). Remaining work is
re-cut into Phases 2–6. Mapping to the old plan: old P2→new P3, old P3→new P4, old P4→new P5,
old P5→new P6; new **Phase 2 is inserted** — a truth-hygiene-and-console sprint that makes
everything after it cheaper and more honest. Effort tags (S/M/L) are build size; the IT team
operates and decides, Claude Code does the hand-coding.

_Where is security in this roadmap? Everywhere and in three concentrations. The security
**engine** is already built (§4 — the 18-stage pipeline is the product). **Phase 2** lands
the remaining cheap hardening (tasks 6: scoped tokens, fail-closed validation, offsite-ready
backups). **Phase 4 is the security-operations phase** — detection, alerting, DLP v2,
red-team CI gate, incident response. **Phase 6 is the security-certification phase** — pen
test, key custody, org PKI, DR, compliance matrix, formal risk acceptance._

### Done log
- **Phase 0 — Make it real, not a demo** ✅ 2026-07-06. Prod stack (postgres:17, real
  secrets, mTLS :8443, production tripwires), restore-tested daily backups, repo on Gitea.
- **Phase 1 — Complete the connectors** ✅ 2026-07-06. files-mcp built (with dedicated
  path-traversal attack tests); gitea-mcp and postgres-mcp on real systems least-privilege.
- **Increment — Client access layer** ✅ 2026-07-06. MCP OAuth 2.1 AS + `/connect` wizard;
  verified through the live mTLS proxy (14 tests).
- **Increment — Admin control surface** ✅ 2026-07-09. API keys, OAuth client mgmt, operator
  lifecycle, server lifecycle, notification center; **live-QA-verified** via `ciadmin`
  browser walkthrough (11 tests).

### Phase 2 — Truth, hygiene & console completion (L, ~3–4 weeks) — **tasks 1–4 ✅ 2026-07-12**
_Goal: everything the system shows and every claim the docs make is true; the admin console
does **everything an admin needs** — no backend-only controls, no inert toggles, no blind
spots from the §7b register; the repo is clean enough to hand to an auditor; the last cheap
security wins land._

**Progress (2026-07-12):** tasks 1–4 done — hygiene, the test-artifact purge, the dashboard
truth pass, and the full console build-out. Suite: **193 tests green** (was 148). Remaining:
tasks 5–10 (session policy, security quick wins, test debt, docs, governance sweep,
employee-zero).

> **Four production defects were found and fixed while building this** — all pre-existing,
> none previously caught by a test:
> 1. **The gateway could not boot at all.** `mcp` was pinned to a *range* (`>=1.2,<2.0`) and
>    drifted to 1.8.1, whose FastMCP calls `issubclass()` on raw annotations — so every
>    server module using `from __future__ import annotations` failed to import. All four
>    production connectors were dead. SDK pinned; guard test added
>    (`tests/test_servers_import.py`) so an SDK bump fails CI instead of production.
> 2. **`/api/health` re-verified the entire audit chain on every request** — a 3.6 s CPU
>    pass at 6.5k records, run by the container healthcheck every 30 s and by every
>    dashboard poll, growing linearly with the log. Now a cached full verification (60 s
>    TTL, 5 ms warm); the console's Re-verify button forces a fresh pass.
> 3. **Stopping or removing a server could hang forever.** The stdio teardown is entered on
>    another task, so closing it from a request task hangs (anyio cross-task cancel scope).
>    The teardown is now detached — the request returns immediately.
> 4. **Adding a server with a typo'd path hung the admin request indefinitely**, holding a
>    worker: a dead subprocess never answers the MCP handshake. The handshake is now
>    bounded (30 s) and fails as a clean 502 naming the likely cause.

Tasks:
1. **✅ Repo hygiene** (2026-07-12, commit 9e2222c): delete H1 stray artifacts and H8 dead code (`ui.backup-vanilla/`,
   `Login-page.txt`, `qwen_chat.py`); delete the H16 TOTP QR images (re-enroll the affected
   accounts if the images were ever shared); rotate the H2 OpenRouter key and move
   `MCP_APP_PASSWORD` into `deploy/secrets/`; commit the pending `ADMIN-CONTROLS.md`.
2. **✅ Test-data purge script** (2026-07-12): `scripts/purge_test_artifacts.py` sweeps
   `pytest-*` artifacts from the registry, OAuth clients/refresh tokens, API keys, temp
   operators (+ their credentials and MFA secrets), dynamic servers and notification noise;
   wired into CI teardown so pollution cannot recur. 59 stale OAuth clients, 5 temp
   operators and 2 pending test tools removed from the dev store (H3).
3. **✅ Dashboard truth pass** (2026-07-12) — A3–A5, A9, A16, A19 / H4, H5, H10.
   Per-call durations are now recorded in the audit chain, so latency is *measured*
   everywhere it appears (verified live: p50 7.0 ms, p95 13.6 ms on real calls). The canned
   "+11.01%" deltas, the hardcoded Mon–Sun latency curve, the synthetic traffic series and
   the stdio=100 transport pie are gone — replaced by real aggregates (`app/insights.py`).
   Rate-limit bars show live consumption; Alerts/Settings toggles persist; re-tier is a real
   dialog. Where a value genuinely does not exist yet the UI renders "—" rather than invent
   one.
4. **Admin console completion — everything the admin needs, real and in the UI.** Works down
   the §7b register (the ADMIN-CONTROLS backlog pulled forward from Phase 4, plus the
   walkthrough discoveries):
   - kill-switch safety UX: confirm dialog, scope pickers, reason field, auto-expiry (A7);
   - audit usability: export (CSV/JSON), field filters, pagination (A2);
   - registry governance completeness: reject/ban a pending tool, manual quarantine, tool
     schema view before approval, drift before/after diff (A8, A24);
   - policy, rate-limit, and DLP editing from the UI — including per-server rate-limit
     overrides and per-role server entitlements — backed by exposing DLP/anomaly thresholds
     in `config.yaml` (today hardcoded in `dlp.py`/`anomaly.py`), so Phase 5 tuning is a
     config change an admin makes from the console (A6, A15);
   - gateway self-page: version, uptime, health detail, effective config, maintenance mode,
     **backup status/history, certificate-expiry tracking, disk/log-growth view**
     (A10, A11, A13, A23);
   - observability rollups: DLP activity (masks by user/tool/detector), approval-aging/SLA
     view, live lockout list with unlock, last-used timestamps on API keys and OAuth
     clients, vault-lease page over the existing API (A14, A17, A18, A20, A21);
   - per-operator notification read state (A22);
   - server edit-in-place and real Version/Latency columns (A16, H10 remainder).
   Only external alert delivery (A1) stays in Phase 4 — it depends on the SIEM and channel
   decisions [D6]/[D10].
5. Session policy (A12 / H11, [D9]): configurable console TTL + idle timeout + a 2-minute
   expiry warning toast.
6. Security quick wins: scoped Gitea machine-account token (H13); jsonschema startup tripwire
   in production (H14); backup destination to a second disk/NAS now, offsite in Phase 3 (H15).
7. Test debt (H7): unit tests for `anomaly.py`, `vault.py`, `apikeys.py`, `notifications.py`,
   `mcp_manager.py`, `reports_server.py`; a CI check that `dashboard/src` builds and the
   committed `ui/` bundle is current (H12).
8. Docs refresh (H6): README counts, OPERATIONS.md gaps (server-onboarding end-to-end
   runbook, PKI/CA rotation, upgrade/patching procedure, log rotation & capacity).
9. Governance actions in the console: approve the pending files-mcp tools; review the two
   quarantined opendata tools (drift re-pin or reject); retire `docs`/`actions` fixtures
   from config (H9). **Constitute the Risk Board on paper** — name ≥2 approvers with
   separation of duties in OPERATIONS.md, so "Risk-Board approval" is a body, not a login.
10. **Employee-zero smoke test** on a real client machine (login → OAuth → `/mcp` →
    `files__search_content` → DLP mask → approval round-trip).

→ _Done when: the suite is ≥180 test functions green; a fresh reviewer finds zero fabricated
numbers and zero inert controls in the console; **every §7b register row A2–A24 is closed and
every row in ADMIN-CONTROLS.md is ✅ or explicitly deferred with a reason** (the only planned
deferrals: A1 alert delivery and A25 SIEM health → Phase 4); the repo has no stray artifacts;
and employee-zero has run end-to-end on real hardware._

_**Mini-pilot starts here.** Immediately after Phase 2, onboard ≤5 friendly users (R3 bounds
the cohort while state is flat-file) and let them work in parallel with Phases 3–4. Their
latency, approval-friction, and DLP observations become the Phase 5 tuning baseline — real-user
learning should not wait for HA._

### Phase 3 — State & scale (L, was old Phase 2)
_Goal: the gateway survives concurrency, restarts, and node loss at 300-user scale._

Tasks:
1. **State migration to PostgreSQL** (the big one): audit chain, approvals, registry,
   credentials/operators, OAuth clients/refresh, API keys, notifications, kill-switch/drain
   state move from JSON files to the DB behind the existing store interfaces; flat-file
   backend retained as the dev/test default; one-shot migration tool + rollback procedure;
   keep the HMAC hash chain intact across the move.
2. Shared runtime state for multi-instance: sessions, rate-limit windows, circuit-breaker
   state, OAuth codes, vault leases, taint sets, lockout counters, JWT replay cache, and
   **approval executed results** (today an approved call's result dies with a restart —
   a user-visible bug, fix regardless of HA) — DB or Redis-class store ([D5] informs); or an
   explicit sticky-session design decision documented.
3. HA: 2+ gateway instances behind a load balancer (nginx upstream or the org's LB); config
   for instance identity; health-based ejection. Target OS: Linux nodes (retire R9
   Windows couplings: shares mount path, Gitea address, backup scheduling).
4. Load test: `scripts/loadtest.py` to 300+ concurrent sessions; record PEP overhead
   (target: p95 added latency ≤ 150 ms per mediated call); tune limits/timeouts/breaker.
5. Offsite/second-site backups + log rotation & disk-capacity runbook.

→ _Done when: 300 concurrent sessions sustained within the latency budget, killing one
gateway node drops zero sessions, restarting everything loses zero durable state, and a
restore from offsite backup has been executed once._

### Phase 4 — See & respond: SecOps (M, was old Phase 3)
_Goal: an attack shows up as an alert a human actually receives, and the team has rehearsed
the response._

Tasks:
1. SIEM integration [D6]: point the export stream at the chosen SIEM; ship a **detection
   content pack** (brute-force, first-tool-use, sequence/volume anomalies, tool drift,
   approval-SLA breach, kill-switch engagement, quarantine events); surface SIEM export
   consumer health in the console self-page (A25).
2. Alert **delivery** [D10] (A1): email/webhook channel for critical notifications; on-call
   escalation note in OPERATIONS.md.
3. Audit retention: immutable/WORM store, ≥2-year in-Kingdom retention (NDMO); retention/
   pruning for operational stores.
4. **DLP v2:** Arabic NER detector (offline model) as the third detection point; measured
   FP/FN against an org-built Arabic PII corpus; extend DLP to all three edges (user→gateway,
   tool-results→context, output→user). Thresholds are already config-exposed and console-
   editable from Phase 2 task 4 — the new detector plugs into that surface.
5. **Red-team corpus as CI gate:** Arabic + English + Unicode-obfuscated injection suite; the
   build fails if any tainted value reaches a Tier≥2 invocation.
6. IR program: four playbooks (prompt injection, compromised identity, compromised/rug-pulled
   server, agent-mediated exfiltration); **monthly kill-switch drill; monthly canary
   approvals** (deliberately-wrong requests must be rejected — misses trigger approver
   retraining); annual tabletop.

→ _Done when: an induced brute-force appears in the SIEM and a human is notified within
minutes; the red-team corpus runs in CI; and one kill-switch drill and one canary cycle have
completed clean._

### Phase 5 — Pilot, then roll out (S→M, was old Phase 4)
_Goal: real users, tuned thresholds, repeatable onboarding._

Tasks:
1. Staff connect guide (net-new, wraps the `/connect` wizard): one page, screenshots, the
   three supported clients (Claude Code / LM Studio / other OAuth-capable MCP clients).
2. Expand the mini-pilot to 10–20 users across ≥2 roles (employee/analyst); measure latency,
   approval friction (time-to-approve, approval rate), DLP false positives, anomaly false
   alarms.
3. Role-based micro-training: users (injection awareness), approvers (what a canary looks
   like, Unicode spoofing), admins (containment drill).
4. Tune: rate limits from 95th-percentile observed usage; approval tiers per server; anomaly
   thresholds.
5. Department-by-department expansion with a per-department entitlement review.

→ _Done when: pilot cohort has run ≥4 weeks, every measured threshold has been reviewed
against real data, and onboarding a new user takes ≤15 minutes without an engineer._

### Phase 6 — Harden & certify (M, was old Phase 5)
_Goal: production sign-off an auditor will accept._

Tasks:
1. Independent penetration test; remediate; retest.
2. Key custody per [D7]: HSM or hardened software store; org PKI per [D1] replaces the dev
   CA; M-of-N ceremony for root material if HSM.
3. OIDC/Keycloak cutover if the org mandates central IdP (`auth.mode: oidc` is staged).
4. DR: second site per [D5]; failover + restore drills with recorded RTO/RPO.
5. **Compliance traceability matrix** at control-ID level: NCA ECC-2:2024 + CSCC-1 (if
   designated critical) + DCC + NCS; PDPL (RoPA, DPIA, DSR procedure); NDMO classification
   mapping; SDAIA GenAI guidelines; DGA cloud-exception filing if applicable; FIPS 140-3
   CMVP verification for modules in the crypto path if [D7] lands on HSM.
6. Formal residual-risk acceptance: R1 signed [D8]; exceptions register; go-live sign-off.

→ _Outcome: production accreditation. The system is no longer a project; it's a service._

## 11. Extension track — descoped, with re-activation triggers

Inventoried from the v10 BuildSpec / Platform-Build-Plan / Auth-Redesign docs. **None of these
are scheduled.** Each is listed so the descope is a decision, not an accident — with the
trigger that would put it back on the roadmap.

| Capability | Trigger to activate |
|---|---|
| Hosted inference tier (vLLM/GPU) + model intake pipeline + guardrail chain | Org decides employees may not run local models, or wants a sanctioned in-house model |
| Server-side sandboxed agent runtime + thin clients | Same trigger as above; eliminates R1 structurally |
| Client attestation / approved-model list | R1 acceptance is refused at [D8], or a pilot incident traces to a rogue client |
| Planner/quarantine LLM split + capability-typed taint (full CaMeL) | Hosted inference exists (prereq); injection incidents observed past the current taint engine |
| RFC 8693 token exchange, audience-bound backend tokens, no-passthrough | Backend MCP servers multiply beyond ~10 or third-party servers are onboarded |
| SPIFFE/SPIRE workload identity; Streamable-HTTP+mTLS south of the gateway | HA fleet grows past a handful of nodes, or a zero-trust network mandate lands |
| Tokenization/FPE + detokenization vault | DLP masking proves insufficient for analyst workflows on real PII at scale |
| Air-gap + media-ingress station + admission control (Kyverno) + private registries | Org re-designates the system as air-gapped critical infrastructure (Vision A) |
| Confidential compute (CPU/GPU CC) | Regulator requires it; offline GPU attestation matures |
| FIDO2/WebAuthn / AAL3 smartcards for approvers | Org PKI/IdP decision [D1] lands on hardware-key issuance |
| Narrow parameterized data tools replacing postgres-mcp's generic SQL `query` | Pilot telemetry shows over-broad reads, or the data steward [D4] requires column-level minimization (today bounded by READ ONLY txns + DB-role grants + row caps) |
| UEBA behavioral baselining per identity (MITRE ATLAS mapping) | SIEM (Phase 4) is live and the anomaly engine's false-positive rate stays high |

## 12. Milestones & measurable targets

| Milestone | Means | Status |
|---|---|---|
| M0 Real, not a demo | Prod stack, real secrets, mTLS, backups | ✅ 2026-07-06 |
| M1 All data sources + client access + admin console | three data sources (DB, Git, docs) + reports/opendata auxiliaries; OAuth onboarding; live-QA'd console | ✅ 2026-07-09 |
| M2 Clean, true & console-complete | Phase 2 exit criteria | — |
| M3 Scale proven | Phase 3 exit criteria (300 concurrent, node-kill = 0 loss) | — |
| M4 SecOps live | Phase 4 exit criteria (SIEM alert within minutes, drills run) | — |
| M5 Pilot complete | Phase 5 exit criteria (≥4 weeks, thresholds tuned) | — |
| M6 Sign-off | Phase 6 exit criteria (pen test, DR drill, matrix, R1 signed) | — |

**Standing targets (SLOs) once live:**
- PEP overhead: p95 ≤ 150 ms added per mediated tool call at 300 concurrent.
- Access-token TTL ≤ 600 s; identity revocation effective on next call (< 60 s worst case).
- Audit chain verified daily (automated); zero unexplained chain breaks.
- Alert latency: critical security event → human notification ≤ 5 min.
- Backups: daily, offsite, restore-tested monthly; audit retention ≥ 2 years immutable.
- Cadences: kill-switch drill monthly · canary approvals monthly · access review quarterly
  (monthly for write-capable roles) · patch window monthly · IR tabletop annually ·
  pen test annually.
- Red-team injection corpus: zero tainted-value Tier≥2 invocations, enforced in CI.

## 13. Do now (next two weeks)

1. **Employee-zero smoke test** on a real client machine — the one unproven step of the core
   promise (Phase 2, task 10).
2. **Console governance sweep** — approve files-mcp tools, action the two quarantined
   opendata tools, purge `pytest-*` artifacts (Phase 2, tasks 2 & 9).
3. **Commit the pending `ADMIN-CONTROLS.md`, delete the stray `main.js` and the TOTP QR
   images,** rotate the exposed OpenRouter key and move `MCP_APP_PASSWORD` to
   `deploy/secrets/` (Phase 2, task 1 — under an hour of hygiene).
4. **Scoped Gitea machine token** (Phase 2, task 6).
5. Start the **dashboard truth pass** (Phase 2, task 3).
6. Take **[D2] and [D6]** to the organization — the two decisions with the longest lead
   times ahead of Phases 3–4.
