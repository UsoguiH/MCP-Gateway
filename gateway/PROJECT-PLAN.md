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

## Where we are: ≈ 45% to real production

The hard part is nearly done; the system around it is early. The **control-plane software**
(the security engine) is ~90% complete and covered by 90+ automated tests. But a production
system for a 300-person org is more than software — it is connectors + infrastructure +
operations. Against that whole, we are a little under halfway. (It would be easy to call this
"90% done" by looking only at the code; the code is 90%, the _system_ is ~45%.)

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

## Roadmap — six phases (dependency order)

Sequenced by what unblocks what. Effort tags (S/M/L) are _build_ size; the IT team operates
and decides, Claude Code does the hand-coding.

- **Phase 0 — Make it real, not a demo (START HERE, M).** Persistent DB + least-privilege role;
  replace all dev secrets and flip production config flags; deploy mTLS terminator + real TLS;
  push to self-hosted Gitea; enable backups.
  → _Outcome: a real, hardened single-node deployment with no dev defaults._
- **Phase 1 — Complete the connectors (M).** Build the internal-docs/file-share server; connect
  the DB and Git servers to real systems with least-privilege creds, each onboarded via the
  registry gate. → _Outcome: the AI can safely reach all three data sources._
- **Phase 2 — Scale & resilience (L).** Move gateway state into the DB; run 2+ instances behind
  a load balancer; load-test to 300+ and tune limits/timeouts/breaker.
  → _Outcome: proven to carry the whole org, no single point of failure._
- **Phase 3 — See & respond, SecOps (M).** Wire audit → SIEM; turn anomaly alerts into
  email/webhook notifications; audit retention + immutable store; incident runbooks +
  kill-switch drill. → _Outcome: the team is told when something's wrong._
- **Phase 4 — Pilot, then roll out (S).** Onboard 10–20 staff with their local AI; measure
  latency, approval friction, false positives; expand department by department.
  → _Outcome: real users, tuned thresholds, repeatable onboarding._
- **Phase 5 — Harden & certify (M).** Independent pen test; DR site; HSM for keys if required;
  formal risk acceptance + compliance mapping. → _Outcome: production sign-off._

## Do now (this week — all Phase 0)

1. **Stand up the real Postgres** — persistent volume, apply the least-privilege `mcp_app` role,
   rewire the gateway to connect as it (off the throwaway container).
2. **Push to Gitea** — repo is scanned/cleaned/committed; two commands once Gitea is up.
3. **Put real security in front** — real certs, deploy the mTLS terminator, load real secrets,
   flip production config so dev conveniences are off.
