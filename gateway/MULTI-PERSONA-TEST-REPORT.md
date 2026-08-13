# Secure MCP Gateway — Four-Persona Honest Test Report

**Date:** 2026-08-10
**System under test:** Secure MCP Gateway, running live at `http://127.0.0.1:8800` (flat-file state, 10 servers registered, 243 tools / 2 pending, audit chain intact).
**Method:** Four independent Sonnet-5 agents each stress-tested the running system and the source from one persona's lens — an **end user**, an **admin**, a **business stakeholder**, and an **AI-client integrator**. Each was told to be brutally honest, cite evidence (file:line, endpoint, or live observation), and separate what is *shipped* from what is *aspirational*. Findings below are theirs, lightly edited for consolidation; nothing was softened.

> Honesty note: all four agents completed. The dedicated admin agent hit an API error on its first run; its retry completed and its full findings are in the Admin section below (it independently verified several things the docs overstate).

---

## Executive summary

| Persona | Score | One-line verdict |
|---|---|---|
| End user | **6.5 / 10** | Strong bones, but broken on mobile and the first five minutes (login language, dead links) work against the operator. |
| Admin | **6 / 10** | Real governance engine, but the evaluated box is the *dev* config (dev crypto keys, flat-file, live toy fixtures) — not the HA/PG stack the docs claim — and alerts never leave the box. |
| Business stakeholder | **5 / 10** today | Genuinely differentiated architecture, but no cost/ROI reporting, the defining risk is unsigned, and "70% done" is self-graded. |
| AI-client integrator | **7.5 / 10** | Protocol + OAuth 2.1 layer is unusually solid; two concrete bugs (`DELETE /mcp`, rate-limiter) and locale rough edges. |

**The single most important cross-cutting truth:** the *engineering core is real and good* — the OAuth/PKCE flow, HITL approval round-trips, audit chaining, and DLP pipeline all work end-to-end against real tools. What's weak is everything **around** the core: first-run UX, operational delivery (alerts, secrets, DR), business evidence (cost, compliance mapping), and a handful of concrete bugs. This is a system that is more finished on the inside than on the outside.

---

## Cross-cutting themes (multiple personas hit these independently)

1. **Arabic/English split personality.** The login screen (end user), the OAuth consent popup (integrator), and the operator base implied by `org: "Government Entity"` are Arabic RTL — but the entire dashboard and connector page are English-only, with no language toggle. Three of four personas flagged this independently. An Arabic-only operator can *log in* but cannot read a single dashboard label; an English operator gets a jarring Arabic consent page mid-connect.
2. **Alerts never reach a human.** The business and (system-evidence) admin views agree: anomaly and kill-switch events land in an in-dashboard bell only. OPERATIONS.md itself calls external delivery "the single biggest operational gap." A control that fires silently into a web page nobody is watching is a log entry, not a control.
3. **Pilot fixtures `docs` / `actions` still registered.** The app's own startup tripwire says to remove them "before serving real users." They're also the *only* two backends that work without Docker — so they silently shape every first-connection demo. Flagged by the integrator and confirmed live.
4. **Self-graded status, and the demo box isn't the claimed box.** "70% to production," the risk register, and the ✅-marked hygiene items are all authored by the builder. The admin agent verified the running instance is `env=development`, flat-file, single-instance — *not* the "substantially complete" HA/PostgreSQL stack the docs describe — with the `docs`/`actions` toy fixtures serving live traffic (450/809 calls). Given a documented history of the dashboard showing fabricated numbers (H4/H5, since fixed), several personas independently recommend an outside party re-verify the claims and that the dashboard show `state_backend`/`env` prominently so nobody mistakes the dev instance for the hardened one.

---

## Verified, actionable bugs (highest-confidence, fix these first)

These are concrete code defects with reproduction evidence, not opinions:

| # | Bug | Evidence | Fix |
|---|---|---|---|
| B1 | **`DELETE /mcp` rejects OAuth + API-key clients.** Session teardown is wired to `current_user` (cert-only), not `mcp_principal`. Every `/connect` client uses OAuth or a bearer token, so none can end a session per spec — they get a misleading 401. | `app/main.py:592-596` vs `mcp_principal` at `:572`. Live: `DELETE /mcp` with OAuth token → `401 invalid token…`. | One-line dependency swap to `mcp_principal`. |
| B2 | **Login IP rate-limiter is dead code.** The limiter gates on `/api/login` / `/api/dev/login`, but the real endpoints are `/api/auth/login`, `/api/auth/mfa`, `/oauth/authorize`. The IP throttle never fires; only per-account lockout (5 fails / 5 min) backstops. Low-and-slow spraying across many usernames from one IP hits no IP friction. | `app/main.py:146`. Live: 30× bad password to `/api/auth/login` → no limiter 429, only per-account lockout. | Match the real paths. |
| B3 | **`initialize` ignores client `protocolVersion`.** Server always echoes its own `2025-11-25` regardless of what the client requests — no mismatch signal. | `app/mcp_server.py:227-239`. Live: sent `2024-11-05`, got `2025-11-25`. | Read/negotiate or at least log a mismatch. |
| B4 | **Backend-down reported as `isError:false` success.** A dead Docker backend returns a *successful* MCP result with the failure buried in the payload (`ConnectionTimeout`). A client LLM reading `isError` treats a dead backend as "it ran." | Live: `postgres__execute_query` → 10s → `isError:false` + `{"error":"connection timeout"}`. | Surface connection-level failure as `isError:true` or in `_meta`. |
| B5 | **Overview stat card vs. Top Tools disagree with no explanation.** "Tool Calls (Last 7 days)" reads 0 while "Top Tools" beside it lists six tools with usage — because one is range-windowed and the other is lifetime, unlabeled. | `data.ts:220-224`. Live on Overview. | Label the time horizon on each panel. |

---

## Persona 1 — End User

*A day-to-day operator who logs in to do their job.*

### What's bad (worst first)
- **[Critical] Unusable on a phone/small screen.** Both side panels are hard-coded non-collapsing widths (`App.tsx` `SideNav`=212px, `RightSidebar`=300px, both `shrink-0`). At a 390×844 viewport the two rails eat 512px and the main content region measures **0px wide**. No responsive breakpoint, no hamburger. Checking gateway status from a phone shows a sliver of sidebar and nothing else.
- **[High] Login is 100% Arabic RTL; the app is 100% English — no toggle.** `Login.tsx` renders every string in Arabic; the moment MFA succeeds you land in an English-only console. An Arabic-only speaker can authenticate but can't read a label; there's no switcher either way.
- **[High] "Reset password" and "Create account" are dead links dressed as actions.** `Login.tsx:112` and `:152` — both `<a href="#">` that `preventDefault()` and print a static gray sentence. A locked-out user gets no form, no ticket, no flow.
- **[Medium] Dark mode is a `filter: invert(1) hue-rotate(180deg)` hack** (`App.tsx` ~1776), not a real theme. It inverts *every* hue, so semantic status colors (green=healthy, red=danger, amber=warn) don't reliably keep their meaning — dangerous in a security console where "red = broken" is load-bearing.
- **[Medium] Overview panels contradict each other** (see B5).
- **[Medium] Modals have no a11y semantics.** `ui.tsx` `Modal` is a plain `<div>` — no `role="dialog"`, no `aria-modal`, no focus trap, no Escape-to-close. Every dialog (revoke key, kill switch, create operator) is affected.
- **[Low] Notification feed has no severity filter** — 44 unread after one login; kill-switch events interleaved with routine "Gateway started" noise, only "New/Earlier" grouping.
- **[Low] `PoliciesPage` has no empty state** (unlike every other table) — `App.tsx` ~1068.
- **[Low] The single search box silently double-duties** as global search *and* per-page table filter with no "filtered by X" indicator, so a stale filter can make a table look empty.

### What to add / improve
1. Fix mobile first — collapse rails to 72px (or overlay) below a breakpoint. Highest-value fix.
2. Pick one language for login+app, add a switcher.
3. Make "Reset password" do something real (even a "request sent to admin" flow).
4. Label time windows on every panel that could disagree.
5. Real dark theme, or drop the toggle.
6. Modal a11y basics (`role`, focus trap, Escape).
7. Severity filter on notifications.

### Verdict — **6.5/10**
Strong, feature-complete, API-backed console (real actions not fake toggles, thoughtful confirm dialogs, forensic tooling most internal tools skip) — but the first five minutes (login language, mobile, dead links) actively work against the operator it was built for.

---

## Persona 2 — Admin

*Responsible for operators, access control, audit, incident response, secrets, backups, uptime.*

### What's bad (worst first)
- **[Critical] The instance being evaluated is the dev config, not the hardened stack the docs claim.** Verified via `/api/health` and `/api/admin/gateway`: `state_backend="file"`, `"flat-file (single instance)"`, `env="development"`. PROJECT-PLAN.md claims Phase 3 ("state & scale") is "substantially complete" with a shared-`gwstate` PostgreSQL HA pair — none of that is what's running. Everything an admin can click here is the single-instance, in-memory-runtime-state config the same doc warns races under concurrency. Shown to a reviewer as "the gateway," it materially overstates readiness.
- **[Critical] Production crypto tripwires are firing — dev KEK/audit/vault keys in active use.** Verified live. The KEK protects the CA private keys and the TOTP/MFA secrets at rest (`data/mfa_secrets.json`); the audit key is what makes the hash chain tamper-*evident* rather than merely tamper-*visible-if-you-check*. On dev-default keys, anyone with the public documented default can forge audit continuity and decrypt MFA seeds. It's only a *warning* because `MCP_ENV` isn't `production` — nothing stops this exact config being deployed for real with the warning scrolling past in a log.
- **[High] Alerts do not leave the box — confirmed in code, not just docs.** `app/notifications.py` line 1: "Instead of email/webhooks, the gateway surfaces everything… in the dashboard's right panel." Grep of `app/` for `webhook|smtp|requests.post|send_email` → one hit, the docstring disclaiming it. Kill-switch engagement, lockouts, breaker trips, approval-SLA breaches — all invisible unless a human is staring at the console. For a pipeline that gates destructive actions on human approval, an unwatched queue is not a control.
- **[High] State DB is a self-acknowledged SPOF (R11) and the 300-concurrent SLO is unproven (R12).** If `gwstate` is down, both HA instances fail closed and every mediated call stops — no DB redundancy executed. Measured p95 ~650 ms at just 7 sessions is 4× the 150 ms target; nobody has run 300 concurrent anywhere. "Horizontally scalable pair" rests on extrapolation, not a load number that clears the bar.
- **[High] R1 — gateway authenticates the person, not their AI model — has no compensating control for reads, and the sign-off (D8) has no signer.** A logged-in operator whose local model is jailbroken can issue any *permitted read* they're cleared for, bounded only by anomaly detection and rate limits — there is no approval gate on reads. The most consequential trade-off in the system, and it "must be formally accepted in writing" — which hasn't happened.
- **[Medium-High] Pilot fixtures `docs`/`actions` are live and taking real traffic right now.** `/api/admin/servers`: both `state:"running"`, 450 and 809 calls served. OPERATIONS.md says production "refuses to start" with these registered — true only under `MCP_ENV=production`. No badge/warning in the running instance flags that these in-memory toys are mixed into the tool catalogue an operator/AI sees. Only discipline prevents shipping them.
- **[Medium] Vault/credential management has no rotate, no add/remove, no age alerting.** Confirmed absent from `app/vault.py`; ADMIN-CONTROLS.md marks all three ❌. The Gitea machine token is an all-scope admin token (H13) and there's no mechanism to know when it ages past a rotation policy — it just keeps working.
- **[Medium] Secrets sprawl on one host, confirmed on disk.** `deploy/secrets/` holds ten flat files — `kek`, `audit_key`, `vault_key`, `mfa_key`, `proxy_secret`, `pg_superuser_pw`, `mcp_app_pw`, `gitea_token`, `gwstate_pw`, `gwstate_url` — one Windows disk, no HSM (D7 open). Backups default to `D:\Backups\mcp` on the *same machine* unless an operator remembers `-Offsite` — one disk failure takes primary and backup together.
- **[Medium] `.env` still sits in the repo root** (305 bytes, dated the same day as the claimed Phase-2 hygiene commit). Contents unreadable in this sandboxed review, so whether the OpenRouter key / Postgres password it reportedly held (H2) was actually rotated is unconfirmed. A secrets-bearing `.env` at repo root is bad practice the hygiene pass should have eliminated, not just neutered.
- **[Low-Medium] ABAC/entitlements and the risk-tier ladder are file-only.** Per-role allow-lists and tier ceilings live in `policy.yaml` with no console UI — a privilege change is an out-of-band file edit + restart, invisible to the audit trail that governs every other admin action. Undercuts "the console does everything an admin needs."
- **[Low] No console workflow to rotate the gateway's own signing/HMAC/vault keys** (ADMIN-CONTROLS.md). Combined with the active dev-default keys, a KEK/audit-key compromise has no in-product remediation path.

### What to add / improve
1. Make `MCP_ENV=production` a **hard gate on deployment**, not opt-in — the dev-key/dev-fixture warnings should be impossible to run past on anything reachable outside localhost.
2. Ship real alert delivery (webhook/SMTP) before onboarding any real pilot user — table stakes for HITL to mean anything; don't let it wait on the SIEM decision.
3. Run the actual 300-concurrent load test on real (non-Windows-Docker) hardware and publish the number before claiming the scale story is done.
4. Stand up the HA/PostgreSQL stack as the thing people actually evaluate — or at minimum surface `state_backend` and `env` front-and-center on the dashboard so nobody mistakes the dev instance for the hardened one.
5. Build vault credential rotation + age alerting; rotate the Gitea admin token now.
6. Get R1 formally signed (D8) before expanding past the current cohort.
7. Delete `.env` from repo root, confirm the rotation happened, move secrets toward a real secret manager/HSM (close D7).
8. Strip `docs`/`actions` from any config that could be mistaken for production, and surface a "TEST FIXTURES ACTIVE" badge instead of a boot-time-only tripwire.
9. Bring ABAC/entitlement and tier-ladder editing into the console so every privilege change is auditable.

### Verdict — **6/10 · deploy to real production? No. Only-pilot? Yes.**
The engineering is genuinely strong where finished — the 18-stage pipeline, kill-switch guardrails (reason required, TTL-bounded, scope-validated — all verified live), fail-closed schema validation, cert/session binding, and audit export/filter tooling all check out. But the system being evaluated is running with **dev crypto keys, flat-file single-instance state, and live toy connectors** — none of which matches the "HA, PG-backed, production-tripwired" story the docs tell — while alert delivery flatly does not exist and the SPOF and SLO risks remain open. Only-pilot, and only with alert delivery added, the HA/PG stack actually running, dev keys rotated, and R1 signed before the cohort grows past a handful of friendly users.

---

## Persona 3 — Business Stakeholder

*Department head / compliance officer / budget owner deciding whether to adopt.*

### What's bad / risky for the business (worst first)
- **[Critical] The defining risk is accepted in name only.** R1 — "a jailbroken or backdoored local model acts with its owner's full clearance" — is the load-bearing trade-off of the whole BYO-AI pitch, and the plan itself says it "must be formally accepted in writing." D8 (who signs it) is still open. Today nobody has accepted this on paper.
- **[Critical] Core governance ownership is unassigned.** D1 (PKI), D3 (where documents live), D4 (data steward), D7 (HSM) all open. R4: "nobody owns data classification" — DLP masks known PII, but no one has decided which tables/documents are Secret vs Restricted. An auditor's first question has no answer.
- **[High] No cost, ROI, or chargeback reporting exists anywhere.** Code search of `app/` finds nothing — no cost-per-call, no cost-avoided-vs-SaaS, no per-department billing. For a budget owner funding a 2–4-person ops team plus infra, there is nothing in the product to justify the spend in business terms, only engineering metrics.
- **[High] Alerts don't reach a human** (same as admin view).
- **[High] "70% to production" is self-graded, and the missing 30% is exactly what a business needs to trust it** — SIEM, alert delivery, IR drills, org PKI, pen test, sign-off. The number moved 45→55→70% across three self-authored revisions in under a month.
- **[High] Small-team key-person risk** (R6) on a system meant to protect 300+ staff — same 2–4 people own PKI, backups, DR, SIEM, secrets, and the code.
- **[Medium] Scale unproven** (R12); **dashboard has a documented history of fake numbers** (H4/H10, since fixed, but worth re-verifying every ✅); **Arabic free-text PII is a DLP blind spot** (structured only — misses the majority of PII in real Arabic documents); **DR only tested same-disk**.
- **[Low-Medium] No compliance traceability matrix yet** (NCA ECC-2/PDPL/NDMO — Phase 6). **Most capability is dormant** — 230 of ~235 registry entries pending by design, so headline tool counts overstate what's usable.

### What to add / improve
1. Build a real cost/ROI view (cost per call, vs. unmanaged keys / vendor SaaS, per-department usage). Biggest business gap.
2. Close D8 (sign R1) and D4 (name a data steward ≠ the security chair) first.
3. Ship alert delivery before more users.
4. Get an outside party to check "70%" and re-audit for fabricated data.
5. Produce a draft compliance mapping now, even incomplete.
6. Prove 300-concurrent on real hardware, or sell the pilot scope (10–20 users) until R12 closes.
7. Fix Arabic PII before processing real Arabic documents; re-drill DR offsite; add a plain-language monthly business report; document succession.

### Verdict — **5/10 today** (→ ~8/10 once cost reporting, a signed R1, and alert delivery land)
The architecture is genuinely differentiated and defensible for an on-prem, controlled-internet org. But as a business proposition today it's thin: no cost/ROI reporting, the top risk unsigned, alerts that don't page, and a self-assessed progress number whose missing 30% is precisely the evidence a CFO or auditor asks for first. Fund it as a continued *pilot* for the specific org it was built for — not an org-wide rollout — until those land.

---

## Persona 4 — AI-Client Integrator

*Developer connecting Claude Code / Cursor / Claude Desktop / a custom MCP client.*

### What's bad (worst first)
- **[High] `DELETE /mcp` broken for every documented client** (B1).
- **[Medium] Per-IP login rate-limiter is dead code** (B2).
- **[Low] No `protocolVersion` negotiation in `initialize`** (B3).
- **[Low] Backend failures reported as `isError:false` successes** (B4).
- **[Low/UX] OAuth consent screen is Arabic-only RTL** (`main.py:637-724`) — the popup every OAuth client shows mid-connect, jarring in an otherwise English flow.
- **[Info] "claude.ai's cloud can't reach it" copy** (`connect.html:169`) couldn't be verified against a real Claude Desktop client — confirm before trusting.
- **[Improve] Manual token has no refresh** — 8-hour non-refreshable (`main.py:836`); unattended integrations (LM Studio, scripts) need a human to regenerate every 8h.

### What actually WORKED (verified live with curl — this matters)
- **Discovery**: both `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server` return spec-correct RFC 9728 / RFC 8414 docs.
- **Unauthenticated `/mcp`** → correct `401` with a `WWW-Authenticate` challenge a compliant client self-discovers from.
- **Full OAuth 2.1 auth-code + PKCE flow** driven end-to-end: dynamic client registration → authorize + consent + live TOTP → single-use code → token + refresh. Every adversarial control fired: `plain` PKCE rejected, code replay → `invalid_grant`, refresh rotation kills the old token, unknown client_id / non-loopback redirect rejected.
- **All three auth paths work against `/mcp`**: cert-bound session, `mcpk_` API key, and OAuth bearer.
- **End-to-end tool calls through the full pipeline**: a tier-0 read returned real data with governance `_meta`; a tier-3 destructive call (`actions__delete_record`) correctly **held for 2-signer human approval** and the approval resource round-trip worked; unknown tool → clean `isError:true`; malformed JSON → correct `-32700`.
- **Live "connected" indicator** flipped to `connected:true` the moment a session was established.
- Security headers, CSP, no-store on sensitive routes, and origin-exemption scoping all present and correctly scoped.

### Verdict — **7.5/10 · can a real user connect Claude Code today? Yes, with caveats.**
The MCP protocol layer and OAuth 2.1 implementation are unusually solid for a self-hosted gateway — discovery, DCR, PKCE, rotation, and HITL round-trips all work end-to-end against real tools. The real problems are narrow: a broken `DELETE /mcp` for exactly the auth methods every client uses, a mis-pointed rate limiter, and DX/locale rough edges. The documented `claude mcp add` + in-app Authenticate flow will succeed; graceful disconnect is broken and the mid-flow Arabic consent page will look foreign to non-Arabic operators.

---

## Consolidated priority list (what to fix, in order)

**Now — concrete bugs, cheap fixes, high confidence**
1. B1 — `DELETE /mcp` → use `mcp_principal` (one line).
2. B2 — fix login rate-limiter paths.
3. B5 — label the Overview time windows.
4. Remove/mark the `docs`/`actions` pilot fixtures.

**Before any real users — operational & security**
5. Real KEK/audit/vault secrets + run under `MCP_ENV=production`; always front with the mTLS terminator.
6. Ship alert delivery (webhook + SMTP).
7. Least-privilege Gitea token; MFA QR images off disk; schema-validation fatal in prod.
8. Fix mobile layout; resolve the login/app language split.

**Before org-wide scale — trust & business**
9. State-DB replica + failover; re-drill DR offsite.
10. Sign R1 (D8); name a data steward (D4); draft the compliance mapping.
11. Build a cost/ROI + plain-language monthly business report.
12. Prove the 300-concurrent SLO on real hardware; ship Arabic free-text PII detection.

---

## Overall honest take

Averaged, this lands around **6.4/10 today**. The verdict the four personas converge on: **the security engine is production-grade; the product around it is pilot-grade.** The protocol, auth, approval, audit, and DLP internals genuinely work and were verified live — that's the hard part and it's done well. What's missing is the unglamorous 30% that turns a strong engine into a deployable product: real secrets, alerts that page a human, a phone-usable and language-consistent UI, cost/compliance evidence a business can defend, and a short list of concrete bugs. None of it is architecturally hard; most is already on the roadmap. Ship it as a **controlled pilot** for the on-prem, controlled-internet org it was built for — and treat the self-graded "70%" as a builder's estimate that an outside reviewer should confirm before it's quoted to leadership.
