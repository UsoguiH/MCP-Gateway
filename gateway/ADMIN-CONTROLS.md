# MCP Gateway — Admin Control Surface

Everything an admin should be able to control from the dashboard, organized by domain.
Grounded in the current architecture: risk tiers 0–3, hash-pinned registry, HITL
approvals, credential vault, HMAC-chained audit, OAuth clients.

**Status legend**
- ✅ exists — backend **and** UI have it today
- ✅ P2 — delivered in the Phase 2 console build-out (2026-07-12)
- 🟡 partial — some of it exists, or backend exists but no UI
- ❌ missing — not available anywhere

Reviewed: **2026-07-12, after the Phase 2 truth + console sprint.** The 2026-07-09 pass
delivered API keys, OAuth client management, operator lifecycle, server lifecycle and the
notification centre. Phase 2 closed the rest of the register (§7b of PROJECT-PLAN.md):
every control an admin needs is now in the UI, and every number the console shows is
measured rather than fabricated.

**Delivered in Phase 2 (2026-07-12):**
- **The console stopped lying.** Per-call durations are now recorded in the audit chain
  (`gateway.py`), so latency/avg/p95 are measured everywhere they appear. The canned
  "+11.01%" deltas, the hardcoded Mon–Sun latency curve, the synthetic traffic series and
  the stdio=100 transport pie are gone — replaced by real aggregates from `app/insights.py`.
  Where a value genuinely does not exist yet, the UI renders "—" instead of inventing one.
- **Toggles that do something.** `app/settings.py` is a validated, persisted overlay on the
  YAML baseline. Rate limits (incl. per-server overrides), approval tier, DLP detectors,
  anomaly thresholds, alert rules and session policy are editable from the console and take
  effect on the next request — no SSH, no restart. The Alerts and Settings switches used to
  be local React state that saved nothing.
- **Kill-switch guardrails.** Scope pickers (no more free-text typos that silently protect
  nothing), a mandatory reason, an optional auto-release TTL, a confirmation that states the
  blast radius, and a live view of who engaged what and why.
- **Registry governance you can actually perform.** Read a tool's schema *before* approving
  it; see a side-by-side diff of exactly what changed when drift quarantines it; **reject**
  a tool (previously an admin could only ever say yes); manually quarantine on suspicion.
- **Audit investigation.** Server-side filters over the whole chain, pagination, and
  CSV/JSON export. "What did khalid touch last Tuesday?" is now a question the console
  answers instead of an SSH session and a grep.
- **The gateway watches itself.** A Gateway page with version, uptime, effective config,
  **backup status**, **certificate expiry**, disk/log growth, and maintenance mode.
- **DLP activity page** — masking rollups by detector, tool and caller (the events were
  always in the audit chain; nothing had ever aggregated them).
- **Per-operator notification read state** — one admin clearing the bell no longer hides an
  incident from the rest of the team.
- Fixed in passing: **all four production connectors were dead** (an unpinned `mcp` SDK
  drifted to 1.8.1, whose FastMCP cannot introspect string annotations, so every server
  using `from __future__ import annotations` failed to import and the gateway could not
  boot). SDK pinned, imports fixed, regression test added (`tests/test_servers_import.py`).

**Still open (by design):** external alert delivery (email/webhook) waits on the SIEM and
channel decisions — Phase 4.

---

## 1. Servers

| Control | Status |
|---|---|
| View status, tools, breaker state, tier breakdown | ✅ exists (Manage drawer) |
| Restart / stop / start a server process | ✅ NEW (Manage drawer, persisted) |
| Reset circuit breaker (force-close after fixing the cause) | ✅ NEW |
| Enable / disable (drain) a server — stop new calls, let in-flight finish | ✅ NEW |
| Add / remove a server without editing config files | ✅ NEW (+ Add server, Remove in drawer) |
| Edit an existing server's command / env / transport from the UI | ✅ P2 (Manage drawer → Edit configuration; registry pins survive the edit) |
| Kill-switch a server | ✅ exists (Kill Switch page, one-click per server) |
| Set per-server rate limit override | ✅ P2 (Rate Limits page → per-server overrides) |
| Populate Version / Latency / Uptime columns in the servers table | ✅ P2 (version from the MCP handshake; latency measured from audit durations) |

## 2. Tools (Registry)

| Control | Status |
|---|---|
| Approve onboarding of new tools | ✅ exists |
| Review drift & re-pin hash | ✅ exists |
| Change risk tier | ✅ P2 (real dialog, replacing `window.prompt()`) |
| Enable / disable an individual tool without quarantining or kill-switching | ❌ missing |
| Quarantine a tool manually (not just automatic on drift) | ✅ P2 (reason required; durable) |
| Reject / permanently ban a pending tool | ✅ P2 (stays rejected across re-discovery; reinstatable) |
| View a tool's full schema/description — what the admin is actually approving | ✅ P2 (Inspect; plus a side-by-side drift diff showing exactly what changed) |
| Per-tool allowlist by role/clearance (e.g. `drop_table` only for DBAs regardless of tier) | ❌ missing (per-**server** role entitlements exist in policy.yaml; per-tool does not) |
| Argument constraints / guardrails (e.g. `delete_rows` must include a WHERE) | ❌ missing |

## 3. Identities & Operators

| Control | Status |
|---|---|
| Revoke / restore identity | ✅ exists |
| Unlock after failed-login lockout | ✅ exists |
| Create a new operator (one-time temp password + TOTP enrollment) | ✅ NEW |
| Delete / offboard an operator | ✅ NEW |
| Change role and clearance | ✅ NEW |
| Force password reset | ✅ NEW |
| Enroll / reset MFA | ✅ NEW (row menu) |
| View an operator's active sessions and last login | 🟡 Sessions page shows activity, not auth state |
| Grant / revoke approver status (`can_approve`) per person | ❌ missing (role-level only — change the role to change approver status) |

## 4. Sessions & Clients

| Control | Status |
|---|---|
| View live sessions and per-identity forensic timeline | ✅ exists |
| Terminate a specific session/token immediately | ✅ NEW |
| Terminate all sessions for a user ("sign them out everywhere") | ✅ NEW |
| Set session TTL / idle timeout | 🟡 P2 (configurable in Settings → session; the expiry-warning toast is the remaining piece) |
| Approve / block a new MCP client on first connect (client allowlisting) | ❌ missing |

## 5. OAuth / API Credentials

| Control | Status |
|---|---|
| List registered OAuth clients (from `/oauth/register`) | ✅ NEW (API Keys page) |
| Revoke an OAuth client or its tokens | ✅ NEW (kills refresh tokens) |
| Create / revoke API keys with scopes and expiry | ✅ NEW (scoped read/standard/full → tier cap, operator-bound, hashed at rest, one-time reveal, enforced on `/mcp`) |
| Rotate the gateway's own signing/HMAC secrets | ❌ missing |

## 6. Vault (Managed Credentials)

| Control | Status |
|---|---|
| View which credentials the gateway holds (name, target, age — never the secret) | 🟡 backend `/api/admin/vault` exists; UI shows only a Yes/No in the server drawer |
| Rotate a credential | ❌ missing |
| Add / remove a credential | ❌ missing |
| Alert on credential age (e.g. Gitea token > 90 days) | ❌ missing |

## 7. Approvals (HITL)

| Control | Status |
|---|---|
| Approve / reject pending calls, two-person + SoD, tainted-arg warnings | ✅ exists |
| Approval history — who approved what, when, both signers | ✅ NEW (History tab) |
| Expire stale requests (auto-reject after N hours) | ✅ NEW (`approvals.pending_ttl_hours`, resolved pruned after `retention_hours`) |
| Manual "reject all pending" | ❌ missing |
| Delegate approval authority (on-call schedule, vacation) | ❌ missing |
| Configure which tiers require approval and how many signers | 🟡 `approval_min_tier` now in policy.yaml — file-only, no UI |

## 8. Kill Switch & Containment

| Control | Status |
|---|---|
| Engage / release global, server, tool, user scopes | ✅ exists |
| Confirmation step on global kill | ✅ P2 (states the blast radius: "EVERY user and EVERY tool — all 300+ staff") |
| Scope validation / picker for tool and user scopes | ✅ P2 (dropdowns of real servers/tools/users; an unparseable scope is refused) |
| Auto-expiring containment ("kill for 1 hour") | ✅ P2 (optional TTL; a forgotten kill cannot strand the org) |
| Who engaged it and why — require a reason string, show it on the active scope | ✅ P2 (reason mandatory, recorded in the audit chain, shown on the active scope) |

## 9. Policies & DLP

| Control | Status |
|---|---|
| Edit rate limits (global, per-tool, per-server, login) from the UI | ✅ P2 (Rate Limits page; live consumption bars alongside the ceilings) |
| Manage DLP rules (enable/disable detectors, mask vs block) | ✅ P2 (Settings → master switch + per-detector toggles) · custom regex ❌ |
| View DLP hits — what was masked/blocked, for whom | ✅ P2 (DLP Activity page: by detector, by tool, by caller) |
| Toggle registry onboarding gate, SIEM export for real | 🟡 P2 (shown read-only and labelled `config` — deploy-time settings, no longer fake switches) |
| Edit the ABAC role ladder (tier ceilings per role) | ❌ missing — display only |
| Edit per-role server entitlements (`servers:` allowlists) from the UI | ❌ missing — policy.yaml only |

## 10. Alerts & Notifications

| Control | Status |
|---|---|
| View anomaly alerts | ✅ exists (+ Re-evaluate) |
| In-dashboard notification center (severity, dedupe, unread badge, mark-read) | ✅ exists |
| Per-operator read state (one admin clearing the bell must not hide an incident from the team) | ✅ P2 |
| Enable / disable individual detection rules | ✅ P2 (Alerts page — toggles now persist and the engine honours them) |
| Configure thresholds (error rate %, failed-login count, approval SLA, window) | ✅ P2 (Alerts page) |
| Acknowledge / resolve / snooze an alert | ❌ missing — alerts just sit there |
| Delivery channels — email, webhook, Slack/Telegram | ❌ **Phase 4** (depends on the SIEM + channel decisions D6/D10); **this is what makes everything else work when nobody's watching** |

## 11. Audit & Compliance

| Control | Status |
|---|---|
| Verify chain integrity, browse events | ✅ exists (+ Re-verify) |
| Export (CSV/JSON, honouring the current filters) | ✅ P2 |
| Filtering | ✅ P2 (server-side: event, identity, server, tool, time range, free text — over the whole chain, not a 200-row window) |
| Pagination | ✅ P2 (50/page, newest first) |
| Per-call duration recorded and shown | ✅ P2 |
| Record detail view (full arguments, digests, chain hashes) | 🟡 digests + duration in the table; no per-record drawer |
| Retention policy control (how long, archive target) | ❌ **Phase 4** (WORM / SIEM retention) |

## 12. Gateway Itself

| Control | Status |
|---|---|
| Self-health page: version, uptime, PID, servers, tools | ✅ P2 (Gateway page) |
| Backup status (did last night's backup actually run?) | ✅ P2 (latest run, age, size, retained count, stale warning) |
| Certificate expiry tracking | ✅ P2 (every cert the deployment depends on, days left, expiring/expired badges) |
| Disk headroom + audit-log growth rate | ✅ P2 (incl. projected exhaustion) |
| View effective config (read-only dump of what's actually loaded, secrets redacted) | ✅ P2 |
| Maintenance mode (pause mediated calls during a patch; admins keep working) | ✅ P2 |
| Trigger a backup on demand | ❌ missing (scheduled only) |
| Reload config without restart | 🟡 P2 (runtime settings overlay applies instantly; config.yaml still needs a restart) |
| Rotate the gateway's own signing/HMAC secrets | ❌ missing |

---

## What remains (post-Phase-2 backlog)

Phase 2 closed the §7b admin gap register. Ordered by blast radius:

1. **External notification delivery (email/webhook)** — the HITL queue and critical alerts
   only work if someone is staring at the dashboard. An unwatched approval queue is not a
   gate. Deliberately held for **Phase 4**: it depends on the SIEM choice [D6] and the
   channel decision [D10]. (Section 10)
2. **Vault management** — rotate/add/remove a managed credential; alert on credential age
   (the Gitea token is still an all-scope admin token). (Section 6)
3. **Per-tool authorization** — allowlist a tool by role/clearance, and argument guardrails
   (e.g. `delete_rows` must carry a WHERE). Today authorization is per-server + per-tier.
   (Section 2)
4. **ABAC editing from the UI** — role ladder and per-role server entitlements are still
   policy.yaml-only. (Section 9)
5. **Approval workflow depth** — acknowledge/snooze an alert, delegate approval authority
   (on-call/vacation), manual "reject all pending". (Sections 7, 10)
6. **Secret rotation from the console** — signing key, audit HMAC, vault key. (Sections 5, 12)
