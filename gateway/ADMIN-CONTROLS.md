# MCP Gateway — Admin Control Surface

Everything an admin should be able to control from the dashboard, organized by domain.
Grounded in the current architecture: risk tiers 0–3, hash-pinned registry, HITL
approvals, credential vault, HMAC-chained audit, OAuth clients.

**Status legend**
- ✅ exists — backend **and** UI have it today
- ✅ NEW — delivered in the priorities 1–4 build-out (2026-07-09)
- 🟡 partial — some of it exists, or backend exists but no UI
- ❌ missing — not available anywhere

Reviewed: 2026-07-09, **verified by a live admin walkthrough** (signed in as the
`ciadmin` operator through password+TOTP, every page exercised in a real browser).
Priorities 1–4 shipped and verified working: real API keys + OAuth client management,
operator lifecycle + session/MFA control, server lifecycle, in-dashboard notification
center, approvals history + auto-expiry. The remaining ❌ items are the not-yet-built
backlog.

Live-QA observations (2026-07-09), beyond the tables:
- **opendata tools quarantined on definition drift** — `opendata.search_datasets` and
  `opendata.preview_resource` sit quarantined in the registry awaiting drift review /
  re-pin (governance working as designed; an admin needs to action them).
- **Test-data hygiene** — 2 `pytest-echo.*` tools pending in the registry and 7
  `pytest-mcp` OAuth client registrations pollute the dev store; the notification
  feed carries the unit-test noise too. Cosmetic in dev, but argues for a
  purge-test-artifacts script (or a dedicated test data dir).
- **Servers table Version and Latency columns are never populated** ("—" for all).
- **Overview trend percentages are canned demo values** (+11.01% on 5 requests).
- **Console session expires after ~10–15 min** with a clean logged-out screen;
  fine, but there is no visible warning and no TTL/idle setting anywhere.

---

## 1. Servers

| Control | Status |
|---|---|
| View status, tools, breaker state, tier breakdown | ✅ exists (Manage drawer) |
| Restart / stop / start a server process | ✅ NEW (Manage drawer, persisted) |
| Reset circuit breaker (force-close after fixing the cause) | ✅ NEW |
| Enable / disable (drain) a server — stop new calls, let in-flight finish | ✅ NEW |
| Add / remove a server without editing config files | ✅ NEW (+ Add server, Remove in drawer) |
| Edit an existing server's command / env / transport from the UI | ❌ missing (remove + re-add) |
| Kill-switch a server | ✅ exists (Kill Switch page, one-click per server) |
| Set per-server rate limit override | ❌ missing (global config only) |
| Populate Version / Latency columns in the servers table | ❌ missing (always "—") |

## 2. Tools (Registry)

| Control | Status |
|---|---|
| Approve onboarding of new tools | ✅ exists |
| Review drift & re-pin hash | ✅ exists |
| Change risk tier | ✅ exists (still via `window.prompt()` — needs a real dialog, AdminPages.tsx:480) |
| Enable / disable an individual tool without quarantining or kill-switching | ❌ missing |
| Quarantine a tool manually (not just automatic on drift) | ❌ missing |
| Reject / permanently ban a pending tool (today: approve or pending forever) | ❌ missing |
| View a tool's full schema/description — what the admin is actually approving | ❌ missing |
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
| Set session TTL / idle timeout | ❌ missing |
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
| One-click per-server kill buttons | ✅ NEW |
| Confirmation step on global kill | ❌ missing — `engage("global")` fires directly, one click halts everything |
| Scope validation / picker for tool and user scopes | ❌ missing — still free text; a typo'd scope silently contains nothing |
| Auto-expiring containment ("kill for 1 hour") | ❌ missing |
| Who engaged it and why — require a reason string, show it on the active scope | ❌ missing |

## 9. Policies & DLP

| Control | Status |
|---|---|
| Edit rate limits (global, per-tool, per-server, login) from the UI | ❌ missing — display only (verified) |
| Manage DLP rules (enable/disable patterns, add custom regex, mask vs block) | ❌ missing |
| View DLP hits — what was masked/blocked, for whom | ❌ missing |
| Toggle registry onboarding gate, SIEM export for real | ❌ missing — Settings toggles are local state only |
| Edit the ABAC role ladder (tier ceilings per role) | ❌ missing — display only |
| Edit per-role server entitlements (`servers:` allowlists) from the UI | ❌ missing — policy.yaml only |

## 10. Alerts & Notifications

| Control | Status |
|---|---|
| View anomaly alerts | ✅ exists (+ Re-evaluate) |
| In-dashboard notification center (severity, dedupe, unread badge, mark-read) | ✅ NEW |
| Acknowledge / resolve / snooze an alert | ❌ missing — alerts just sit there |
| Configure thresholds (error rate %, latency, failed-login count) | ❌ missing |
| Delivery channels — email, webhook, Slack/Telegram for approvals and critical alerts | ❌ missing; **this is what makes everything else work when nobody's watching** |

## 11. Audit & Compliance

| Control | Status |
|---|---|
| Verify chain integrity, browse events | ✅ exists (+ Re-verify) |
| Export (CSV/JSON, time range) | ❌ missing |
| Filtering | 🟡 free-text search + event-type select; no time-range, no identity filter, no pagination (200-row silent cap) |
| Record detail view (full arguments, digests, chain hashes) | ❌ missing |
| Retention policy control (how long, archive target) | ❌ missing |

## 12. Gateway Itself

| Control | Status |
|---|---|
| Self-health page: version, uptime, memory, audit log size, config hash | ❌ missing |
| Backup status + trigger backup (Phase-0 backups exist; dashboard can't see them) | ❌ missing |
| View effective config (read-only dump of what's actually loaded) | 🟡 pieces shown on Settings / Rate Limits |
| Reload config without restart | ❌ missing |
| Maintenance mode (reject new sessions, banner for operators) | ❌ missing |

---

## Priority sequencing (next build-out)

Priorities 1–4 from the previous pass are **done and live-verified**. What remains,
ordered by blast radius:

1. **External notification delivery (email/webhook)** — the HITL queue and critical
   alerts only work if someone is staring at the dashboard. An unwatched approval
   queue isn't a gate. (Section 10; also the Phase-3 SIEM/alerting seam.)
2. **Kill-switch safety** — confirm dialog on global kill, scope pickers for
   tool/user (typos silently contain nothing), reason string, auto-expiry.
   Small work, big incident-response payoff. (Section 8)
3. **Audit usability** — export, time-range + identity filters, record detail,
   pagination past the 200-row cap. First thing an incident responder needs.
   (Section 11; the DB-state migration in Phase 2 is the natural moment.)
4. **Registry governance completeness** — reject/ban a pending tool, manual
   quarantine, view the schema being approved, real re-tier dialog. (Section 2)
5. **Policy / rate-limit / DLP editing from the UI** — convenience, after the
   safety controls exist. (Section 9)
6. **Gateway self-page** — health, backup status, effective config, maintenance
   mode. (Section 12)
