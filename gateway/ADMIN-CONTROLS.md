# MCP Gateway — Admin Control Surface

Everything an admin should be able to control from the dashboard, organized by domain.
Grounded in the current architecture: risk tiers 0–3, hash-pinned registry, HITL
approvals, credential vault, HMAC-chained audit, OAuth clients.

**Status legend**
- ✅ exists — backend **and** UI have it today
- 🟡 partial — some of it exists, or backend exists but no UI
- ❌ missing — not available anywhere

Reviewed: 2026-07-09. **Build-out of priorities 1–4 shipped** (real API keys +
OAuth client management, operator lifecycle + session/MFA control, server
lifecycle, in-dashboard notification center). Items delivered are marked ✅ NEW
below; the remaining ❌ items are the not-yet-built backlog (priorities 5–6).

Delivered this pass:
- **API keys** — real issue/revoke, scoped (read/standard/full → tier cap), bound
  to an operator, hashed at rest, one-time token reveal, enforced on `/mcp`.
  Backend `app/apikeys.py`, UI `dashboard/src/app/AccessPages.tsx`.
- **OAuth clients** — full inventory + revoke (kills refresh tokens) on the same page.
- **Operators** — create (with one-time temp password + TOTP enrollment), offboard,
  change role/clearance, force password reset, enroll/reset MFA, sign-out-everywhere,
  terminate a single MCP session. `app/auth.py` lifecycle + `AdminPages.tsx`.
- **Servers** — restart / stop / start / drain / breaker-reset / add / remove from the
  Manage drawer, persisted across restarts. `app/mcp_manager.py`, `app/gateway.py`.
- **Notifications** — in-dashboard right-panel feed (severity, dedupe, unread badge,
  mark-read/clear) driven off the audit chain. `app/notifications.py`, `notify.tsx`.
- Tests: `tests/test_admin_controls.py` (11 passing).

---

## 1. Servers

| Control | Status |
|---|---|
| View status, tools, breaker state, tier breakdown | ✅ exists (read-only Manage drawer) |
| Restart / stop / start a server process | ❌ missing |
| Reset circuit breaker (force-close after fixing the cause) | ❌ missing |
| Enable / disable (drain) a server — stop new calls, let in-flight finish | ❌ missing |
| Add / remove / edit a server (command, env, transport) without editing config files and rebooting the gateway | ❌ missing |
| Kill-switch a server | ✅ exists (Kill Switch page) |
| Set per-server rate limit override | ❌ missing (global config only) |

## 2. Tools (Registry)

| Control | Status |
|---|---|
| Approve onboarding of new tools | ✅ exists |
| Review drift & re-pin hash | ✅ exists |
| Change risk tier | ✅ exists (via `window.prompt()` — needs a real dialog) |
| Enable / disable an individual tool without quarantining or kill-switching | ❌ missing |
| Quarantine a tool manually (not just automatic on drift) | ❌ missing |
| Reject / permanently ban a pending tool (today: approve or pending forever) | ❌ missing |
| View a tool's full schema/description — what the admin is actually approving | ❌ missing |
| Per-tool allowlist by role/clearance (e.g. `drop_table` only for DBAs regardless of tier) | ❌ missing |
| Argument constraints / guardrails (e.g. `delete_rows` must include a WHERE; `send_message` only to internal domains) | ❌ missing |

## 3. Identities & Operators

| Control | Status |
|---|---|
| Revoke / restore identity | ✅ exists |
| Unlock after failed-login lockout | ✅ exists |
| Create a new operator | ❌ missing |
| Delete / offboard an operator | ❌ missing |
| Change role and clearance (ABAC ladder is display-only) | ❌ missing |
| Force password reset (set `password_change_required`) | ❌ missing |
| Enroll / reset MFA | 🟡 backend endpoint exists (`POST /api/admin/mfa/{username}/enroll`), no UI |
| View an operator's active sessions and last login | 🟡 Sessions page shows activity, not auth state |
| Grant / revoke approver status (`can_approve`) per person | ❌ missing |

## 4. Sessions & Clients

| Control | Status |
|---|---|
| View live sessions and per-identity forensic timeline | ✅ exists |
| Terminate a specific session/token immediately | ❌ missing — only full identity revoke or kill switch |
| Terminate all sessions for a user ("sign them out everywhere") | ❌ missing |
| Set session TTL / idle timeout | ❌ missing |
| Approve / block a new MCP client on first connect (client allowlisting) | ❌ missing |

## 5. OAuth / API Credentials

| Control | Status |
|---|---|
| List registered OAuth clients (from `/oauth/register`) | ❌ missing entirely from UI |
| Revoke an OAuth client or its tokens | ❌ missing |
| Create / revoke API keys with scopes and expiry | ❌ **current API Keys page is client-side mock — top priority** |
| Rotate the gateway's own signing/HMAC secrets | ❌ missing |

## 6. Vault (Managed Credentials)

| Control | Status |
|---|---|
| View which credentials the gateway holds (name, target, age — never the secret) | 🟡 backend `/api/admin/vault` exists, no UI |
| Rotate a credential | ❌ missing |
| Add / remove a credential | ❌ missing |
| Alert on credential age (e.g. Gitea token > 90 days) | ❌ missing |

## 7. Approvals (HITL)

| Control | Status |
|---|---|
| Approve / reject pending calls, two-person + SoD | ✅ exists |
| Approval history — who approved what, when, both signers | ❌ missing (only raw audit stream) |
| Expire stale requests (auto-reject after N hours) + manual "reject all" | ❌ missing |
| Delegate approval authority (on-call schedule, vacation) | ❌ missing |
| Configure which tiers require approval and how many signers | ❌ missing — hardcoded policy |

## 8. Kill Switch & Containment

| Control | Status |
|---|---|
| Engage / release global, server, tool, user scopes | ✅ exists |
| Confirmation step on global kill | ❌ missing — one click halts everything |
| Scope validation / picker (choose from real users/tools instead of free text) | ❌ missing — a typo'd scope silently contains nothing |
| Auto-expiring containment ("kill for 1 hour") | ❌ missing |
| Who engaged it and why — require a reason string, show it on the active scope | ❌ missing |

## 9. Policies & DLP

| Control | Status |
|---|---|
| Edit rate limits (global, per-tool, per-server, login) from the UI | ❌ missing — display only |
| Manage DLP rules (enable/disable patterns, add custom regex, mask vs block) | ❌ missing |
| View DLP hits — what was masked/blocked, for whom | ❌ missing |
| Toggle registry onboarding gate, SIEM export for real | ❌ missing — Settings toggles are local state only |
| Edit the ABAC role ladder (tier ceilings per role) | ❌ missing |

## 10. Alerts & Notifications

| Control | Status |
|---|---|
| View anomaly alerts | ✅ exists |
| Acknowledge / resolve / snooze an alert | ❌ missing — alerts just sit there |
| Configure thresholds (error rate %, latency, failed-login count) | ❌ missing |
| Delivery channels — email, webhook, Slack/Telegram for approvals and critical alerts | ❌ missing entirely; this is what makes everything else work when nobody's watching |
| Nav badge + auto-refresh for pending approvals and critical alerts | ❌ missing |

## 11. Audit & Compliance

| Control | Status |
|---|---|
| Verify chain integrity, browse events | ✅ exists |
| Export (CSV/JSON, time range) | ❌ missing |
| Time-range + identity + full-text filtering, pagination | ❌ missing (200-row silent cap) |
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

## Priority sequencing

The dashboard is strong on **observation** and the three security verbs it was built
around (approve, quarantine, kill) — almost everything else is read-only glass: the
admin can see problems but has to SSH somewhere to fix them.

Ordered by blast radius:

1. **Real API key / OAuth client management** — the current API Keys page revokes
   nothing; a "revoked" leaked key keeps working.
2. **Session termination + MFA enroll + operator lifecycle** — contain a person, not
   just a scope.
3. **Server actions** — breaker reset, disable/drain, restart.
4. **Notification delivery** — an unwatched HITL queue isn't a gate.
5. **Policy / rate-limit editing** — convenience, after the safety controls exist.
