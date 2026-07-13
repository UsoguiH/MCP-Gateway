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

### 1c. High availability & shared state (Phase 3) — `docker-compose.ha.yml`

By default the gateway keeps its state in flat files under `data/` and its runtime state
(sessions, rate windows, breaker, taint) **in one process's memory**. That is a single
instance, permanently: two of them would each grant the full rate budget, each hold half the
sessions, and race each other's JSON writes.

Setting **`MCP_STATE_DB_URL`** moves *everything* into a shared PostgreSQL database
(`gwstate`) and the gateway becomes horizontally scalable — any instance can serve any
request of any session, so no sticky routing is needed and losing a node drops nothing.

```bash
# 1. create the gwstate database + least-privilege role (writes deploy/secrets/gwstate_pw + _url)
powershell -File scripts\create_gwstate.ps1
#    (on a FRESH pgdata volume, deploy/postgres_init/02_gwstate.sh does this automatically)

# 2. migrate the existing flat-file state in (verifies the audit chain BEFORE and AFTER)
docker run --rm --network gateway_default -v gateway_gw-data:/app/data:ro \
  -v "$PWD/deploy/secrets:/run/secrets:ro" \
  -e MCP_STATE_DB_URL="$(cat deploy/secrets/gwstate_url)" \
  -e MCP_AUDIT_KEY_FILE=/run/secrets/audit_key \
  mcp-gateway:ha python scripts/migrate_state.py

# 3. run the HA pair behind the mTLS load balancer
docker compose -f docker-compose.ha.yml up --build -d
```

**Fail-closed:** if `MCP_STATE_DB_URL` is set and the database is unreachable, the gateway
**refuses to boot**. It must never silently fall back to per-instance files while an operator
believes state is shared. `/api/health` reports `state_backend`, `state_ok` and the serving
`instance`; every response also carries an **`X-Gateway-Instance`** header, which is how you
tell which node produced a given audit record or slow call.

**What is shared, and what deliberately is not.** Durable state (audit chain, approvals **and
their executed results**, registry, identities/credentials/MFA, OAuth, API keys,
notifications, containment, settings) lives in normal tables. Runtime state (MCP sessions,
rate-limit events, breaker, taint, OAuth codes, lockouts, vault leases) lives in **UNLOGGED**
tables — no WAL cost, and every row in them is re-establishable by design (a client
re-initializes; a rate window refills). Node-local files stay node-local: the SIEM mirror
(`siem_stream.jsonl`) is a per-node feed a log shipper expects to find on that node.

**Rollback is real.** `python scripts/migrate_state.py --rollback --out data.exported` writes
the DB back out to flat files — byte-identical audit JSONL, chain verifiable. Unset
`MCP_STATE_DB_URL`, restart, and you are back on files having lost nothing.

**Scaling past two nodes** ([D5]: hardware TBD): add `gateway-c` to `docker-compose.ha.yml`
(copy the `<<: *gateway` block, give it a new `MCP_INSTANCE_ID` and data volume) and add it to
the nginx `upstream`. The instances share the **`gw-pki` volume** — the token-signing key must
be identical across nodes or a token minted by A is refused by B.

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
- **gitea-mcp** (116 tools): `delete_repo` requires `confirm=true`; all writes go to the Gitea audit
  trail under the token's identity. It runs as the dedicated **`mcp-gateway` machine account** (not
  a person's personal token) with a **scoped, non-admin** token —
  `write:repository`, `write:issue`, `read:user`, `read:organization` — and is a `write`
  collaborator on only the repositories it needs. Verify least privilege after any credential
  change: the token must succeed on `/api/v1/user/repos` and be **refused `/api/v1/admin/users`
  with 403**. To re-issue: create the token as that account
  (`POST /api/v1/users/mcp-gateway/tokens`), write it to `deploy/secrets/gitea_token`, restart.
  (`GITEA_SUDO=<user>` attributes actions to a specific account but needs an admin token — do not
  use it.)
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
- **Pre-deploy tripwires — never ship with:** `auth.dev_login_enabled: true`, `auth.require_mfa: false`, `registry.require_approval: false`, or the `dev-*-change-me` values for `MCP_GATEWAY_KEK`/`MCP_AUDIT_KEY`/`MCP_VAULT_KEY` (the KEK also protects the at-rest CA keys and TOTP secrets). Under
  `MCP_ENV=production` these are **hard startup errors**, not warnings. Two more:
  - **`jsonschema` must be installed.** It enforces `additionalProperties: false` on every tool
    call. Argument validation now **fails closed** — without the library the gateway refuses
    mediated calls rather than silently waving them through. (It also blocks a call whose tool
    declares a *malformed* schema: the schema comes from the MCP server, so a deliberately-broken
    one was previously a way to switch argument validation off for that tool.)
  - **The `docs` and `actions` fixtures must be removed from `servers:`.** They are test fixtures —
    in-code sample data and an in-memory record store the e2e suite drives — and production refuses
    to start while they are registered.

## 4. Routine operations
| Task | How |
|---|---|
| **Watch health** | `GET /api/health` (status, servers, tools, pending tools, audit chain ok) |
| **Gateway self-page** | Console → **Gateway**: version, uptime, effective config, **backup status**, **certificate expiry**, disk/log growth, maintenance mode |
| **Metrics / dashboards** | `GET /api/metrics` (event counts, breaker, active leases, pending onboarding) — admin |
| **Verify audit integrity** | `GET /api/admin/audit` → `chain_ok` (incremental). **Full** re-verification from genesis: `GET /api/admin/audit/verify` or the console's **Re-verify** button |
| **Investigate** | Audit page: filter by identity / server / tool / time range over the whole chain, then **Export CSV/JSON**. Per-call durations are recorded |
| **Onboard a new tool** | it lands `pending` → **Inspect the schema** → `POST /api/admin/registry/{server}/{tool}/approve`. See §5e |
| **Reject / ban a tool** | `.../reject {"reason":"..."}` — stays inactive and re-discovery will not resurrect it |
| **Quarantine a tool on suspicion** | `.../quarantine {"reason":"..."}` — narrower than a kill switch, and durable |
| **Tool definition drift** | auto-quarantines → **read the diff** (`.../diff`) → `.../approve_drift` to re-pin |
| **Kill switch** | Console → Kill Switch: pick the scope, **give a reason (required)**, optional auto-release. `POST /api/admin/killswitch/engage {"scope":"...","reason":"...","ttl_minutes":N}` |
| **Retune a limit mid-incident** | Console → Rate Limits (global, per-tool, per-server override). Applies on the next request; no restart |
| **Maintenance mode** | Console → Gateway: pauses mediated calls for non-admins during a patch/migration. Admins keep working |
| **Revoke an identity** | `POST /api/admin/revoke {"sub":"..."}` (blocks in-flight tokens <1s; survives restart; kills their API keys too) |
| **Clear a lockout** | `POST /api/admin/unlock {"sub":"..."}` after out-of-band verification |
| **Active credential leases** | `GET /api/admin/vault` |
| **Purge test artifacts** | `python scripts/purge_test_artifacts.py` (run with the gateway stopped; also runs in CI teardown) |

**Console sessions.** Settings → *Session policy*: an **idle timeout** (default 30 min — an active
operator's session renews silently, so it only bites when they stop), an **absolute maximum**
(default 8 h, forces a real re-authentication however active they are), and an **expiry warning**
(default 2 min, with a countdown and a *Stay signed in* button). The console previously signed
people out mid-approval with no warning and no setting anywhere.

**Alerts reach the dashboard only.** The notification centre and Anomaly page are the *only* place
critical alerts surface today — read state is per operator, so one admin clearing the bell does not
hide an incident from the rest of the team. **External delivery (email / webhook) does not exist
yet**: an unwatched approval queue is not a gate. It arrives with the SIEM integration (Phase 4) and
is the single biggest operational gap in this system.

## 5. Backup & rotation
- **Back up:** `data/` (audit log, registry, approvals, revocations) and `pki/` (or the HSM/CA).
- **Rotate token-signing key:** publish new public key, overlap window ≥ token TTL, then cut over
  (prod: OpenBao Transit rotate). **Rotate audit HMAC key:** start a new chain segment, archive the old.
- **Retention:** audit ≥ 2 years, in-Kingdom, immutable (NDMO). Ship WORM copies off the gateway host.
- **Check the backup ran:** the console's **Gateway** page shows the last run, its age, size and
  retained count, and turns red past 36 h. A backup that has been failing for three weeks is
  otherwise discovered on the day it is needed.

### 5a. Restore drill (run MONTHLY — an untested backup is not a backup)

**Automated:** `powershell -File scripts\restore_drill.ps1` restores the newest backup run
into a **throwaway** postgres container + scratch directory and proves it is usable — it
restores `appdb.sql` and `gwstate.sql`, **re-verifies the restored audit chain's HMAC from
genesis**, and unpacks every `gw-data*.tgz` checking each JSON store parses. It never touches
the live stack. Point it at the offsite copy, which is the copy that actually has to work:

```powershell
powershell -File scripts\restore_drill.ps1 -From '\\nas01\mcp-backups\2026-07-12_0200'
```

A restore that has not been *executed* is a hope, not a backup — and a restore that produces a
database whose chain does not verify is a *tampering finding*, not a bad backup. Record the
wall-clock time: that is your real RTO and it belongs in the DR plan.

> **The first execution of this drill found three defects that would each have broken a real
> recovery.** None were visible from looking at the backup — the files were all there, the job
> was green. This is the entire argument for running it.
>
> 1. **The backup did not include the roles.** PostgreSQL roles live in the *cluster*, not in a
>    database, so a per-database `pg_dump` only ever *references* `mcp_app` / `gwstate` and
>    never creates them. Restoring into a fresh server died with `role "mcp_app" does not
>    exist`. `backup.ps1` now runs `pg_dumpall --globals-only` first (`globals.sql`), and the
>    restore applies it before any database.
> 2. **Restoring the globals resets the superuser's password** to whatever it was when the
>    backup was taken — so the password you started the recovery server with stops working
>    mid-restore. Expect it; do not panic and assume the dump is corrupt.
> 3. **A restored chain cannot be verified without its HMAC key.** The audit log is only
>    tamper-*evident* while you hold `deploy/secrets/audit_key`. Restore it and the records are
>    just JSON — readable, unprovable. **Back the key up separately from the data** (different
>    medium, different custody), or every archived chain becomes permanently unverifiable. The
>    drill fails loudly rather than quietly "passing" without it.

**Restore-drill log** (append one line per drill: date · source · RTO · result):

| Date | Source | Wall-clock RTO | Result |
|---|---|---:|---|
| 2026-07-13 | local `D:\Backups\mcp` (Phase-3 commissioning) | 38.7 s | **PASS** — appdb + gwstate restored; audit chain verified intact over 8,233 records; all three `gw-data*` volumes unpacked and parsed |

**Manual (full recovery of a live stack):**
1. Stop the gateways: `docker compose -f docker-compose.ha.yml stop gateway-a gateway-b`.
2. Restore `gwstate.sql` (and `appdb.sql`) into a **scratch** database first and diff row
   counts against production; never restore straight over a live database.
3. Restore the `gw-data*` and `gw-pki` volume tarballs from the chosen run.
4. Start the gateways and confirm: `/api/health` → `audit_chain_ok: true` **and**
   `state_ok: true`, operator sign-in works, and `GET /api/admin/audit/verify` re-verifies the
   whole chain from genesis.

### 5b. PKI / certificate rotation (the outage with a known date)
The **Gateway** page lists every certificate the deployment depends on with days-to-expiry and
flags anything inside 30 days. Nothing else warns you.
- **Server + client certs (mTLS):** re-issue from the org CA (or `deploy/gen_tls_certs.sh` for the
  dev CA), drop them into `deploy/tls/`, `docker compose restart proxy`. Client certs must be
  redistributed to workstations *before* the old ones lapse — plan two weeks.
- **Gateway CA (`pki/ca.cert.pem`):** rotating it invalidates every issued client cert. Stand up
  the new CA alongside the old, re-issue certs, then retire the old CA once no one presents it.
- **Order of work:** always issue-and-distribute first, cut over second. A certificate rotation done
  in the other order is an outage.

## 5c. Upgrading the gateway (and why dependencies are pinned)
0. **Rolling upgrade (HA):** with two instances behind the LB you can upgrade with no window —
   `docker compose -f docker-compose.ha.yml up -d --no-deps --build gateway-a`, wait for it to
   report healthy (nginx ejects it from rotation while it is down, and every session it was
   serving continues on `gateway-b` because sessions are shared), then repeat for `gateway-b`.
   Roll BOTH before declaring done: a fleet running two different versions against one shared
   schema is a state you do not want to debug.
1. Read the diff. Run the full suite locally: `python -m pytest tests/ -q`.
   The e2e file needs a gateway on `127.0.0.1:8800` (`python -m uvicorn app.main:app --port
   8800`) — and **kill any stale one first**: a leftover server from an earlier run keeps the
   port, so the tests silently exercise the OLD code and then time out. If `test_e2e` fails
   wholesale with `ReadTimeout`/`ConnectError`, that is what happened.
2. **Never loosen a dependency pin to make an install succeed.** `mcp` was pinned to a *range*
   (`>=1.2,<2.0`), drifted to 1.8.1, and its FastMCP began calling `issubclass()` on raw
   annotations — every connector using `from __future__ import annotations` failed to import and
   **the gateway could not boot at all**. `tests/test_servers_import.py` now guards this: it
   imports every server module and asserts its tools register. If that test fails after a bump,
   the bump is the problem.
3. Rebuild the console if you touched `dashboard/src`: `cd dashboard && npm run build`, and commit
   `ui/`. CI runs `scripts/check_ui_build.py`, which fails if the committed bundle does not match
   its source — otherwise the gateway serves a build that is not the code in the repo.
4. Deploy with `maintenance mode` on (Gateway page): mediated tool calls pause for everyone except
   admins, so you can finish the migration while still being able to fix it. The console stays up —
   unlike a kill switch.
5. Verify after: `/api/health` clean, all servers connected, chain intact, then maintenance off.

## 5d. Log growth, rotation and capacity
The audit chain and the SIEM mirror are **append-only and grow forever**. The Gateway page shows
the growth rate (bytes/day), the current size, disk headroom, and a projected exhaustion date.
- The hot path does **not** re-verify the whole chain per request (that cost 3.6 s of CPU at 6.5k
  records and grew linearly). Verification is incremental; a **full** pass runs at startup and
  whenever an operator clicks **Re-verify**. Both are cheap enough to run often — do not "optimise"
  by skipping them.
- **Rotation (file backend):** archive `audit_log.jsonl` to the WORM store at a segment boundary,
  start a new chain segment (see key rotation above), and keep the archived segment + its key so
  the old chain stays verifiable. Never truncate the live log in place — that breaks the chain
  and looks exactly like tampering.
- **Rotation (DB backend):** same rule, different mechanics. Export the segment with
  `scripts/migrate_state.py --rollback` (it writes a byte-exact, independently verifiable JSONL),
  ship that to the WORM store, then delete the archived rows **only** at a segment boundary where
  a new chain starts. `DELETE FROM audit_log` mid-chain leaves a hole the next full verification
  reports as a broken link — which is correct, and which is why you must never do it casually.
- **Capacity (DB backend):** the UNLOGGED runtime tables self-trim (`rate_events` and expired
  sessions/codes/leases are swept on write); `audit_log` is the only table that grows without
  bound. Watch it with the Gateway page's growth projection, same as the file.

## 5e. Onboarding a new MCP server (end to end)
Adding a server is a governance act, not a config edit. The gateway is built to make that
sequence unskippable.
1. **Vet the code.** Prefer servers you author. A third-party server is untrusted code with a
   credential — read it, or do not run it.
2. **Least-privilege credential first.** Create a dedicated machine account on the backend and
   issue a **scoped, non-admin** token — never a person's personal token. (Worked example: the
   Gitea connector runs as the `mcp-gateway` account with `write:repository`, `write:issue`,
   `read:user`, `read:organization`. It is refused `/admin/*` with a 403. Verify that before you
   trust it.) Put the secret in `deploy/secrets/` and reference it by `*_FILE`, never inline.
3. **Add it** from the console (Servers → **Add server**) or `POST /api/admin/servers/add`. A bad
   spec cannot wedge the gateway: the handshake is bounded and a failure returns a clean 502 with
   the likely cause, leaving the inventory unchanged.
4. **Its tools land `pending`** (`registry.require_approval: true`) and cannot be called.
5. **Review each tool before approving it.** Registry → **Inspect** shows the full description and
   input schema. Approving a hash you have not read is not governance.
6. **Set risk tiers deliberately.** The discovery heuristic guesses (reads → 0, reversible writes →
   1, send/export → 2, delete/drop → 3) and guesses conservatively, but *it does not know your
   business*. A tool that mails customers is tier 2 even if it is named `create_message`.
7. **Grant the entitlement.** A role can only reach servers listed in its `servers:` allow-list in
   `policy.yaml`. Unlisted = invisible.
8. **Watch it.** Its first calls appear in Traffic & Logs with real durations; the circuit breaker
   and per-server rate limit contain it if it misbehaves.
9. **Reject and ban** anything you are unsure of — `Reject` keeps the tool permanently inactive and
   re-discovery will not resurrect it.

## 5f. The Risk Board (who actually approves)
"Risk-Board approval" appears throughout this system — on tool onboarding, drift re-pinning, and
tier changes. It must be a **named body**, not whoever happens to be logged in. Auditors ask for
this on day one.

**Seated Risk Board (pilot).** It is constituted below from the operator accounts that exist in
this deployment, so the board is a real body with separation of duties from day one — not a
placeholder. At production, replace the pilot demo operators (`sara`/`khalid`/`noura`/`faisal`/
`admin`) with your named staff via the Identities page, keeping the same three seats and the
same rule that no one person holds two seats.

| Seat | Operator account | Role · clearance | Responsibility |
|---|---|---|---|
| Chair (security) | `admin` | admin · top_secret | Final say on tool tiers, onboarding, and residual-risk acceptance |
| Approver A | `noura` | approver · secret | Reviews tool schemas before onboarding; co-signs Tier-3 actions |
| Approver B | `faisal` | approver · secret | Reviews tool schemas before onboarding; co-signs Tier-3 actions |

The **data steward** and **service owner** functions are held by the Chair on the pilot; split
them out to named people when the operator roster is filled with real staff (a data steward who
owns which tables/documents are Secret vs Restricted, and a service owner who can veto a tool as
unnecessary). `ciadmin` is a CI/test account and is **not** a board member.

**Separation of duties is enforced in code:** a tier-3 action needs **two** approvers and the
requester may never approve their own request (`approvals.py`). That guarantee is only real if the
approvers are different *people* — do not give one person two accounts, and do not let the Chair
be the sole approver on a Tier-3 action.

**Cadence:** review the pending queue weekly. Anything sitting past its SLA shows on the Approvals
page with an aging banner and raises an alert.

## 5f-2. Performance: what the gateway actually costs per call

Measured on the Phase-3 HA stack (2 instances, shared `gwstate`, mTLS LB). Numbers are from
`scripts/loadtest.py`; the method matters more than the absolute values, because the absolute
values are dominated by where PostgreSQL lives.

**The one number to know:** *added latency ≈ (database round trips per call) × (round-trip
cost)*. The gateway makes ~10–12 DB round trips per mediated call. On the commissioning box
(Docker Desktop on Windows) a round trip costs ~5 ms, so the floor is ~50–60 ms; on a Linux
node with PostgreSQL on the same host it is ~0.1–0.3 ms, so the same code path costs a few ms.
**If added latency looks bad, count round trips and measure one — do not guess.**

Four things were found by profiling and are worth not re-introducing:

- **Never read a secret on a hot path.** `secret()` re-reads the file from the secrets mount
  every call, and on a container secrets mount that is **2.7 ms**. `statestore.enabled()` used
  to resolve the state-DB URL that way — on every store operation, dozens of times per request
  — and `audit._audit_key()` re-read the HMAC key *for every hash*, i.e. once per record while
  verifying the chain. The gateway was spending most of its "database time" reading a file
  while the database answered in 0.13 ms. Use `config.secret_cached()`.
- **Never load the signing key per request.** `pki.signing_key()` decrypted the PEM — running
  the passphrase KDF it is deliberately sealed with — on every JWT sign *and verify*. It is
  cached now. Rotation is a restart, which it already was.
- **A TTL cache must be single-flight.** When the entry lapsed, every in-flight request raced
  to reload it; the reload made each request slower, which made the TTL lapse again sooner.
  `tools/list` measured **17 s** at p50 under 40 concurrent clients because of this. One
  thread refreshes; everyone else uses the value they have.
- **Do not hold a lock across I/O.** The audit chain must serialize on one global lock (that is
  what makes it tamper-evident), but it held that lock for a read *and* a commit. Appends are
  now **group-committed**: one writer thread batches everything queued, takes the lock once,
  and commits once. Callers still block until their record is durable — durability is
  unchanged — but the per-record cost collapses under load.

**Known open item:** the standing SLO (p95 added latency ≤ 150 ms at 300 concurrent) is **not
yet proven**. Measured p95 on the commissioning box is ~650 ms at 7 sessions and ~420 ms at 40,
against a ~5 ms/round-trip database. The 300-session run is deferred to real hardware, where
the round-trip cost — the dominant term — is 20–50× lower. `scripts/loadtest.py --provision
300` is written and ready; run it on the Phase-3 nodes when [D5] delivers them.

**Load-testing the gateway from one machine hits its own defences.** The per-IP login throttle
(`login_rate_per_minute`) correctly treats N simultaneous logins from one source as credential
stuffing — real users arrive from N different workstations. The harness backs off and retries;
do not "fix" this by weakening the control.

## 5g. Losing a node, and losing the state database (HA failure modes)

**A gateway node dies.** Nothing happens to users. nginx ejects it from rotation within seconds
(`max_fails=3 fail_timeout=10s`) and every in-flight session continues on the surviving node,
because sessions live in `gwstate`, not in the dead process. *Verified 2026-07-12: 12/12 calls
on one live MCP session served without a single error while its instance was `docker kill`ed
mid-session.* Restart it (`docker compose -f docker-compose.ha.yml up -d gateway-b`); it
rejoins rotation automatically and re-syncs the server inventory within one 30 s sweep.

nginx retries a *connect* failure on the other upstream but **never replays a request that
already reached an instance** (`proxy_next_upstream error timeout`) — a tool call must never
double-execute.

**The state database dies.** This is the single point of failure the HA design buys down to,
and it is deliberate: the alternative (a second shared store, e.g. Redis) is another thing a
2–4 person team must operate. Both gateways will report `state_ok: false` on `/api/health`,
the healthcheck marks them unhealthy, and mediated calls fail closed. Recovery is the restore
drill (§5a). **When [D5] delivers hardware, the first thing to make redundant is this
database** (streaming replica + automatic failover), not a third gateway node.

## 6. Incident response (first move = contain at the gateway)
1. **Compromised agent/identity:** `POST /api/admin/revoke`; `killswitch user:<sub>`.
2. **Compromised/misbehaving server:** `killswitch server:<name>` (the circuit breaker also auto-opens
   after repeated failures); pull its registry entry.
3. **Injection suspected:** taint + HITL already gate writes; review `credential_injected` and
   `approval_*` events; rotate any exposed backend credentials (leases are short-lived).
4. Reconstruct via correlation ids in the SIEM stream. Run ≥1 tabletop/year (injection → HR/finance
   read → exfil attempt via the actions server).

**In HA, containment is fleet-wide and immediate.** A kill switch, revocation, quarantine or
drain applied on *any* instance is enforced by *every* instance within ~1 s (the shared
containment tables carry a 1 s read cache). You do not have to find "the right node" during an
incident, and you must not assume a contained node is the only one that mattered. Every
response carries `X-Gateway-Instance`, and audit records name the instance — use them to
correlate, not to decide where to click.

## 7. Production readiness — operator-provided (see `GATEWAY-COMPLETION-PLAN.md` §B)
Client LLM hosts + a brokered confidential-compute GPU (inference is client-side, off the gateway);
HSM + workstation TPM; Keycloak host (`auth.mode: oidc`); TLS 1.3 + mTLS terminator
+ SPIFFE; SIEM product; DR site + offline backups; air-gap network + admission control; Arabic NER
model. The gateway software is complete and seams are ready for each.
