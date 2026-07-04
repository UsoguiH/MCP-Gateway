# MCP Gateway — Master Software Development Plan

> **Purpose.** The single authoritative plan for the Secure MCP Gateway: precisely **what is
> built** (verified) and **what remains** (with deliverables, acceptance criteria, dependencies,
> effort, and owners). It is the index and status tracker over the deeper documents; it does not
> duplicate them.
> **Context.** On-prem, air-gapped AI-agent platform for a ~200-person government-affiliated entity;
> data sovereignty is legally critical. NCA (ECC-2:2024 / CSCC-1:2019 / DCC-1:2022 / NCS-1:2020) +
> PDPL + NDMO binding.
> **Companion docs.** Architecture: `MCP-Secure-Architecture-v10-Final-BuildSpec.md`. Platform
> program (M1–M14): `MCP-Platform-Build-Plan.md`. Threat model: `MCP-Security-Blueprint.md`. Auth:
> `MCP-Authentication-Redesign-Plan.md`. Gateway completion: `gateway/GATEWAY-COMPLETION-PLAN.md`.
> Operations: `gateway/OPERATIONS.md`.

## Status legend
✅ **Built & verified** (in-repo, tested) · 🟡 **Partial** (dev stand-in; prod swap defined) ·
⏳ **Planned** (not started) · 🔒 **Infra-gated** (needs hardware/hosted service).

---

## 0. Executive summary

- **The gateway control-plane software is 100% complete, containerized, and verified** — 66 automated
  tests green (clean-room reproducible), Docker image builds and runs healthy, security-audited
  (12-finding pentest: **8 fixed/mitigated, 3 infra-residual, 1 accepted**).
- **What remains is infrastructure and integration**, not gateway code: real inference (vLLM+GPU),
  key custody (HSM/TPM), the hosted IdP (Keycloak), transport security (TLS/mTLS/SPIFFE), the SIEM
  product, DR, and the deferred **production MCP-server selection**. Every one has a code seam and
  config switch already in place.
- This plan sequences the remaining work into **9 workstreams (W1–W9)** mapped onto the M1–M14
  program phases, each with testable acceptance criteria.

### 0.1 Non-goals (explicitly out of scope)
- **No cloud dependency** anywhere in the trust chain (air-gap is a hard constraint, not a preference).
- **No frontier hosted models** — capability ceiling is the air gap; best verified open weights only.
- **Production MCP-server *selection*** is a separate, Risk-Board-gated project (W5); this plan builds
  the platform that onboards them, not the servers themselves.
- **The dev PKI/vault/mock-LLM are stand-ins**, not shipped credentials — production replaces them
  with HSM/TPM, OpenBao, and vLLM (never ship `dev_login_enabled: true` or the dev KEK).
- **Not a substitute** for the companion architecture/threat/compliance docs — this is the index over them.

---

## PART I — WHAT WE BUILT (✅ done & verified)

### I.0 Completion scorecard (at a glance)
| Area | Status | Evidence |
|---|---|---|
| Gateway control-plane software | ✅ **100%** | 19 Python files (18 functional), 26 routes, 75 tests green |
| Authentication (TPM+PIN 2FA) | ✅ **100%** software; 🔒 real TPM/HSM pending | pentested: 8/12 fixed/mitigated, 3 infra-residual, 1 accepted |
| Authorization / HITL / taint / DLP / audit | ✅ **100%** | full pipeline tested end-to-end |
| Credential vault + injection | 🟡 dev issuer (OpenBao seam ready) | secret never in model/audit (tested) |
| Observability (metrics, SIEM export) | 🟡 export hook built; SIEM product pending | `/api/metrics`, `siem_stream.jsonl` |
| Deployment (Docker) | ✅ **built & verified** | image 296 MB, runs healthy in-container |
| External IdP (Keycloak OIDC) | ✅ code path built & tested; 🔒 host pending | `auth.mode: oidc` |
| Inference (LLM) | 🟡 mock + `openai_compat` path; 🔒 vLLM+GPU pending | swap `llm.provider` |
| Data classification propagation (W3.3), schema hardening (W9.6), CI/fuzz/compose/dep-check/loadtest/RTL (W9) | ✅ **built & tested** | +9 tests; `classification.py`, `_validate_args`, `.github/`, `scripts/` |
| Transport (TLS/mTLS/SPIFFE), network, DR, SOC product, prod servers | ⏳🔒 planned (Part II) | seams + config ready |

**Verified 75/75 tests green and Docker image healthy at time of writing.**

### I.1 Architecture (as built)
Thin UI/agent → **FastAPI Gateway (the single Zero-Trust PEP)** → MCP servers over stdio.
The LLM only *proposes* tool calls; the gateway *disposes*. Every call traverses a fixed pipeline:
kill-switch → 3-key rate-limit → registry → circuit-breaker → Unicode sanitize → size limits →
taint → ABAC → HITL → **credential injection** → dispatch → Unicode+DLP on result → HMAC audit.

### I.2 Module inventory (18 functional modules in `gateway/app/`, + empty `__init__.py`)
| Module | Responsibility |
|---|---|
| `pki.py` | Dev CA + ES256 signing key + PIN-sealed user certs (🟡 stand-in for HSM/TPM) |
| `auth.py` | **TPM+PIN 2-factor cert auth**, ES256 cert-bound tokens, lockout, step-up, revocation, **OIDC mode** |
| `devclient.py` | Client/TPM-side challenge signing (dev) |
| `authz.py` | ABAC decision (role × clearance × tier × taint), deny-by-default |
| `taint.py` | Prompt-injection taint tracking (untrusted content → escalation) |
| `dlp.py` | Saudi National ID/Iqama/IBAN detection + checksum + clearance-gated masking |
| `classification.py` | NDMO 4-level label propagation; per-tool classification → DLP unmask threshold |
| `registry.py` | Tool risk registry, **hash-pinning/rug-pull quarantine**, onboarding governance |
| `approvals.py` | Tiered HITL, two-person + SoD, **persistent** |
| `controls.py` | Kill switch + **3-key rate limiting** (user/tool/server) |
| `vault.py` | **Per-call dynamic credential issuance** (🟡 stand-in for OpenBao) |
| `unicode_guard.py` | NFKC + bidi/zero-width stripping |
| `audit.py` | **HMAC-SHA256 hash-chained** audit + counters + SIEM export |
| `gateway.py` | Orchestrator: the full pipeline + **circuit breaker** |
| `mcp_manager.py` | MCP stdio sessions + discovery (🟡 stdio → Streamable HTTP+mTLS in prod) |
| `llm.py` | LLM adapter: `mock` \| `openai_compat` (🟡 mock → vLLM) |
| `config.py` | Loader + **startup validation** |
| `main.py` | FastAPI surface (26 routes), edge guard (origin/size/rate), auth deps |

### I.3 Security controls (built, each maps to blueprint + closed v7 flaw)
Identity 2FA (TPM+PIN, phishing-resistant) · ABAC deny-by-default · tool hash-pinning + rug-pull
quarantine · injection taint containment · tiered HITL + SoD + Tier-3 step-up · Unicode/RTL defense ·
Saudi-PII DLP with clearance gating · HMAC tamper-proof audit + SIEM export · 3-key rate limiting ·
circuit breaker · kill switch (global/server/tool/user) · identity revocation (durable) ·
anti-hammering lockout · per-call credential injection (secret never in model/audit) ·
protocol hardening (origin/size/schema-shaping) · registry onboarding governance.

### I.4 API surface (24 API routes + `/` + favicon = 26 routes; static UI mounted separately at `/ui`)
Auth (5): `/api/login/challenge`, `/api/login`, `/api/dev/login`, `/api/dev/userlist`, `/api/me`.
Core (2): `/api/tools`, `/api/chat`. HITL (3): `/api/approvals` (+approve/reject).
Admin (12): killswitch (status/engage/release), **revocations**, revoke/unrevoke/unlock, audit,
registry (+approve/approve_drift), vault. Observability (2): `/api/metrics`, `/api/health`.

### I.5 Quality & verification (built)
- **75 tests** green: 28 unit-security, 19 unit-auth, 6 fuzz, 22 end-to-end — **clean-room reproducible**.
- **Security-audited**: 12-finding pentest — **8 fixed/mitigated** (PIN-leak endpoint removed, size caps,
  origin guard, HMAC audit, durable revocation, encrypted keys-at-rest, lockout-DoS mitigated,
  login throttle) · **3 infra-residual** (mTLS terminator, TLS, real TPM) · **1 accepted** (bearer-token
  replay within the 10-min TTL — inherent to the bearer model; short TTL + revocation bound it).
- **Deployment (built & verified)**: `requirements.txt`, `Dockerfile` (non-root, healthcheck,
  runtime secrets) — image builds (296 MB) and runs **healthy** in Docker; full auth+DLP flow verified
  in-container.
- **Docs (built)**: `README.md`, `OPERATIONS.md` runbook, `GATEWAY-COMPLETION-PLAN.md`.

---

## PART II — WHAT WE WILL BUILD (remaining workstreams)

> Each item: **deliverable → acceptance test → dependency → effort (S/M/L) → owner**.
> Effort is engineering-only; hardware lead times dominate the schedule (see §III).
> `M/server` = the effort recurs **per onboarded server** (W5).

### W1 — Identity, PKI & credential hardening 🔒 (Auth plan Phases 1–2)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W1.1 | Stand up **Keycloak** realm; flip gateway `auth.mode: oidc` | gateway validates a real Keycloak JWT; RBAC by realm role | Keycloak host | M | Platform |
| W1.2 | **X.509 CBA / WebAuthn** at Keycloak; **PIV smartcard+PIN** for admins (AAL3) | login is phishing-resistant; admin = AAL3 | W1.1 | M | SecOps |
| W1.3 | **HSM (YubiHSM/Luna)** custody: CA root, token-signing, KEK; **workstation TPM** for user keys | keys non-extractable; verify CMVP cert | HSM/TPM procurement | L | Platform |
| W1.4 | **OpenBao** vault: dynamic per-backend DB creds via `hvac`; replace `vault.py` dev issuer | secret absent from context (trace-verified); short-TTL leases | OpenBao host | M | Platform |
| W1.5 | RFC 8693 **token exchange** per backend (audience-bound, no passthrough) | downstream token `aud`=server; passthrough impossible | W1.1 | M | Gateway |

### W2 — Inference tier 🔒 (Platform plan Phase 2)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W2.1 | vLLM serving; flip `llm.provider: openai_compat` | gateway plans via real model; controls still run on its calls | GPU nodes | M | AI/eval |
| W2.2 | **Model intake pipeline** (license→hash→scan→eval→sign→register) | unverified weights refuse to load | W2.1 | L | AI/eval |
| W2.3 | **Guardrail chain** (Prompt Guard 2 → Qwen3Guard) wired pre/post | injection corpus blocked at guardrail | W2.1 | M | AI/eval |
| W2.4 | **Planner/quarantine model split** (untrusted content → tool-less model → taint refs) | zero tainted-value privileged invocations (red-team) | W2.1 | L | AI/eval |

### W3 — Data protection 🔒 (Platform plan Phase 6)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W3.1 | **Arabic NER** DLP detector (3rd point) + `dlp.py` pluggable hook | Arabic PII masked; FP/FN measured vs corpus | NER model | M | Data |
| W3.2 | **Tokenization/detokenization vault** (clearance+purpose+rate, bulk=Tier3) | detokenize audited; never a model tool | OpenBao/HSM | M | Data |
| W3.3 | NDMO **classification propagation** library for data servers | every data response carries a label | — | M | Data |
| W3.4 | RAG governance rails (signed bundles, provenance→taint) | poisoned bundle rejected | — | M | Data |

### W4 — Transport & network security 🔒 (Platform plan Phases 1, 4)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W4.1 | **TLS 1.3** north; **mTLS terminator** injects verified cert thumbprint (closes pentest H1/H2) | token-theft replay fails; cleartext gone | certs/PKI | M | Platform |
| W4.2 | **Streamable HTTP + mTLS** south (gateway→servers); retire stdio in prod | each server reachable only from gateway SPIFFE id | W1.3 | M | Gateway |
| W4.3 | **SPIFFE/SPIRE (or step-ca+cert-manager)** workload identity | mutual auth on every hop; short-lived SVIDs | — | L | Platform |
| W4.4 | **Microsegmentation** + default-deny egress + air-gap verification | no east-west except gateway→server; no egress | network gear | L | Platform |
| W4.5 | Per-session **sandboxed agent runtime** (gVisor-class), egress-deny | endpoint compromise yields no tokens | — | L | Platform |

### W5 — Production MCP servers ⏳ (the deferred decision; Platform plan §10)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W5.1 | Server **selection** (org chart × systems inventory; HR/finance isolated) | Risk-Board-approved server list | — | S | Program |
| W5.2 | **Onboarding pipeline** run per server (ingress→sign→admission→eval→registry→staged) | server passes authz/injection gates before enablement | W1–W4 | M/server | Platform |
| W5.3 | In-house thin servers over raw APIs (RO-first: docs/records → HR → correspondence) | least-privilege scoped creds; label propagation | W5.2 | M/server | Domain |
| W5.4 | Retire the two reference fixtures | fixtures removed post-pilot | pilot | S | Gateway |

### W6 — SOC, observability & IR 🔒 (Platform plan Phase 7)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W6.1 | Point SIEM export → **Wazuh/OpenSearch**; WORM audit sink | events land in SIEM; audit immutable, ≥2yr, in-Kingdom | SIEM host | M | SecOps |
| W6.2 | SIEM **detection content** (first-tool-use, sequence/volume anomalies, egress bursts, drift, detok spikes, canary) | rules fire in purple-team test | W6.1 | M | SecOps |
| W6.3 | **UEBA** baselining per agent NHI; MITRE ATLAS mapping | anomalous tool chains alert | W6.1 | M | SecOps |
| W6.4 | **IR playbooks** ×4 + monthly kill-switch drill + annual tabletop | drills evidenced | — | M | SecOps |
| W6.5 | OpenTelemetry tracing + per-dept cost attribution | end-to-end trace w/ correlation ids | — | M | Platform |

### W7 — Resilience & DR 🔒 (Platform plan Phase 8)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W7.1 | Backups: `data/` + PKI/HSM escrow; key-rotation runbooks | restore drill passes | — | M | Platform |
| W7.2 | Second-site DR + HSM replication + failover | RTO/RPO drill evidenced | 2nd-site GPU | L | Platform |
| W7.3 | HA gateway (stateless core prep for MCP 2026-07-28) | round-robin behind LB; no session affinity | — | M | Gateway |

### W8 — Governance, compliance & accreditation 🔒 (Platform plan Phases 0, 9)
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W8.1 | AI Risk Board seated; policies; role-based training | governance operating | — | S | Program |
| W8.2 | **Control-ID traceability matrix** (ECC/CSCC/DCC/NCS/PDPL/NDMO) | every control → evidence | all | L | Data+SecOps |
| W8.3 | DPIA + RoPA + DSR procedures; retention schedule | filed; DSR spans logs/caches | — | M | DPO |
| W8.4 | **NCA confirmations** (EdDSA status, TLS suites, session timeouts) — see auth plan §5 | written NCA sign-off | — | S | Program |
| W8.5 | Independent **pen test** + accreditation walk (spec §13) | findings triaged; accreditation signed | all | M | SecOps |

### W9 — Gateway software backlog ✅ (BUILT & TESTED — in-repo, no infra)
> Status: **all six delivered** — CI (`.github/workflows/ci.yml`), `docker-compose.yml`,
> `scripts/check_deps.py`, parser-fuzz suite (`tests/test_fuzz.py`), `scripts/loadtest.py`,
> RTL toggle, and `additionalProperties:false` schema validation (`gateway._validate_args`).
> Only W9.4's *sizing* run (≈250 concurrent) awaits real vLLM (W2.1).
| # | Deliverable | Acceptance | Dep | Eff | Owner |
|---|---|---|---|---|---|
| W9.1 | **CI pipeline** — pytest + JSON-RPC/parser fuzzing + SBOM (Syft) + Trivy + cosign sign | CI blocks merge on red/critical; image signed | — | S | Gateway |
| W9.2 | `docker-compose.yml` — gateway + stub Keycloak/vLLM for a full local stack | `compose up` yields a working stack | — | S | Gateway |
| W9.3 | Dependency allowlist + pinned private index | non-allowlisted dep refused | — | S | Platform |
| W9.4 | Load test to `MCP-Platform-Build-Plan.md` §5 sizing (≈250 concurrent) | SLA met; degradation ladder recorded | W2.1 | M | AI/eval |
| W9.5 | Arabic-first RTL UI polish | RTL renders correctly; approver dialogs legible | — | S | Gateway |
| W9.6 | OpenAPI/schema hardening (`additionalProperties:false` on all tool/arg schemas) | unexpected fields rejected | — | S | Gateway |

---

## PART III — TIMELINE, VERIFICATION, RISKS

### III.1 Phase mapping (to `MCP-Platform-Build-Plan.md`, M1–M14)
```
M1  M2  M3  M4  M5  M6  M7  M8  M9  M10 M11 M12 M13 M14
[W8 governance/procure.......................................]
    [W1/W4 identity+air-gap+PKI/HSM.......]
            [W2 inference..........]
      [GATEWAY SOFTWARE ✅ DONE — ahead of Phase 3]
                        [W4 agents ]
                            [W2.4 quarantine + W3 data.......]
                                [W6 SOC/IR.................]
                                    [W7 DR.................]
                                            [W5 servers + W8.5 pilot/accred]
GPU ▲(M4-6)                            2nd-site GPU ▲(M10)
```
The gateway build (normally Phase-3 critical path) is **complete early**; the schedule is now
gated by procurement (GPU/HSM) and the identity/network foundation (W1/W4).

### III.2 Verification & acceptance (every phase gate is a runnable test or an auditable artifact)
- **Software:** the 66-test suite stays green in CI on every change; new workstreams add tests.
- **Gate checks:** unverified weights refuse to load (W2); over-clearance denied + secret absent from
  context (W1); token-theft replay fails under mTLS (W4); injection corpus → zero privileged
  invocations (W2.4/W3); SIEM rules fire in purple-team (W6); failover/restore drills pass (W7);
  control-ID matrix complete + independent pen test clean (W8).
- **Definition of Done (program):** pilot metrics green · accreditation signed · onboarding pipeline
  demonstrated end-to-end · reference fixtures retired.

### III.3 Top risks
GPU/HSM lead time (order M1; interim dev on 27B) · gateway *underestimated* — **mitigated: already
built** · Saudization hiring for security roles (start M1) · HITL friction (tune Tier-1 in pilot) ·
MCP 2026-07-28 stateless shift (tracked; W7.3) · production-server scope creep (Risk-Board gate, W5.1).

### III.4 Team (per `MCP-Platform-Build-Plan.md` §2)
Program lead · 3–4 platform/infra · 2–3 gateway/backend · 2 AI/eval · 2–3 SecOps · data steward + DPO.
ECC-2:2024: cybersecurity roles filled by qualified Saudi nationals (recruit M1).

### III.5 Environments, licensing & release
- **Environments:** dev (this build: mock LLM, dev PKI, `dev_login` on) → staging (real IdP/vault/vLLM,
  synthetic data) → prod (air-gapped, HSM/TPM, `dev_login` off, TLS/mTLS). Config-only differences;
  same image.
- **Licensing (all OSI-permissive / self-hostable):** Keycloak (Apache-2.0), OpenBao (MPL-2.0, avoids
  Vault BSL), step-ca (Apache-2.0), Qwen3.5 (Apache-2.0). Confirm before commit; see auth plan §5.
- **Release & change control:** version-pinned images from a private registry; signed (cosign) +
  admission-gated; every change passes the 66-test suite + CI (W9) before promotion; registry/tool
  onboarding and config changes go through the Risk-Board with segregation of duties.
- **Rollback:** image is stateless bar `data/` + `pki/`; roll back by re-pinning the prior signed image;
  revocations/approvals persist on the mounted volume, so a rollback never drops a pending approval.
- **Sizing/SLA:** capacity model in `MCP-Platform-Build-Plan.md` §5 (≈250 concurrent @ ~31 tok/s/user
  on 4× H100-class); load test is W9.

---

## Change log
- **v4** — **implemented all in-repo software from the plan**: W9 fully built (CI + parser-fuzz +
  compose + dep-allowlist + load-test + RTL + `additionalProperties:false` schema validation),
  W3.3 NDMO classification propagation (`classification.py`), W1.4 OpenBao vault adapter (config path).
  Tests 66 → **75** green (28 security + 19 auth + 6 fuzz + 22 e2e), clean-room verified; load-test
  harness run (100/100 OK). Remaining Part-II items are hardware/hosted/human (operator-provided).
- **v3** — applied an independent code-vs-plan review (6 defects fixed): corrected the sizing
  cross-ref (Platform §5, not §7); fixed the I.4 route arithmetic and added the omitted
  `/api/admin/revocations`; added "+1 accepted" to the scorecard for parity; converted W9 to a
  5-field table; defined the `/server` effort unit. Every Part-I claim independently verified against
  the code (modules, 66 tests, 26 routes, pipeline order, all features, companion docs).
- **v2** — review passes: reconciled counts (9 workstreams; 12 findings = 8 fixed/mitigated + 3
  infra-residual + 1 accepted; 17 functional modules; 24 API + 26 total routes); added §0.1 Non-goals
  and §III.5 Environments/Licensing/Release/Rollback/SLA; fixed typos. Re-verified 66/66 tests green.
- v1 — consolidated from the completion build: gateway software ✅ 100% (66 tests, Docker verified);
  remaining work organized into W1–W9 with acceptance criteria and M1–M14 mapping.
