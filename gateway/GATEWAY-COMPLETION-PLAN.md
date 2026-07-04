# MCP Gateway — Completion Plan (to 100% software-ready)

> **STATUS: §A COMPLETE.** All A1–A13 built and verified — 66 tests green (46 unit + 20 e2e),
> clean-room reproducible from an empty state. §B remains operator-provided infrastructure.


> Target: a **production-ready gateway control plane** for a ~200-person government entity.
> Honest scope split: **§A is software I build and verify now**; **§B is operator-provided
> infrastructure** the code is made ready for (seams + config), which cannot be provisioned
> on a dev box (GPU, HSM/TPM, Keycloak host, mTLS network, DR site, SIEM product).
> Definition of done for §A: no stubs, persistent where it must be, config-driven, fully tested,
> deployable. Every item below has a "done when" and a test.

## Current status (already built + verified, 60 tests green)
Auth (TPM+PIN cert, hardened, pentested), ABAC/authz, taint tracking, DLP (Saudi ID/Iqama/IBAN),
tool registry + hash-pinning/rug-pull, HITL tiers + SoD, kill switch, Unicode guard,
HMAC-chained audit, MCP stdio manager, inbound MCP endpoint (POST /mcp), 2 reference servers, UI.

## §A — Software to complete (build now, in order)

| # | Gap | Done when | Test |
|---|---|---|---|
| A1 | **Persist HITL approvals** (in-memory today → lost on restart) | approvals survive restart; pending list reloads | restart test |
| A2 | **Persist taint** per session (optional) + **lockouts** note | taint durable across restart within session TTL | unit |
| A3 | **Vault credential injection** — real dev vault; per-(server,user) short-lived creds injected into the tool call, never model context; audited | a credential-requiring tool receives injected creds; secret absent from audit/model | e2e |
| A4 | **Registry governance workflow** — `require_approval` mode: new tools land `pending`, admin approves | new tool not callable until approved when mode on | e2e |
| A5 | **Rate limiting (3 keys)** — per-user + per-tool + per-server | per-tool and per-server limits enforced | unit + e2e |
| A6 | **External-IdP (OIDC/Keycloak) auth mode** — `auth.mode: builtin｜oidc`; validate Bearer JWT via JWKS, map claims→{sub,role,clearance} | oidc mode validates a Keycloak-style token; builtin unchanged | unit |
| A7 | **Config validation on startup** — required keys/types checked, clear errors | bad config fails fast with a readable message | unit |
| A8 | **Circuit breaker** — per-server consecutive-failure tracking → auto-open + cooldown | failing server auto-opens, recovers after cooldown | unit |
| A9 | **Observability** — `/api/metrics`, richer `/api/health`, **SIEM export hook** (audit → configurable sink) | metrics counts, health detail, audit mirrored to sink | e2e |
| A10 | **Session hardening** — `MCP-Protocol-Version` handling; CSPRNG session ids bound to user | protocol-version negotiated; session id per-user | e2e |
| A11 | **Deployment artifacts** — `requirements.txt`, `Dockerfile`, `.dockerignore`, `.gitignore`, run script | image builds; server starts from it | build check |
| A12 | **Ops docs** — README overhaul + `OPERATIONS.md` runbook (backup, rotate, kill, onboard server) | runbook covers each control | review |
| A13 | **Test coverage** — every A-item tested; suite stays 100% green | full suite green | pytest |

## §B — Operator-provided infrastructure (seams ready, documented, NOT buildable here)
Client-side LLM hosts + a brokered confidential-compute GPU (inference runs off the gateway, which
connects clients via the inbound MCP endpoint); HSM + workstation TPM (swap `MCP_GATEWAY_KEK`
→ HSM, PKI → OpenBao/step-ca); Keycloak host (swap `auth.mode: oidc`); TLS 1.3 + mTLS terminator
+ SPIFFE (south/north transport); SIEM product (point A9 sink at it); DR site + offline backups;
air-gap network + admission control; Arabic NER model (DLP third detector); confidential computing.
Each maps to `MCP-Platform-Build-Plan.md` phases.

## Build discipline
Build A1→A13 in order; run the full test suite after each; do not proceed on red.
Clean-room verify (fresh state) at the end. Report honest status of §A (done) vs §B (operator).
