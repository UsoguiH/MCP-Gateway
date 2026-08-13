# MCP Platform Build Plan — Everything Except the MCP Servers

> Companion to `MCP-Secure-Architecture-v10-Final-BuildSpec.md`. This plan builds the **platform**: identity, air-gap supply chain, inference, gateway, agent runtime, injection containment, HITL, data-protection services, audit/SOC, DR, and governance.
> **Explicitly deferred by decision:** which MCP servers/tools to run. §10 prepares that future decision (selection criteria, onboarding pipeline, interface contract) so servers slot in later with zero platform rework.
> Dates assume program start = **M1 (month 1)**. Durations are engineering estimates for a ~300-person government entity with the §2 team; adjust after Phase 0 procurement realities.

---

## 1. Scope

**In scope (build now):**
1. Program setup: governance, compliance filings, procurement, hiring.
2. Air-gap foundation: network segmentation, on-prem identity, PKI/HSM, media-ingress station, private registries, offline signing + admission control.
3. Inference tier: GPU cluster, vLLM serving, model intake pipeline, model registry, guardrail models, eval harness.
4. MCP Gateway control plane (built against the MCP spec, tested with **reference test servers** — see below).
5. Server-side agent execution tier + thin clients.
6. Injection containment (planner/quarantine split, taint tracking) + tiered HITL.
7. Data-protection platform services: tokenization/detokenization vault, 3-point DLP, classification tooling. (These are prerequisites the future data MCP servers will call.)
8. Audit/WORM → SIEM, SOC detection content, IR playbooks, red-team harness.
9. DR site, drills, backups.
10. Governance, training, accreditation evidence, pilot.

**Deferred (next project):** selection and build of production MCP servers (which systems to expose, which tools, which vendor/OSS servers). §10 is the prepared runway.

**Bridge — reference test servers:** you cannot test a gateway with zero servers. Phase 3 includes two throwaway **test fixtures** built in-house (~1 week each): a read-only "echo/docs" MCP server and a mock "write-action" MCP server (fake CRM-style writes). They exist only to exercise authZ, audit, HITL, quarantine, and kill-switch paths end-to-end. They are **not** the production server decision and get deleted after the pilot.

---

## 2. Team, roles, hiring (start Phase 0 — longest human lead time)

| Role | FTE | Notes |
|---|---|---|
| Program lead / service owner | 1 | Owns plan, phase gates, Risk Board secretary |
| Platform/infra engineers | 3–4 | K8s, network, registries, ingress station, DR |
| Gateway/backend engineers | 2–3 | The bespoke control plane (§ Phase 3) — strongest hires |
| AI/eval engineer | 2 | Serving, model intake, eval harness, guardrails, red-team |
| SecOps | 2–3 | May be existing SOC; SIEM content, IR, PAM, detection |
| Data steward + DPO liaison | 1 | Classification binding, DPIA/RoPA, DSR |
| **ECC-2:2024 constraint** | — | Cybersecurity positions must be filled by qualified **Saudi nationals** — start recruiting M1; this is a schedule risk, not paperwork |

**Governance (seat in M1):** AI Risk Board — CISO delegate, data office, legal/DPO, service owner. Owns risk-tier approvals, model intake approvals, policy changes, exceptions, residual-risk acceptance (R1–R7).

---

## 3. Phase 0 — Program setup & long-lead items (M1–M2, some tracks run through M6)

| # | Task | Owner | Output |
|---|---|---|---|
| 0.1 | **GPU procurement order** — 2× (4–8× H100/H200) nodes primary + DR decision (full vs. degraded capacity), guardrail/embedding sidecar node, spares. Lead time 3–6 months: **order in M1.** | Platform | PO + delivery schedule |
| 0.2 | **DGA cloud-exception filing** via RAQMI (grounded in CSCC critical-system restriction) | Program lead | Filed exception (≈25-day decision) |
| 0.3 | **DPIA + RoPA started**; PDPL scoping with DPO | Data steward | Draft DPIA |
| 0.4 | HSM procurement (2 sites), WORM storage, media-ingress hardware (scan station, one-way transfer), network gear | Platform | POs |
| 0.5 | Hiring/Saudization plan; SOC integration agreement | Program lead | Staffing plan |
| 0.6 | **Model license & legal review** (Qwen3.5 Apache-2.0 primary; Fanar-2/Falcon-H1 sidecars; guardrail set) + open engagement with HUMAIN re: ALLaM roadmap | AI + legal | Approved model list v1 |
| 0.7 | Facility readiness: power/cooling for GPU nodes at both sites | Platform | Site survey |
| 0.8 | Baseline the accreditation traceability matrix skeleton (ECC-2:2024, CSCC-1:2019, DCC-1:2022, NCS-1:2020, PDPL, NDMO, DGA, SDAIA AI instruments) | Data steward + SecOps | Empty matrix, control IDs enumerated |

**Gate 0:** Board seated, GPUs ordered, RAQMI filed, hiring underway.

---## 4. Phase 1 — Air-gap foundation & supply chain (M2–M5)

The real perimeter. Everything else depends on it.

1. **Network:** physical air-gap verification; micro-segments (clients / agent sandboxes / gateway / inference / data services / DMZ / audit); deny-by-default east-west; one mTLS mechanism chosen (identity-aware CNI, Cilium-class, **or** mesh — not both).
2. **Identity:** on-prem IdP (Keycloak or AD FS against existing AD); OIDC everywhere; MFA; PAM/JIT deployment; two-person rule wiring for HSM/kill-switch/ingress-approval.
3. **PKI & keys:** private CA; HSM initialization (both sites), key ceremony (two-person, recorded); NCS-1:2020-compliant algorithm choices.
4. **Media-ingress station:** isolated scan host → signature/hash verification against out-of-band manifests → import; two-person approval workflow; evidence records; one-way low→high enforcement.
5. **Private registries:** Harbor-class for containers; model registry; OPA policy repo; offline CVE mirror; injection-corpus mirror. Offline signing: key-based cosign / private CA (no public Fulcio/Rekor).
6. **Admission control:** Kyverno/Gatekeeper — unsigned = refused, cluster-wide.
7. Secrets: Vault **or** OpenBao (license review decides) with dynamic-secrets engines; HSM-backed auto-unseal/root.

**Gate 1 (acceptance):** unsigned artifact refused; no internet route from any production segment (scanner evidence); ingress import produces a signed evidence record; PAM session recording works.

---

## 5. Phase 2 — Inference tier (M4–M7; starts when first GPU node lands)

1. **Model intake pipeline** (the runway for every future model): license check → provenance/hash verification → format scan → eval battery (capability, Arabic quality, safety, backdoor probes) → signed model-registry entry → staged rollout. Run it for real on the v1 portfolio: **Qwen3.5 primary; Qwen3.5-27B quarantine instance; Qwen3Guard-Gen-8B (+Stream); Prompt Guard 2 86M; embedding model; optional Fanar-2-27B.**
2. **Serving:** vLLM, priority scheduling, per-department quotas (enforced at AI-gateway layer); telemetry off (`VLLM_NO_USAGE_STATS=1`, `DO_NOT_TRACK=1`, `HF_HUB_OFFLINE=1`) and verified by egress-deny logs.
3. **Eval harness v1** (offline): promptfoo/garak/PyRIT-class + org Arabic corpus (build starts here — Arabic injection + Arabic PII test sets are org-built assets, budget ~4 engineer-weeks).
4. Capacity baseline: load test to the §7 sizing figures (≈250 concurrent @ ~31 tok/s/user on 4× H100-class FP8); document degradation ladder.
5. **CC decision executed:** CPU CC if hardware supports; GPU CC deferred (no supported offline attestation — R7) — Board records the decision.

**Gate 2:** unverified weights refuse to load; eval baseline recorded; 300-user load test passes SLA; zero outbound connection attempts logged.

---

## 6. Phase 3 — MCP Gateway control plane (M4–M9; the core build, overlaps Phase 2)

**Base decision (M4, ~2-week spike):** evaluate IBM ContextForge, Docker MCP Gateway, agentgateway, Lasso as a base vs. from-scratch. Recommendation: take the best-fit OSS base for MCP protocol plumbing; the differentiating layers below are custom regardless.

Build order:
1. Protocol core on **MCP spec 2025-11-25** (plan the 2026-07-28 stateless-core adoption as a tracked change): strict schema validation (args **and** results), size/recursion/time limits, identity-bound sessions (never authentication), 403 on bad Origin, no token passthrough.
2. **ABAC enforcement point:** OPA/Rego; decision = role × clearance × NDMO label × tool tier; deny by default; policy unit tests in CI.
3. **Vault credential injection:** per-call, per-tool dynamic secrets; secrets never in model context (trace-verified test).
4. **Tool risk registry:** gateway-owned tiers (0–3); tool-definition **hash pinning**; drift → auto-quarantine. Built now, populated later when real servers arrive.
5. **Unicode defense:** NFKC normalization, bidi/zero-width stripping at every boundary; homoglyph checks.
6. **Caches** partitioned by (user, clearance, classification).
7. Rate limits, quotas, circuit breakers, **kill switch** (per-tool/user/server/global; two-person for global).
8. **Minimized WORM audit → SIEM:** hashes + tokenized excerpts default; full payload only Tier ≥2, field-encrypted.
9. **SDL:** memory-safe language; parser fuzzing in CI; dependency allowlist; independent pen test booked for M9.
10. **Reference test servers** (the two fixtures from §1) to exercise everything above.

**Gate 3:** over-clearance call denied; secret absent from context; mutated tool definition auto-quarantines; oversized/malformed result rejected; fuzzer runs clean in CI; pen-test findings triaged.

---

## 7. Phase 4 — Agent execution tier + clients (M7–M9)

1. Per-session sandboxed agent runtimes (container + syscall filtering, gVisor-class), egress-deny, one per user session, wiped on end; only sandboxes reach the gateway.
2. Thin client (web UI, Arabic-first RTL): renders chat + HITL approval UI; holds no tokens/context.
3. Endpoint posture: managed + EDR (existing ECC estate); endpoints are not trust anchors.

**Gate 4:** endpoint-compromise simulation yields no tokens/context; sandbox cannot reach non-allowlisted hosts; session isolation verified.

---

## 8. Phase 5 — Injection containment + HITL (M8–M11; the hardest engineering)

1. **Planner/quarantine split:** privileged planner (Qwen3.5) sees only trusted input, emits typed plans; quarantine instance parses untrusted content; outputs enter plans as **taint-labeled opaque references**.
2. **Taint/capability engine in the gateway:** tainted values cannot flow into Tier ≥2 action parameters without human approval of resolved values.
3. **HITL tiers 0–3:** OPA-policy auto-approval for Tier 1; normalized-text diff previews (Tier 2); two-person (Tier 3); approver ≠ requester; approval dashboards; **canary-approval program** (monthly deliberately-wrong requests; misses trigger retraining).
4. Guardrail chain wired: Prompt Guard 2 first-pass → Qwen3Guard on I/O → policy engine.
5. **Red-team acceptance:** Arabic + English + Unicode-obfuscated injection corpus vs. the test-fixture servers; target = zero tainted-value privileged invocations; suite becomes a CI regression gate.

**Gate 5:** injection corpus passes; bidi-spoofed preview detected; Tier-3 without two approvers impossible; canary program live.

---

## 9. Phase 6–8 — Data services, SOC, DR (parallel tracks, M8–M13)

**Phase 6 — Data-protection services (M8–M11):**
- Tokenization/FPE service + **detokenization vault** (clearance + purpose + rate-limit + audit; bulk = Tier 3; never exposed as an MCP tool); keys in HSM.
- **3-point DLP pipeline** (user↔gateway, tool-results→context, model-output→user): deterministic validators (National ID/Iqama/SA-IBAN) + Arabic NER; clearance-gated unmasking; FP/FN measured against the Arabic PII corpus.
- Classification tooling: NDMO four-level labels (Top Secret/Secret/Restricted/Public), classification register, label propagation library that future data MCP servers must use (part of the §10 contract).
- Knowledge/RAG governance rails: signed bundles, provenance-gated writes, versioned index — built even though corpus content arrives with the future servers.

**Phase 7 — SOC & IR (M9–M12):**
- SIEM content pack: first-tool-use per user, sequence anomalies, volume/token spikes, egress-deny bursts, approval bypass, tool drift, detokenization spikes, canary access, quarantine-breach (P1).
- IR playbooks ×4 (injection, model-behavior, tool compromise, agent-mediated exfiltration); kill-switch drill monthly from first drill in M10.
- OpenTelemetry tracing end-to-end + per-department cost/GPU attribution.

**Phase 8 — DR (M10–M13, gated on second-site GPU delivery):**
- Second site build-out; HSM replication + key escrow (two-person); offline immutable backups (weights, registries, WORM copies); private link.
- **Drills:** failover to RTO/RPO, restore-from-backup, kill-switch — all evidenced for CSCC.

**Gates 6–8:** raw PII absent from traces end-to-end; unmasking audited; SIEM rules fire in purple-team test; failover + restore drills pass.

---

## 10. Phase 9 — Pilot, accreditation, and the prepared MCP-server runway (M12–M14)

1. **Pilot:** 20–30 users, test-fixture servers + pure-chat/RAG-less use; measure latency, HITL friction, guardrail FP rates; fix; expand to all 300 for chat-grade use.
2. **Accreditation:** traceability matrix completed with phase-gate evidence; DPIA/RoPA finalized; training delivered (users / approvers / admins); acceptance criteria §13 of the spec walked with the compliance team.
3. **The deferred decision, prepared** — when you're ready to choose MCP servers, everything below already exists:
   - **Interface contract** every production server must meet: MCP spec 2025-11-25+, SPIFFE identity, signed image + SBOM through media-ingress, tool definitions hash-pinned, NDMO label propagation on all data responses, least-privilege scoped credentials from the vault, read-only default.
   - **Selection criteria checklist:** in-house thin server over raw API exposure; vendor/community code = untrusted → DMZ or rebuild; tool surface minimalism; Arabic data handling; auditability.
   - **Onboarding pipeline (already built):** ingress → sign → admission → eval gates (injection/authz) → Risk Board tier assignment → registry entry → staged enablement per department.
   - First candidates to evaluate then (typical for a gov entity): document/records search (RO), HR self-service (RO→RW), correspondence drafting, ticketing/ITSM, data-warehouse RO analytics — **decision deferred as agreed.**

**Gate 9 / Program done:** pilot metrics green; accreditation signed; server-onboarding pipeline demonstrated end-to-end on a test fixture; test fixtures retired.

---

## 11. Timeline summary

```
M1  M2  M3  M4  M5  M6  M7  M8  M9  M10 M11 M12 M13 M14
[P0 setup+procure]
    [P1 air-gap foundation]
            [P2 inference        ]
            [P3 gateway                  ]
                        [P4 agents  ]
                            [P5 injection+HITL      ]
                            [P6 data services       ]
                                [P7 SOC/IR          ]
                                    [P8 DR              ]
                                            [P9 pilot+accred]
GPU delivery ▲(M4–6)                 2nd-site GPUs ▲(M10)
```
**≈14 months to platform-ready.** Critical path: GPU procurement → Phase 2 → Phase 5. If GPUs land early, pull Phases 2/5 left. MCP-server selection project starts any time from M12 (criteria ready), production servers onboard from M14.

## 12. Top program risks

| Risk | Mitigation |
|---|---|
| GPU lead time slips | Order M1; interim dev on small node (27B-class models) keeps Phases 3/5 unblocked |
| Saudization hiring for security roles | Start M1; SOC outsourcing to approved provider as bridge |
| Gateway underestimated (most common failure) | OSS base spike M4; 2–3 dedicated engineers; pen test booked early; scope discipline — registry/HITL/taint before nice-to-haves |
| HITL friction sours pilot users | Tier-1 auto-approval tuned during pilot; approval-latency SLO |
| MCP spec 2026-07-28 shift mid-build | Tracked change from day 1; stateless core reduces gateway state — adopt at Phase 3 midpoint if final |
| SDAIA Responsible AI Policy enacted mid-program | Registration/audit artifacts already produced by design (§9 of spec) |
