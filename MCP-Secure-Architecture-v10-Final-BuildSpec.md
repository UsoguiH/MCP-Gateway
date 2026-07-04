# Secure MCP Architecture — v10 FINAL Build Specification

> **Air-gapped · NCA CSCC-designated · self-hosted open-weight inference · Saudi government entity · ~300 employees.**
> Supersedes v7. Derivation: v7 was adversarially critiqued (38 flaws, see `MCP-v7-Critique.md`); v8 and v9 closed them in two passes (see `MCP-Iteration-Ledger.md`); v10 closed the remainder and passed a final critique with no design-level findings. The stopping criterion is §2 (threat→control completeness) + §12 (residual risks bounded by 2026 technology, not by design).
> All time-sensitive claims verified against primary sources as of **2026-07-02**: MCP spec 2025-11-25 + 2026-07-28 RC changelogs, NCA/SDAIA/DGA/NDMO instruments, model cards and licenses, NVIDIA CC documentation, published injection-defense research.

---

## 0. How to use this document

1. Read fully before building; controls are layered and cross-referenced to threats (T#) and to the v7 flaws they close (A#/B#/C#/D#).
2. All prior open variables are resolved: **government, non-financial (no SAMA) · CSCC applies · fully air-gapped on-prem · self-hosted open-weight models · ~300 users.**
3. Build in phases (§11). Each phase has runnable acceptance tests.
4. The two components to get right, in order: **(1) the MCP Gateway control plane (§4.4–4.6), (2) the media-ingress supply chain (§4.11)** — the second is what makes an air-gapped architecture actually air-gapped.
5. A control the operating team cannot run is a defect (§8.1). Prefer fewer, integrated components over best-of-breed sprawl.

---

## 1. Context & constraints (confirmed)

- Saudi government entity, ~300 employees; design headroom to ~600.
- **NCA CSCC** designated critical system → CSCC + ECC controls mandatory; SAMA CSF out of scope (non-financial); **PDPL/SDAIA** applies to personal data; **DGA** standards apply (government entity); national data classification policy applies (§9).
- **Fully air-gapped**: production has no internet path, ever. All ingress/egress of software, models, and security content happens through the controlled media-ingress process (§4.11). "Data residency" is trivially satisfied; the *real* sovereignty control is what crosses the gap on media.
- Priority: security → operability → performance → cost. Arabic-first (UI, PII detection, evaluation, adversarial testing).

---

## 2. Threat model (the definition of done)

Fifteen threat classes. Rule: **every threat has ≥2 independent controls (defense in depth, checkable), every control maps to ≥1 threat (no cargo cult), every control has an owner and a test (§11).**

| # | Threat | Primary controls | Backstop controls |
|---|---|---|---|
| T1 | External attacker (via supply chain or media, since no network path) | §4.11 ingress verification, signing, admission control | §4.9 detection; §4.10 segmentation |
| T2 | Malicious insider (regular user) | §4.1 ABAC × national classification; §4.7 tokenization; §5 HITL tiers | §4.9 audit + anomaly detection; §4.8 DLP |
| T3 | Rogue privileged admin | §4.1 PAM/JIT, SoD, two-person rule; HSM custody | §4.9 WORM audit (admin-tamper-evident); physical controls; optional CC (§4.3.4) |
| T4 | Compromised user endpoint | §4.2 server-side agent execution (endpoint holds no tokens/context) | §4.1 short-lived tokens; EDR per ECC |
| T5 | Prompt injection via content (transient) | §4.5 control/data-flow separation + taint tracking | §4.10 egress-deny; §5 HITL; §4.9 detection |
| T6 | Stored injection (poisoned RAG/knowledge) | §4.7.4 corpus write gates, signed bundles, provenance | §4.5 retrieval results are tainted by default; red-team scope |
| T7 | Malicious/compromised MCP server; tool rug-pull | §4.6 signing+pinning+SBOM+admission; tool-definition hash pinning; DMZ for untrusted | §4.4 per-call authZ; §4.10 micro-segmentation; kill switch |
| T8 | Poisoned model weights | §4.11.3 model intake pipeline (provenance, hash, behavioral evals, backdoor probes) | §4.5 same containment as untrusted content sources; staged rollout |
| T9 | Platform software supply chain | §4.11 offline signing, private registries, SBOM, mirrored CVE data | Admission control; §4.9 detection |
| T10 | Physical attack (media/HSM theft, either site) | Physical security program; HSM tamper response; encrypted media | Two-person custody; §6 site controls |
| T11 | Resource exhaustion / DoS (huge tool outputs, GPU starvation) | §4.4 size/time/recursion limits; §7 priority queues + quotas | Circuit breakers; kill switch |
| T12 | Agent-mediated exfiltration (low-and-slow, authorized-but-abused) | §4.8 DLP on all three edges; §4.7 minimization + tokenization | §4.9 volume/sequence anomaly rules; detokenization rate limits |
| T13 | Model behavioral failure (wrong action, hallucinated params) | §5 HITL tiers; §4.4 schema validation of args; guardrail models | §4.9 IR playbook; eval harness regression gates |
| T14 | Cross-user/clearance leakage via caches or shared state | §4.4.6 classification-partitioned caches; per-session sandboxes (§4.2) | Eval-harness cache-poisoning tests |
| T15 | Audit-store compromise or tampering | §4.9 WORM, log minimization, field-level encryption, SoD on SIEM access | Off-site immutable copies (§6); canary log entries |

---

## 3. Reference architecture

```
                        ┌────────────────────────────────────────────────┐
 300 USERS              │  THIN CLIENTS (managed endpoints, EDR)          │
 Arabic-first UI        │  UI only — no agent loop, no tokens, no context │
                        └───────────────────────┬────────────────────────┘
                                                ▼  (on-prem IdP: OIDC, mTLS)
┌───────────────────────────────────────────────────────────────────────────┐
│ IDENTITY & POLICY (on-prem)  Keycloak/AD-FS · ABAC = role × clearance ×    │
│ national-data-classification × tool-tier · OPA policy-as-code · PAM+JIT    │
└───────────────────────┬───────────────────────────────────────────────────┘
                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ AGENT EXECUTION TIER (server-side) — per-session sandboxed runtimes,       │
│ egress-deny; the ONLY thing allowed to talk to the Gateway               │
└───────────────────────┬───────────────────────────────────────────────────┘
                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ MCP GATEWAY CLUSTER (HA, stateless) — the control plane                    │
│ • per-call authZ (ABAC)      • vault-injected per-call credentials         │
│ • TOOL RISK REGISTRY (gateway-owned truth) + tool-definition hash pinning  │
│ • dynamic tool discovery     • HITL tiers 0–3 (§5) w/ normalized previews  │
│ • schema validation of args AND results · size/recursion/time limits       │
│ • Unicode normalization (NFKC), bidi/zero-width stripping at boundaries    │
│ • caches partitioned by (user, clearance, classification)                  │
│ • rate limits · quotas · anomaly detection · kill switch · circuit breakers│
│ • minimized WORM audit → SIEM                                              │
└──┬──────────────┬──────────────────┬──────────────────┬───────────────────┘
   ▼              ▼                  ▼                  ▼
 INFERENCE     QUARANTINE LLM     INTERNAL MCP       DATA MCP (RO)      UNTRUSTED MCP
 open-weight   (tool-less, for    signed+pinned      national labels    (isolated DMZ,
 portfolio,    untrusted content) +SBOM, SPIFFE-id,  at source,         no internal
 vLLM-class,   → taint-labeled    least-priv creds   tokenization/FPE,  reach, hash-
 priority      opaque refs only                      HSM keys           pinned tools)
 queues
   └──────────── mTLS everywhere · deny-by-default egress from ALL tiers ────────────┘

 SUPPLY CHAIN (the real perimeter): MEDIA-INGRESS STATION → verify sigs/hashes →
 scan → private registries (containers, models, policies, CVE mirrors) → admission
 control. One-way low→high transfer; controlled, logged high→low exceptions.

 CROSS-CUTTING: 2 in-Kingdom sites (§6) · OpenTelemetry tracing + cost attribution ·
 CI/CD gates · offline red-team/eval harness · AI Risk Board governance (§8)
```

---

## 4. Layer specifications

### 4.1 Identity & policy *(closes A3; T2, T3)*
- **On-prem IdP** — Keycloak (or AD FS if the org is AD-centric) issuing OIDC tokens; no cloud identity dependency anywhere. MFA per ECC. No shared/service accounts for user-facing access.
- Identity + clearance propagate to every tool call (not just login). Short-lived, audience-scoped tokens; mTLS on every hop.
- **ABAC:** decision = `role × clearance × national data classification of target × tool risk tier`. Deny by default. Policies in **OPA/Rego**, versioned, code-reviewed, tested in CI (policy unit tests are part of the eval harness).
- **PAM + JIT** for all privileged access: time-boxed, approved, session-recorded. **Two-person rule** for: HSM operations, kill-switch, media-ingress approval of new software/models, WORM/audit administration. SoD: no person both writes policy and approves their own tool deployments.

### 4.2 Client tier & server-side agent execution *(closes B7; T4, T14)*
- Endpoints are thin: UI rendering only. Managed, EDR-covered per ECC — but **not trust anchors**: they never hold API tokens, agent context, or retrieved data beyond the rendered view.
- Agent loops run server-side in **per-session sandboxed runtimes** (containers with syscall filtering, e.g. gVisor-class isolation; one sandbox per user session; egress-deny). Only sandboxes may reach the Gateway.
- Session state is per-user, wiped on session end; no shared scratch space across clearance levels.

### 4.3 Inference tier *(closes A1, A2, C2; T8, T13)*
1. **Model portfolio (all self-hosted, weights via §4.11.3 intake; July-2026 state, re-run intake per generation):**
   - *Primary agentic model:* **Qwen3.5** (Apache 2.0) — as of July 2026 the only open-weight family combining top verified tool-calling (best open-weight BFCL-V4 score) with leaderboard-verified Arabic (its predecessor topped Stanford HELM Arabic among open models). Flagship 397B-A17B MoE targets one 8×H200-class node; smaller variants (122B-A10B, 27B dense) for quarantine/sidecar roles. Contenders re-evaluated at each intake: GLM-5.2, DeepSeek-V4, Kimi K2.x (stronger on some agentic benchmarks, **no Arabic claims**; some carry modified/custom licenses — legal review).
   - *Arabic-native sidecar (optional):* **Fanar-2-27B** (Apache 2.0, verified tool calling, ArabicMMLU ~74.7) or **Falcon-H1-34B** (tool calling verified; Arabic variants announced Jan 2026 — weights not yet published, watch item). **ALLaM:** politically attractive and worth engaging HUMAIN about, but technically unusable for agentic work today — only the 7B preview is downloadable (4K context, no tool calling); 34B is closed behind HUMAIN Chat. Track for the rescheduled LEAP (Aug 31–Sep 3, 2026).
   - *Guardrail/utility models (all offline-capable):* **Qwen3Guard-Gen-8B + -Stream** (safety, 8 Arabic variants explicitly supported — the best Arabic-capable open guard) or **Nemotron-Safety-Guard-8B-v3** (Arabic in training data); **Prompt Guard 2 86M** as cheap first-pass injection classifier (multilingual base, Arabic unbenchmarked — measure in your eval harness); **Granite Guardian 4.1-8B** for English-side tool-call-hallucination checks; an Apache-licensed embedding model for retrieval. Orchestrate via NeMo Guardrails (Apache 2.0) — **verify its usage-reporting opt-out before air-gap deployment**.
   - The **quarantine LLM** (§4.5) is a smaller instance (e.g., Qwen3.5-27B) — it needs comprehension, not agentic skill.
2. **Serving:** **vLLM** (the 2026 production standard; Apache 2.0) with continuous batching, `--scheduling-policy priority`, per-department quotas at the AI-gateway layer; offline operation is explicit and verified: `VLLM_NO_USAGE_STATS=1` / `DO_NOT_TRACK=1`, `HF_HUB_OFFLINE=1`, egress-deny confirms. SGLang is the credible alternative (disable Ray telemetry in multi-node). Avoid dead/unfit stacks: HF TGI archived March 2026; Ollama is not a multi-tenant production server. Model registry is internal; only signed, evaluated weights load (admission control applies to models, not just containers).
3. **Retention is org policy now, not vendor promise:** prompts/outputs/traces retained per §8.4 schedule; caches per §4.4.6.
4. **Confidential computing — scoped decision, not dogma:** enable CPU CC (SEV-SNP/TDX) if procured hardware includes it at negligible cost; its marginal value in an owner-operated air gap is the rogue-admin case (T3), which PAM + two-person + physical controls address first. **Confidential-GPU inference:** Hopper-class CC is GA with near-zero overhead at 70B-class (measured ~0% for 4-bit 70B) — but **NVIDIA has no officially supported fully-offline attestation as of July 2026** (local verifier still OCSP-checks NVIDIA cloud; nvtrust issue #135); only an unsupported DIY pattern (mirrored RIMs, cached CRLs with staleness acceptance) exists, and GB200/GB300 NVL72 racks have **no** CPU TEE at all. Decision: defer GPU CC until supported offline attestation ships, or formally accept the DIY pattern via the AI Risk Board — recorded either way in the residual-risk register (R7).

### 4.4 MCP Gateway — the control plane *(closes B2, B4, B11, B12, B13; T5, T7, T11, T13, T14)*
Stateless, HA, load-balanced. Responsibilities:
1. **AuthZ every `tool_use`** against ABAC before forwarding. The model proposes; the gateway disposes.
2. **Vault-injected credentials** at the boundary: per-call, per-tool, short-lived dynamic secrets. Model and context never see secrets.
3. **Tool risk registry (gateway-owned):** the sole source of truth for each tool's risk tier (§5). Server-declared MCP annotations (read-only/destructive hints) are advisory inputs to human review — never enforcement inputs. **Tool definitions hashed and pinned at approval; any drift auto-quarantines the server pending re-review** (rug-pull defense).
4. **Dynamic tool discovery** — only relevant tool schemas load per request (context economy, cache-friendliness).
5. **Protocol hardening — target MCP spec 2025-11-25** (adopt the 2026-07-28 revision, published this month as a locked RC, through the normal change process — its stateless core actually *simplifies* HA gateway design by removing `Mcp-Session-Id`). Enforce the spec's own MUST-level security rules plus gateway limits: sessions are never authentication (identity comes from the OIDC token on every request); session IDs high-entropy, identity-bound, rotated, revoked on anomaly; HTTP 403 on invalid `Origin`; **no token passthrough** — the gateway never forwards a token not issued for the target (RFC 8707 resource indicators); strict schema validation of tool **arguments and results**; size, recursion, and time limits on tool outputs; streaming responses length-capped.
6. **Caches partitioned by (user, clearance, data classification).** Semantic caching only within same-classification partitions; cross-user response cache only for PUBLIC-classified content. Cache-poisoning tests in the eval harness.
7. **Unicode defense:** NFKC normalization; strip/flag bidi-control and zero-width characters at every trust boundary; homoglyph checks on high-risk strings (URLs, IDs, account numbers). HITL previews (§5) render from **normalized** text — what the approver sees is what the model reads.
8. **Rate limits, per-user/tool quotas, anomaly hooks, kill switch** (per-tool / per-user / per-server / global; two-person for global; **drilled monthly**), circuit breakers + timeouts + fallbacks per downstream server.
9. **Minimized WORM audit → SIEM** (§4.9).
10. **Gateway SDL (it is the most attacked code you will own):** memory-safe language; dependency allowlist + its own SBOM; mandatory code review; **fuzzing of the MCP/JSON-RPC parser in CI**; independent penetration test pre-go-live and annually; the gateway passes the same admission control it enforces.

### 4.5 Injection containment — control/data-flow separation *(closes B1, B14; T5, T6)*
The load-bearing design. Prompt injection is **unsolved in 2026**; containment is architectural:
1. **Privileged planner** (primary model) sees only *trusted* input: the user's request, gateway-approved tool schemas, curated system context. It emits a **typed plan** of tool calls.
2. **Untrusted content** (documents, tool results from data sources, anything retrieved) is parsed by a **quarantined, tool-less model instance**. Its outputs enter the plan only as **opaque, taint-labeled references** (`$doc1.summary`), never as text the planner reads.
3. **Capability rules on data flow:** a tainted value cannot become the target/recipient/path of a Tier ≥2 action (e.g., a value derived from a fetched document can be *displayed*, but cannot be the recipient of a send, the path of a delete, or an argument of a privileged write) unless a human approves the specific resolved values through the normalized preview (§5).
4. Backstops when (not if) containment leaks: deny-by-default egress (§4.10), HITL tiers (§5), detection rules (§4.9).
5. **Acceptance test:** red-team corpus of Arabic + English injection payloads (direct, indirect, stored, Unicode-obfuscated); pass = zero privileged-tool invocations sourced from tainted values across the corpus, re-run on every change (§11 phase gates).

### 4.6 MCP servers *(closes B4 remainder; T7)*
- Only vetted servers run: signed, version-pinned images, SBOM, offline admission control. Internal servers get **SPIFFE/SPIRE workload identity** + mTLS; least-privilege scoped credentials; narrowest tool surface (read-only default; write tools separately registered and tiered).
- Prefer thin org-built MCP servers over internal APIs (auth, filtering, audit stay in your control) rather than exposing databases.
- **Community/third-party servers are untrusted code:** isolated DMZ segment, no route to internal systems, tool definitions hash-pinned, and — in an air gap — they cannot call external SaaS anyway, so each must justify existence; most orgs should run **zero** of these in production.

### 4.7 Data layer *(closes B9, D1 binding; T2, T6, T12)*
1. **Classification at the source** using the **NDMO/SDAIA national data classification levels — Top Secret / Secret / Restricted / Public** (Data Classification Policy under the National Data Governance framework; maintain the required classification register: asset, level, assignment date, validity, review date). Labels flow with data and drive ABAC. Not an invented scheme.
2. **Tokenization/FPE** of sensitive fields (National ID, Iqama, IBAN, names) so raw PII never transits the pipeline.
3. **Detokenization is a designed service, not an afterthought:** requires requester clearance ≥ field classification ∧ purpose binding ∧ rate limits ∧ full audit; bulk detokenization = Tier-3 approval (§5). Token vault keys in HSM; **the vault is not reachable as an MCP tool, ever.**
4. **Knowledge/RAG governance:** corpus writes require provenance + human classification review; knowledge bundles are signed and versioned (git) with rollback; retrieval results enter context **tainted** (§4.5); stored-injection is in red-team scope.
5. **Data minimization into context:** retrieve least-needed; filter before prompt assembly.
6. **HSM-backed key custody**, automated rotation (scheduled + event-driven), replicated to DR site under two-person custody.

### 4.8 DLP — three enforcement points *(closes B8; T2, T12)*
- Enforcement at (1) user↔gateway, (2) **tool-results→context**, (3) **model-output→user/actions** — the last two carry the real volume and risk.
- Detection = deterministic validators (National ID/Iqama structure, SA-IBAN checksum) **+ offline Arabic NER** for names/addresses/contextual PII (e.g., Presidio-style engine with custom Arabic recognizers backed by an Arabic-capable NER model such as CAMeL-Tools/AraBERT-class — final choice measured, not assumed, against the Arabic PII corpus below).
- Clearance-gated unmasking (view-level, audited) so masking doesn't break legitimate workflows; measured FP/FN rates against an Arabic PII test corpus in the eval harness; mapped to PDPL.

### 4.9 Audit, detection & response *(closes B10, B15, C8; T3, T12, T15)*
1. **Log-content minimization:** default record = who, tool, tier, decision, payload **hashes** + tokenized excerpts. Full payloads only for Tier ≥2 actions, field-level encrypted, record classification inherits the data touched. The audit store is protected as the highest-classification store it is.
2. WORM/append-only, streamed to SIEM; SoD on SIEM admin; analysts see redacted views by default; canary log entries to detect tampering; off-site immutable copies (§6).
3. **Shipped SOC use-cases** (day-one SIEM rules): first-use-of-tool per user; abnormal tool sequences; token/volume spikes; egress-deny bursts; approval-bypass attempts; tool-definition drift events; detokenization rate anomalies; canary-token access; quarantine-breach attempts (tainted value reaching privileged call = P1).
4. **IR playbooks for the four novel incident classes:** prompt-injection incident, model-behavior incident, tool/server compromise, agent-mediated exfiltration — each with containment steps (which kill switch, which scope), forensics sources (traces, WORM audit), and reporting duties (NCA notification per CSCC/ECC; SDAIA breach notification per PDPL).
5. Retention + data-subject rights per §8.4.

### 4.10 Network *(T5, T7, T11 backstops)*
- Air-gapped: no internet path from any production tier. **Deny-by-default egress applies internally too** — each sandbox/server reaches only its explicit allowlist (contains lateral movement and injection-driven internal exfiltration).
- Micro-segmentation between: clients / agent sandboxes / gateway / inference / each MCP server / data layer / DMZ / audit. mTLS everywhere (mesh or Cilium-class CNI with identity-aware policy — pick **one** mechanism; §8.1).
- The **only** low↔high interface is the media-ingress process (§4.11); any high→low export is case-by-case, approved, logged, and DLP-scanned.

### 4.11 Supply chain — the real perimeter *(closes A4; T1, T8, T9)*
1. **Media-ingress station** (dedicated, isolated): all inbound software, weights, CVE mirrors, eval corpora arrive on approved media → malware scan → **signature/hash verification against out-of-band manifests** → import into private registries. Two-person approval for anything executable or loadable. One-way low→high (data diode or enforced procedure).
2. **Private registries:** containers, model weights, OPA policies, knowledge bundles, offline CVE/vulnerability DB mirror, injection-corpus mirror (keeps "continuous" red-teaming supplied — closes C4).
3. **Model intake pipeline (T8):** license review → provenance + hash verification → artifact format scan → **behavioral eval battery** (capability, safety, Arabic quality, backdoor/trojan probes) → signed model-registry entry → staged rollout with guardrail A/B comparison. **Fine-tuning on org data** = PDPL processing activity: DPIA required; fine-tuned weights inherit the highest classification of their training data.
4. **Offline signing:** private CA / key-based cosign (no public Fulcio/Rekor dependency); admission control verifies signatures offline; unsigned = refused (tested in §11).
5. Update cadence is a policy decision with a floor: security content (CVE mirrors, injection corpora, guardrail models) imported at least monthly; emergency out-of-band path defined and drilled.

---

## 5. Human-in-the-loop — tiered, fatigue-resistant *(closes B3; T2, T5, T13)*

| Tier | Actions | Gate |
|---|---|---|
| 0 | Read-only, non-sensitive | Auto |
| 1 | Reversible, in-domain writes | Policy auto-approval (OPA), logged |
| 2 | Irreversible or sensitive-data writes | Human approval, **normalized-text diff preview** of resolved values |
| 3 | Destructive / mass-scale / cross-boundary / bulk detokenization | Two-person approval |

- Tier assignment lives in the **gateway tool risk registry** (§4.4.3), set by the AI Risk Board (§8.2), never by server self-declaration.
- **Fatigue engineering:** approver ≠ requester; approval-rate and time-to-approve dashboards; **monthly canary approvals** (deliberately wrong requests injected; a vigilant approver must reject; misses trigger retraining and tier re-review); batching UX for Tier 2.
- Previews render from NFKC-normalized text (§4.4.7) so the approver sees what the model sees.

---

## 6. Sites & resilience *(closes A5; T10, T15)*
- **Two in-Kingdom facilities**, private link; HA within primary; tested failover to secondary (RTO/RPO defined with the business, evidenced for CSCC BC/DR).
- **Explicit recorded decision:** full GPU capacity at DR **or** formally accepted degraded-capability DR (e.g., smaller model tier at DR). Do not let this be discovered during a disaster.
- HSM replication + key escrow under two-person custody; offline immutable backups (weights, registries, WORM audit copies, knowledge bundles); **restore drills, not just backup jobs**; DR runbook rehearsed on schedule.

---

## 7. Capacity & performance *(closes C3; T11)*
- Sizing worksheet drives procurement, anchored in published July-2026 data: 4× H100 (FP8, 70B-class) sustains ~250 concurrent requests at ~31 tok/s/user (NVIDIA NIM benchmarks); a documented VMware case served 300 concurrent users on 4× H100 with a 120B MoE; an undersized 2× H100 collapses (~89 s TTFT) at the same load. For ~300 named users at typical ~10–15% duty cycle, a 4–8× H100/H200 node with a 70B–120B-class model is the working floor; the Qwen3.5 flagship MoE wants an 8× H200-class node; budget KV-cache memory explicitly (it can exceed weight memory at high concurrency); headroom ≥40%; procurement lead time buffered; B200-class roughly triples H200 throughput if procurable.
- **Priority classes + per-department quotas** at the serving layer; degradation ladder defined (which workloads slow first); queueing visible to users (honest latency beats silent failure).
- Caching (§4.4.6, partitioned), KV-cache/prefix reuse, quantization choices validated against Arabic quality benchmarks (quantization can hit Arabic harder than English — test in the eval harness, don't assume).
- Cost/GPU-hour attribution per department (FinOps applies even air-gapped: GPUs are the scarce currency).

---

## 8. Governance, people, process *(closes C1, C5, C6, C7, D5)*

### 8.1 Operability as a design constraint
- Named operating model, honestly sized for a 300-person org: platform/infra (~3–4 FTE), SecOps/SOC integration (~2–3, may be an existing SOC), AI/eval engineering (~2), data steward + DPO liaison (~1), service owner (1). **If the org cannot staff this, cut scope (fewer MCP servers, fewer models) — not controls.**
- Consolidation rules: one policy engine (OPA), one secrets system, one mTLS mechanism, one observability stack. Every additional moving part must displace a risk, not decorate the diagram.

### 8.2 AI Risk Board
- Members: CISO delegate, data management office, legal/PDPL (DPO), service owner. Owns: tool risk-tier approvals (§5), model intake approvals (§4.11.3), ABAC/OPA policy change approval, the **exceptions register**, and **residual-risk acceptance** (§12). Meets on cadence; emergency path defined.

### 8.3 People
- Role-based training: users (injection awareness — "your agent can be socially engineered"), approvers (canary program, Unicode-spoofing awareness), admins (PAM procedures). Privileged-role personnel vetting per ECC/CSCC. AI acceptable-use policy signed by all users; data-handling SOPs per national classification level.

### 8.4 Retention & data-subject rights
- Retention schedule per artifact class (prompts, outputs, traces, caches, audit records, eval artifacts) — purpose-bound per PDPL and the entity's records schedule, with audit-record retention set to satisfy ECC/CSCC logging requirements; enforced by TTL automation, verified by audit.
- **RoPA** covers the AI pipeline; **DPIA** before go-live and on major change; **DSR procedure** spans logs, caches, indexes, and fine-tuned artifacts.

---

## 9. Compliance traceability *(closes D1–D4)*
- **Binding rule:** ABAC labels, DLP rules, audit record classes, and handling SOPs bind to the **NDMO/SDAIA four-level national classification (Top Secret / Secret / Restricted / Public)** — not to an invented scheme.
- Frameworks mapped at **control-ID level** in a living traceability matrix (co-owned with the accreditation team; a build artifact, not an afterthought):
  - **NCA ECC-2:2024** (108 controls) + **CSCC-1:2019** (32 controls/73 subcontrols — the critical-system overlay; note it hard-restricts cloud hosting for critical systems, which is itself part of the air-gap justification) + **DCC-1:2022** (data cybersecurity) + **NCS-1:2020** (national cryptographic standards — governs the crypto/HSM choices in §4.7.6).
  - **PDPL** (M/19 as amended by M/148; enforced since Sept 2024) + Implementing Regulations (Sept 2023; track the 2025 amendment consultation for gazetted changes).
  - **NDMO Data Management & PDP Standards** (15 domains / 77 controls — Data Classification is one domain; mandatory for public entities).
  - **SDAIA AI instruments:** AI Ethics Principles v2; **Generative AI Guidelines for Government** (classified data must never enter non-compliant GenAI tools — the air-gapped design is the compliant pattern for Secret-and-above corpora); AI Adoption Framework; and the **draft Responsible AI Policy** (consultation closed May 2026) — build registration- and audit-ready now, since a government LLM on a CSCC system will land in its critical/high tier when enacted.
  - **DGA:** Digital Government Policies V2.0; **file the formal cloud-adoption exception via the RAQMI "Exception from Adopting Cloud Services" service** (or ground it in the CSCC restriction) — a required artifact, not an assumption, for an on-prem build under the Cloud First Policy.
- **Staffing note (ECC-2:2024):** cybersecurity positions must be filled by qualified Saudi nationals — feed this into §8.1 hiring plans early; it is a schedule risk, not a formality.
- Evidence generation designed in: every §11 acceptance test outputs an artifact filed against control IDs.

---

## 10. Technology choices (July 2026 — all must be air-gap operable; swap only for approved equivalents)
- **Identity:** Keycloak / AD FS (on-prem OIDC). **Policy:** OPA/Rego. **PAM:** approved on-prem PAM.
- **Secrets:** HashiCorp Vault **or OpenBao** (license review — BSL vs. open fork) with dynamic secrets; on-prem **HSM** root of trust.
- **Workload identity:** SPIFFE/SPIRE; mTLS via service mesh **or** identity-aware CNI (Cilium-class) — choose one (§8.1).
- **Inference:** vLLM (SGLang alternative) on H100/H200-class nodes; model portfolio per §4.3.1 — Qwen3.5 primary (Apache 2.0), Fanar-2-27B/Falcon-H1 Arabic sidecar options, Qwen3Guard + Prompt Guard 2 + Granite Guardian guardrail set, NeMo Guardrails orchestration. All licenses reviewed at intake (watch modified-MIT/custom licenses on Kimi/MiniMax/Mistral-Medium-class alternatives).
- **Gateway:** the core build. Evaluate self-hostable open-source MCP gateways as a base before writing from scratch — as of July 2026: **IBM ContextForge** (gateway+registry+proxy, OpenTelemetry, plugins), **Docker MCP Gateway** (per-server container isolation, interceptors, image-signature verification), **agentgateway** (Rust data plane, Linux Foundation), **Lasso MCP Gateway** (guardrail plugins incl. Presidio PII); Kong Gateway Enterprise 3.12+ if a commercial, DB-less self-managed base is preferred. Whatever the base, §4.4.10 SDL and the same admission bar apply; the custom work (ABAC binding, tool risk registry, taint tracking, HITL tiers) remains yours. Note the official MCP Registry is still preview-only and does **no artifact signing** (namespace auth only) — your private registry + offline signing (§4.11) is not optional.
- **Supply chain:** Syft (SBOM), cosign key-based/private-CA (offline), Kyverno or OPA Gatekeeper (admission), private registries (Harbor-class), offline CVE mirror.
- **Audit/observability:** WORM store + org SOC/SIEM; OpenTelemetry end-to-end.
- **Red-team/eval (offline-capable):** promptfoo/garak/PyRIT-class harness (all self-hostable OSS) + org-built Arabic injection corpus, refreshed via the media-ingress mirror (§4.11.2); Arabic safety benchmarks (AraTrust/AraSafe-class) in the battery.
- All choices from NCA/SDAIA-approved lists where such lists apply; confirm before procurement.

---

## 11. Build phases (each independently testable; do not skip)

1. **Air-gap foundation & supply chain** — segmentation, on-prem IdP, media-ingress station, private registries, offline signing + admission control. *Test: unsigned artifact refused at admission; no route from any production tier to the internet (verified by scan); ingress process produces evidence records.*
2. **Inference tier** — model intake pipeline, serving stack, priority queues, model registry. *Test: unverified weights refuse to load; Arabic + agentic eval battery passes recorded baseline; telemetry-free operation verified.*
3. **Gateway core** — per-call ABAC, vault credential injection, tool risk registry + hash pinning, minimized WORM audit → SIEM, protocol limits, Unicode normalization. *Test: over-clearance call denied; secret never appears in context (verified by trace inspection); mutated tool definition auto-quarantines its server; oversized/malformed tool result rejected.*
4. **Agent execution tier** — server-side sandboxes, thin clients, egress-deny. *Test: endpoint compromise simulation yields no tokens/context; sandbox cannot reach non-allowlisted hosts.*
5. **Injection containment + HITL** — quarantine LLM, taint tracking, capability rules, tiered approvals with normalized previews, canary program. *Test: injection corpus → zero tainted-value privileged calls; Tier-3 without two approvals impossible; bidi-spoofed preview detected.*
6. **Data layer + DLP** — national-classification labeling at source, tokenization/FPE, detokenization service, three-point DLP with Arabic NER, knowledge-corpus gates. *Test: raw PII absent from traces end-to-end; unmasking requires clearance and is audited; poisoned corpus document caught at write gate AND contained at retrieval (defense in depth proven).*
7. **Resilience** — second site, HSM replication, offline backups, DR + restore + kill-switch drills. *Test: failover drill meets RTO/RPO; restore from offline backup succeeds; kill-switch drill log exists.*
8. **Governance & accreditation** — AI Risk Board seated, policies-as-code gates in CI, traceability matrix populated, DPIA/RoPA done, training delivered, red-team harness on every change. *Test: new tool cannot reach production without registry entry + eval pass + Board tier assignment; accreditation team signs the matrix.*

---

## 12. Residual risk register — and why this is the best achievable (2026-07-02)

Design-level flaws: none open (v7's 38 are closed; two further adversarial critique passes found no new design flaw). What remains is **irreducible with July-2026 technology** — each item has an owner and an explicit Board acceptance (R1–R7):

| # | Residual risk | Why irreducible today | Bounded by |
|---|---|---|---|
| R1 | Prompt injection has no complete solution in 2026 — a sufficiently novel payload may steer the quarantined path's outputs | No provably injection-proof LLM exists; Anthropic (July 2026) reports best-case attack success reduced to ~1.4%, "not solved"; adaptive-attack research (arXiv 2606.26479) shows even out-of-model defenses degrade under adaptive adversaries | §4.5 containment (CaMeL-pattern, arXiv 2503.18813) limits blast radius to tool-less context; egress-deny + HITL + detection cap impact |
| R2 | Open-weight models trail frontier hosted models in capability and injection-robustness | Air gap (your constraint, CSCC-justified) excludes hosted frontier models | §4.11.3 staged intake captures each open-weight generation; surrounding controls assume a weaker model |
| R3 | Insider with privilege + physical access can be bounded, not eliminated | True of every architecture ever built | Two-person rules, PAM, WORM audit, physical program, HSM custody |
| R4 | In-use data protection = physical + access control (+ optional CC); practical FHE-grade inference does not exist | FHE/LLM inference remains orders of magnitude too slow for production in 2026 | Owner-operated facility; T3 controls |
| R5 | Air-gap update latency: a window exists between a published fix/attack and its import | Consequence of the air gap itself | Monthly floor + emergency ingress path (§4.11.5) |
| R6 | Model behavioral failure (hallucination) is reduced, not eliminated | Property of 2026 LLMs | Schema validation, HITL tiers, guardrail models, eval gates |
| R7 | GPU confidential computing cannot be attested offline in a supported way | NVIDIA local verifier still requires OCSP against NVIDIA cloud (nvtrust #135); no vendor-supported air-gapped attestation exists; GB200/GB300 racks lack a CPU TEE entirely | GPU CC deferred (or DIY attestation formally accepted by the Board); T3 covered by PAM/two-person/physical controls meanwhile; revisit when supported offline attestation ships |

**Stopping-criterion check:** every threat (T1–T15) has ≥2 owned, tested controls; every control maps to a threat; compliance is traceable to control IDs; the build is staffed and sized for reality; remaining risks are R1–R7, each bounded by technology or by the org's own chosen constraints — not by a fixable design decision. **Therefore v10 is the best achievable version as of 2026-07-02.** Standing revisit triggers: MCP spec 2026-07-28 final publication (this month — its stateless core simplifies the gateway); SDAIA Responsible AI Policy enactment (registration/audit duties); Falcon-H1 Arabic weight release; ALLaM agentic-capable release via HUMAIN (LEAP, Aug 31–Sep 3, 2026); NVIDIA supported offline attestation; each open-weight model generation.

---

## 13. Acceptance criteria for "done" (all runnable or auditable)
- [ ] No network path from production to the internet (continuous verification, not one-time).
- [ ] Media ingress: unsigned/unverified artifact refused; every import has a two-person evidence record.
- [ ] Every tool call authenticated, ABAC-authorized against national classification, minimally-logged to WORM/SIEM.
- [ ] No secret in model context (trace-verified); credentials per-call, vault-issued, short-lived.
- [ ] Injection corpus (incl. Arabic + Unicode-obfuscated + stored): zero tainted-value privileged invocations.
- [ ] Tool-definition drift auto-quarantines; unsigned server refused.
- [ ] Tier-2 preview shows normalized text; Tier-3 requires two approvers; canary-approval program running with measured rejection rate.
- [ ] PII: deterministic + NER detection meets measured FP/FN targets on Arabic corpus; raw PII absent from pipeline traces; detokenization clearance-gated and audited.
- [ ] Caches proven clearance-partitioned (cross-user leak test fails to leak).
- [ ] DR failover + offline restore + kill-switch drills passed and evidenced.
- [ ] Traceability matrix signed by accreditation/compliance team (ECC + CSCC + PDPL + DGA + SDAIA instruments).
- [ ] DPIA + RoPA complete; retention TTLs enforced and verified; DSR procedure tested end-to-end.
- [ ] AI Risk Board seated; exceptions and residual-risk registers (R1–R6) formally accepted.

---

*End of v10 final specification.*
