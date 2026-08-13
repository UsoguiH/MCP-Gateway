# Iteration Ledger — v7 → v8 → v9 → v10 (final)

> How each iteration was produced: fix every open flaw, then re-critique the result as adversarially as v7 was critiqued, until a critique pass finds no design-level flaw — only residual risks bounded by 2026 technology or by the org's own constraints. That is the stopping criterion v7 never had.
> Flaw IDs (A1…E4) refer to `MCP-v7-Critique.md`.
> All research-dependent items verified against July-2026 primary sources (see the final spec for details).

---

## v8 — "Re-platformed for reality"

**Fixes: A1–A6, C2, C3.** v8 re-derives the platform for air-gapped + CSCC + open-weight + 300 users.

| Change | Replaces (v7) | Detail |
|---|---|---|
| Self-hosted open-weight model portfolio | Claude via sovereign cloud (A1) | Primary agentic model + Arabic-strong model + small guardrail/classifier models, all weights verified at ingress and served from an internal model registry. July-2026 shortlist: **Qwen3.5** primary (only open-weight family with both top verified tool-calling and leaderboard-verified Arabic); Fanar-2-27B / Falcon-H1 as Arabic-native sidecars; Qwen3Guard + Prompt Guard 2 guardrails; ALLaM tracked but not yet agentic-usable (7B/no tools; 34B closed). Full detail in final spec §4.3.1. |
| Org-side retention policy replaces "ZDR" | Vendor-retention language (A2) | Retention now governs *your own* logs/caches/traces; policy defined in v10 (C7). |
| On-prem identity stack | Entra ID option (A3) | On-prem IdP (e.g. Keycloak, or AD FS against the existing domain) — OIDC internally; no cloud reachability assumed anywhere in the trust chain. |
| Offline supply chain | Public Sigstore, live feeds (A3, A4) | Private container/model registry; key-based or private-CA signing verified by admission control offline; mirrored vulnerability DB and injection-attack corpora imported on schedule through a **media ingress station** (scan → verify signatures/hashes → import), one-way transfer (data diode or procedural equivalent) for anything flowing from low to high side. |
| Physical-site DR | "Multi-AZ" (A5) | Two in-Kingdom facilities, private link, replicated HSM/key escrow, offline immutable backups, explicit decision recorded: full GPU capacity at DR **or** formally accepted degraded-capability DR (CSCC BC/DR evidence either way). |
| Right-sized capacity model | Autoscaling hand-wave (C3) | Sizing worksheet: concurrent-user model, tokens/sec/GPU, queueing with priority classes, degradation ladder (who slows first), procurement lead times. Anchored figures: 4× H100 FP8 ≈ 250 concurrent @ ~31 tok/s/user (NIM benchmarks); documented 300-user case on 4× H100; 8× H200-class node for the flagship MoE. Final spec §7. |
| Confidential computing re-scoped | Unconditional CC (C2) | In an owner-operated air gap, CC's marginal value is the rogue-infrastructure-admin case. v8 makes CPU CC (SEV-SNP/TDX) *optional hardening* if the procured hardware supports it at negligible cost, addresses the insider threat primarily via PAM/JIT + two-person rule + physical controls, and defers confidential-GPU inference: Hopper CC is GA with ~0% overhead at 70B-class, but **no vendor-supported fully-offline attestation exists as of July 2026** (NVIDIA local verifier still OCSP-checks NVIDIA cloud; nvtrust #135) — so GPU CC is deferred or DIY-accepted by the Risk Board (residual risk R7 in the final spec). |
| Scale corrected to ~300 | ~500 (A6) | All sizing, licensing, cost sections re-based. |

### Adversarial critique of v8 → what's still wrong
All fifteen Category-B flaws survive: the quarantine is still a label (B1), the cache still leaks across clearances (B2), HITL still rubber-stamps (B3), tool metadata is still trusted (B4), there is still no threat model (B5), model weights are in the registry but their *behavioral* vetting is undefined (B6), agent execution locality is still undecided (B7), DLP still watches the wrong edge (B8), detokenization is undesigned (B9), the audit store is still a crown jewel (B10), the gateway still has no SDL (B11), protocol-level hardening absent (B12), Unicode/RTL attacks unhandled (B13), RAG poisoning unhandled (B14), detection content undefined (B15). **v8 is deployable but not defensible. Iterate.**

---

## v9 — "Security depth"

**Fixes: B1–B15.** Every mechanism named and testable.

| Flaw | v9 mechanism |
|---|---|
| B1 injection | **Control/data-flow separation (CaMeL-style, arXiv 2503.18813; pattern canon arXiv 2506.08837):** the privileged planner sees *only* trusted input (user request, tool schemas) and emits a typed plan; untrusted content is processed by a quarantined, tool-less model whose outputs enter the plan as **opaque references with taint labels**, never as text the planner reads. Capabilities on data values constrain where tainted values may flow (a value derived from an untrusted document cannot become the recipient of a `send` or the path of a `delete`). Egress-deny + HITL remain as backstops (Willison's "lethal trifecta" heuristic: the gateway removes the external-egress leg). Red-team acceptance test: corpus of Arabic/English injection documents; zero privileged-tool invocations sourced from tainted values. |
| B2 cache | Cache keys include `(user, clearance, data-classification)`; semantic cache allowed only within same-classification partitions; response cache for PUBLIC-classified tiers only. Cache poisoning test in eval harness. |
| B3 HITL | Risk-tiered actions: Tier 0 auto (read-only), Tier 1 policy-auto-approved writes (reversible, in-domain), Tier 2 human approval with normalized-text diff preview, Tier 3 two-person approval (destructive/mass/external). Approval-latency and approval-rate dashboards; monthly **canary approvals** (deliberately wrong requests that a vigilant approver must reject) to measure rubber-stamping; approver ≠ requester (SoD). |
| B4 tool trust | Gateway-owned **tool risk registry** is the sole source of truth for tool tiering; server-declared annotations are advisory input to a human review, never enforcement input. Tool definitions are **hashed and pinned** at approval; any drift (description/schema change) auto-quarantines the server pending re-review (rug-pull defense). |
| B5 threat model | Full threat→control matrix added (15 threat classes; see final spec §3). Every control traces to ≥1 threat; every threat has ≥2 overlapping controls (defense in depth made checkable). This converts "best" into a testable property. |
| B6 model supply chain | Model intake pipeline: license review → hash/provenance verification → static scan of artifact format → behavioral eval battery (capability + safety + backdoor probes + Arabic evals) → signed entry in model registry → staged rollout with A/B guardrail comparison. Fine-tuning on org data = a PDPL processing activity: DPIA required, training-data classification ≤ model deployment classification, fine-tuned weights inherit the highest classification of training data. |
| B7 agent locality | **Server-side agent execution**: agent loops run in per-session sandboxed runtimes (container + syscall filtering) in the data center, egress-deny by default; endpoints get a thin UI. Endpoint compromise yields a UI session, not tokens/context. Endpoints remain managed+EDR per ECC, but are no longer trust anchors. |
| B8 DLP placement | DLP/classification enforcement at **three** points: user↔gateway, gateway↔tool-results, gateway↔model-output. Arabic NER model (offline) + deterministic detectors (ID/Iqama/IBAN checksums); clearance-gated unmasking; FP/FN rates measured in eval harness with an Arabic PII test corpus. |
| B9 detokenization | Token vault as its own hardened service: detokenize requires (requester clearance ≥ field classification) ∧ (purpose binding) ∧ (rate limits) ∧ (full audit); bulk detokenization requires Tier-3 approval. Vault keys in HSM; vault excluded from model-reachable tools entirely. |
| B10 audit store | Log-content minimization: payload hashes + tokenized excerpts by default; full payload capture only for Tier ≥2 actions, encrypted field-level, classification inherited from the data touched; SIEM analysts see redacted views by default; retention per national policy + PDPL purpose limitation; DSR (data-subject request) procedure covers logs and caches. |
| B11 gateway SDL | Memory-safe implementation language; dependency allowlist + SBOM on itself; mandatory review; fuzzing of the JSON-RPC/MCP parser in CI; independent pen test before go-live and annually; the gateway passes the same admission control it enforces on others. |
| B12 protocol hardening | Target MCP spec **2025-11-25** and enforce its normative security rules (sessions never used for authentication; identity-bound non-deterministic session IDs; HTTP 403 on invalid Origin; no token passthrough; RFC 8707 resource indicators), plus gateway limits: strict schema validation of tool args **and results**; size/recursion/time limits on tool outputs; streaming length caps. Plan adoption of the 2026-07-28 revision (stateless core — removes `Mcp-Session-Id`, simplifying HA) via the change process. |
| B13 Unicode | Gateway normalizes to NFKC, strips/flags bidi-control and zero-width chars at every trust boundary; HITL previews render from normalized text; homoglyph detection on high-risk strings (URLs, account IDs). Arabic adversarial-Unicode suite in eval harness. |
| B14 knowledge poisoning | Corpus writes gated: provenance required, human review for classification, signed knowledge bundles, versioned index with rollback; RAG retrieval results carry source provenance into taint tracking (B1); red-team scope includes stored-injection. |
| B15 detection & IR | Concrete SOC use-cases shipped as SIEM rules: first-use-of-tool per user, tool-sequence anomalies, volume/token spikes, egress-deny bursts, approval-bypass attempts, tool-definition drift, detokenization spikes, canary-token access. IR playbooks for the four novel incident classes (injection, model-behavior, tool-compromise, agent-mediated exfiltration). Kill-switch drill monthly (C8 pulled forward). |

### Adversarial critique of v9 → what's still wrong
Security depth exists, but: nobody is named to *run* it (C1), people/process controls absent (C5), no governance body or risk acceptance (C6), retention policy still undefined (C7), compliance still maps to framework names not control IDs (D4), national data classification scheme not bound (D1), DGA absent (D2), SDAIA AI instruments absent (D3), PDPL artifacts (RoPA/DPIA/DSR) missing (D5), document flaws E1–E4 uncorrected. **v9 is defensible but not operable or accreditable. Iterate.**

---

## v10 — "Operable, accountable, accredited" — FINAL

**Fixes: C1, C4–C8, D1–D5, E1–E4.** See `MCP-Secure-Architecture-v10-Final-BuildSpec.md` for the full specification. Key additions:

- **Operability as a design constraint (C1):** named team model (platform, SecOps, AI/eval, data steward roles — with realistic FTE counts for a 300-person org), consolidation choices that cut moving parts, and the rule: *a control the team cannot operate is a defect, not a feature*.
- **Governance (C6):** AI Risk Board (security + data + legal/PDPL + business owner), which owns: tool risk-tier approvals, model intake approvals, policy changes, exceptions register, residual-risk acceptance.
- **People/process (C5):** role-based training (users, approvers, admins), privileged-role vetting, AI acceptable-use policy, data-handling SOPs.
- **Retention & DSR (C7, D5):** explicit retention schedule per artifact class; RoPA; DPIA before go-live; DSR execution procedure spanning logs, caches, indexes, fine-tuned models.
- **Compliance traceability (D1–D4):** ABAC labels bound to the NDMO four-level national classification (Top Secret/Secret/Restricted/Public); DGA added (incl. the RAQMI cloud-exception filing); SDAIA AI instruments added (Ethics Principles, GenAI Government Guidelines, AI Adoption Framework, draft Responsible AI Policy — build registration/audit-ready); binding NCA stack pinned to ECC-2:2024 + CSCC-1:2019 + DCC-1:2022 + NCS-1:2020; control-ID-level traceability matrix as a living artifact the accreditation team co-owns.
- **Testable acceptance criteria (E4):** every criterion is a runnable test or an auditable artifact, including air-gap-specific ones (media ingress, both directions).
- **Stopping criterion (E2):** the threat→control matrix is complete (every threat ≥2 controls, every control tested + owned), and a **residual-risk register** lists what remains and *why no 2026 technology removes it*.

### Adversarial critique of v10 → result
A further critique pass finds **no design-level flaw**: every v7 flaw is closed by a named, testable mechanism; every threat class has overlapping, owned, drilled controls; compliance is traceable to control IDs; the build is sized to the real team and the real 300 users. What remains is the residual-risk register — risks bounded by physics, by 2026 technology, or by the org's own constraints (see final spec §12). **v10 is declared the best achievable as of 2026-07-02.**

---

## Why v10 cannot be made better with July-2026 technology

1. **Prompt injection is architecturally contained, not solved — because no 2026 technology solves it.** Control/data-flow separation + taint tracking + egress deny + tiered HITL is the strongest published pattern (CaMeL, arXiv 2503.18813; design-pattern canon, arXiv 2506.08837; Anthropic's July-2026 published position: measurably reduced, "not solved"); anything claiming more is snake oil.
2. **The capability ceiling is the air gap, not the design.** Frontier hosted models outperform self-hosted open weights, but the air-gap constraint is yours (and CSCC-justified). Within the constraint, a verified-intake, best-current open-weight portfolio with staged upgrades is the maximum.
3. **Insider-with-physical-access is bounded, not eliminated** — two-person rules, HSM custody, PAM, WORM audit, physical controls. Elimination is not a property any architecture can offer.
4. **Practical FHE/other in-use crypto for LLM inference does not exist at production speed in 2026;** in-use protection is delivered by physical control + access control (+ optional CC), which is the honest ceiling.
5. **Everything else** (identity, least privilege, supply chain, DLP, audit, DR, governance) is at the strongest published practice with no known stronger alternative deployable air-gapped today.
