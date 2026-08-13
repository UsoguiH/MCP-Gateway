# Secure MCP Architecture — v7 Build Specification

> **Purpose of this document:** A self-contained handoff brief. It gives another Claude instance (or any engineering team) everything needed to build a production-grade, high-security **Model Context Protocol (MCP)** architecture for a **government/critical organization in Saudi Arabia (~500 employees)**. No prior conversation context is required — everything is included here.

---

## 0. How to use this document (instructions for the building agent)

You are being asked to implement the architecture described below. Before writing code or provisioning infrastructure:

1. **Read the whole document first.** The design is layered; each control depends on earlier ones.
2. **Resolve the two open variables** in §2 with the human (financial/SAMA? critical system/CSCC? air-gapped vs. sovereign cloud?). These change specific components.
3. **Build in phases** per §9 — do not attempt everything at once. Each phase is independently testable.
4. **Treat the security controls as requirements, not suggestions.** This is a government, high-security context in the Kingdom of Saudi Arabia. Data residency and auditability are legal obligations, not preferences.
5. **The single most important component is the HA MCP Gateway (§5.4).** It is the one mediated control plane. Build and harden it first.

---

## 1. Context & constraints

- **Sector:** Government / high-security organization in Saudi Arabia.
- **Scale:** ~500 employees (design to scale beyond this).
- **Priority order:** Security first, then performance, then cost.
- **Language:** Arabic-first. Personal data includes Saudi National ID, Iqama, IBAN, etc.
- **Regulatory regime (must comply):**
  - **NCA** — National Cybersecurity Authority: **ECC-2** (Essential Cybersecurity Controls), **CCC** (Cloud Cybersecurity Controls), **CSCC** (Critical Systems Cybersecurity Controls if designated critical).
  - **PDPL** — Personal Data Protection Law, regulated by **SDAIA**.
  - **SAMA CSF** — if the entity is financial.
- **Hard requirement:** All data (at rest, in transit, **in use**) and all model inference must remain **inside the Kingdom**. No cross-border data transfer without explicit legal basis.

---

## 2. Open variables to confirm before building

These change specific components. Confirm with the human first.

1. **Is the entity financial?** → If yes, apply **SAMA CSF** controls (adds HSM, PAM/JIT, stricter audit).
2. **Is it a designated critical system?** → If yes, apply **NCA CSCC** (adds stricter isolation, monitoring, and BC/DR requirements).
3. **Deployment model:** Fully **air-gapped / on-premises** vs. **sovereign cloud region in KSA**. This drives the inference tier (§5.3) and DR strategy (§6).

Default assumption if unanswered: sovereign cloud in KSA, non-financial, treat as critical-adjacent (apply CSCC where reasonable).

---

## 3. Core design principle

**MCP is an attack surface. Centralize and mediate it.**

Never let 500 users' agents connect directly to MCP servers. Everything flows through a single **HA MCP Gateway** that enforces identity, authorization, credential injection, audit, human approval, and prompt-injection containment. Get this choke point right and every other control has a place to attach.

Supporting principles:
- **Zero trust** — no implicit trust from network location; every service authenticates on every call.
- **Least privilege everywhere** — deny by default; grant the narrowest tool/data access that does the job.
- **Defense in depth** — assume any single layer can fail; controls overlap.
- **Data classification drives authorization** — access = user clearance × data label.
- **Untrusted content is data, never instructions** — tool outputs and fetched documents cannot steer privileged actions.

---

## 4. How this design was derived (v1 → v7)

The final architecture is v7 of a deliberate refinement. Each version fixed 5 concrete weaknesses in the prior one. This section is included so the building agent understands *why* each control exists (do not skip controls thinking they're optional — each closes a specific gap).

| Ver | Theme | Hardening added | 5 weaknesses it fixed from the prior version |
|---|---|---|---|
| v1 | Naïve baseline | (insecure starting point) | — |
| v2 | Sovereignty + control | In-Kingdom inference, central gateway, SSO, secrets vault, audit log | (1) data left the Kingdom; (2) no central mediation; (3) no real identity; (4) secrets in config/prompt; (5) no audit trail |
| v3 | Isolation | HA gateway, network segmentation, ABAC + data classification, DMZ for 3rd-party servers, deny-by-default egress | (1) single point of failure; (2) flat network; (3) coarse role-only authz; (4) untrusted 3rd-party servers in trusted zone; (5) no injection/egress defense |
| v4 | Runtime safety + speed | Caching, human-in-the-loop, immutable audit + SIEM, short-lived dynamic secrets, rate limits + kill switch | (1) no performance layer; (2) no HITL for irreversible actions; (3) mutable logs, no SIEM; (4) long-lived static credentials; (5) no rate limiting/anomaly/kill switch |
| v5 | Resilience + data | Multi-AZ/DR in KSA, confidential computing enclave, dynamic tool discovery, DLP for Arabic PII, full observability | (1) no DR/BC; (2) inference not isolated; (3) context bloat from loading all tool schemas; (4) no DLP; (5) weak observability/cost attribution |
| v6 | Zero trust + supply chain | Signed/pinned MCP servers + SBOM + admission control, SPIFFE/SPIRE workload identity, injection quarantine, data-layer classification + tokenization, HSM-backed keys + auto rotation | (1) no supply-chain security; (2) perimeter-only trust; (3) reactive injection defense; (4) classification only at gateway; (5) keys not in HSM, manual rotation |
| v7 | Governance + operations | Policy-as-code + CI/CD security gates, graceful degradation (circuit breakers/fallbacks), PAM + JIT + separation of duties, continuous red-team + eval harness, autoscaling + FinOps, Arabic-first validation | (1) no governance/lifecycle; (2) no graceful degradation; (3) insider/privileged-access risk; (4) no continuous security validation; (5) no scale governance + Arabic validation |

---

## 5. v7 reference architecture

### 5.1 Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│ USERS (500) — hardened clients, Arabic-first UI                        │
│   SSO (national IdP) · mTLS · short-lived scoped tokens                │
└───────────────────────────────┬──────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│ IDENTITY & POLICY  · OIDC/SAML · ABAC (role × data classification)     │
│   Policy-as-code (deny by default) · PAM + JIT for admins              │
└───────────────────────────────┬──────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│ DLP EDGE  — Arabic PII (National ID/Iqama/IBAN) detect + mask, in&out  │
└───────────────────────────────┬──────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│ HA MCP GATEWAY CLUSTER  (the control plane)                            │
│  • per-user authZ on every tool call    • vault: short-lived secrets   │
│  • dynamic tool discovery (tool search)  • HITL approval (irreversible) │
│  • rate limits · anomaly detection · kill switch · circuit breakers    │
│  • prompt/response cache · immutable WORM audit → SIEM                 │
│  • injection QUARANTINE: untrusted content → tool-less path only       │
└───┬──────────────────┬─────────────────────┬─────────────────────┬────┘
    ▼                  ▼                     ▼                     ▼
 INFERENCE TIER   INTERNAL MCP (RO/RW)   DATA MCP (RO)        3rd-PARTY MCP
 confidential     signed+pinned+SBOM     data-layer labels    (DMZ, isolated,
 computing        SPIFFE identity        + tokenization/FPE   no internal reach)
 (SEV-SNP/TDX),   least-privilege        HSM-backed keys
 in-Kingdom,      per-tool creds
 ZDR/min-retain
        └──── zero-trust mTLS between every hop · deny-by-default egress ────┘

 CROSS-CUTTING: multi-AZ + DR in KSA · distributed tracing + cost attribution
 · CI/CD security gates · continuous red-team + injection eval harness · FinOps
```

### 5.2 Identity & policy layer

- Front everything with the organization's **SSO/IdP** (Entra ID, Keycloak, or national IdP) via **OIDC/SAML**. No shared or service accounts for user-facing access.
- **User identity + clearance propagates end-to-end** — the gateway must know *who* is asking before it authorizes *what*. Carry identity to the tool call, not just to login.
- **Short-lived, scoped tokens**; **mutual TLS** on every hop.
- **ABAC** (attribute-based access control): access decision = `user_role × user_clearance × data_classification × tool_risk`. Deny by default.
- **Policy-as-code** — all authorization rules are versioned, reviewed, and testable (e.g. OPA/Rego or equivalent). No ad-hoc rules.
- **PAM + JIT for administrators** — no standing broad admin access; privileged actions are time-boxed, approved, and recorded. Enforce **separation of duties**.

### 5.3 Inference tier (data sovereignty — decide first)

- Model runs **in-Kingdom**: sovereign cloud region in KSA **or** on-prem/air-gapped enclave (per §2).
- **Never** public/foreign model endpoints.
- **Zero or minimal data retention (ZDR)**; contractual data residency; no training on org data.
- **Confidential computing** for the enclave — AMD SEV-SNP / Intel TDX / confidential GPUs so data is protected **in use**, with remote attestation of workloads.
- **Model-tier note:** some frontier models require a minimum data-retention window and are unavailable under strict ZDR. Choose the model tier that matches the retention policy — do not weaken retention to fit a model.

### 5.4 HA MCP Gateway — the control plane (build first, harden most)

Stateless, load-balanced, multi-node cluster. Responsibilities:

1. **Authorize every `tool_use` call** against the caller's identity/clearance before forwarding.
2. **Inject credentials from the vault** at the boundary — the model and its context **never** see secrets. Use short-lived, per-call, per-tool dynamic credentials.
3. **Dynamic tool discovery** (MCP tool search / deferred loading) — load only the tool schemas relevant to a request; keeps context small, latency and cost low, and cache-friendly.
4. **Human-in-the-loop (HITL) approval gate** for irreversible/outbound actions (writes to systems of record, deletes, external messages, financial transactions). Agent proposes; a human approves.
5. **Immutable, tamper-evident audit** (append-only / WORM) of every call: who, what tool, what inputs, what result, approval status. Stream to **SIEM**.
6. **Rate limits, per-user/tool quotas, anomaly detection, and a global kill switch** to instantly disable a tool or user.
7. **Circuit breakers, timeouts, and fallbacks** between gateway↔tools so a failing MCP server degrades gracefully instead of cascading.
8. **Prompt/response/semantic caching** for performance.
9. **Injection quarantine (critical):** untrusted content (documents, web pages, tool outputs) is processed by a **constrained, tool-less path**; only structured, validated results cross into the privileged agent. Privileged tools are **unreachable** from untrusted-content processing. Treat all fetched content as data, never as instructions.

### 5.5 MCP servers

- **Only vetted servers run.** Signed, version-pinned images with **SBOMs** and **admission control** — no unapproved image executes.
- **Zero-trust workload identity** — each server authenticates via **SPIFFE/SPIRE** + mTLS on every call; no implicit trust from network position.
- **Least privilege per server** — its own scoped, short-lived credentials and only the network access it needs.
- **Prefer thin internal MCP servers over your own APIs** rather than exposing raw databases — keeps auth, filtering, and audit in your control.
- **Narrowest tool surface** — fewer tools, fewer parameters, less to abuse. Prefer **read-only** where possible; write/action tools are a separate, more tightly gated category.
- **Third-party/community servers are untrusted code** — run them in an **isolated DMZ** with **no path to internal systems**.

### 5.6 Data layer

- **Classification enforced at the source**, not only at the gateway — so bypassing the gateway (insider/misconfig) does not expose raw data.
- **Tokenization / format-preserving encryption** of sensitive fields (National ID, Iqama, IBAN) so raw PII never flows through the pipeline even if a layer is bypassed.
- **HSM-backed key custody** (hardware root of trust) with **automated key/secret rotation** (scheduled + event-driven).
- **Data minimization into context** — retrieve the least data needed; filter before it reaches the prompt.

### 5.7 Network

- **Deny-by-default egress** from tool-execution environments — reach only an explicit allowlist of hosts. This is the **primary defense against data exfiltration and prompt-injection abuse**.
- **Micro-segmentation**: user tier ↔ gateway ↔ model tier ↔ each MCP server, all firewalled. A breach of one server must not reach another.
- **mTLS on every hop.** No general internet access from tool-execution environments unless a specific, logged, allowlisted need exists.

### 5.8 DLP edge

- Inbound and outbound scanning and masking of **Arabic PII** (National ID, Iqama, IBAN) and classified markers, mapped to PDPL.
- Blocks classified/personal data from entering model context or leaving the boundary without authorization.

### 5.9 Cross-cutting: resilience, observability, governance

- **Multi-AZ HA within KSA + tested DR site** (defined RTO/RPO) — business continuity per NCA.
- **Full observability** — distributed tracing across gateway→model→tools; per-user and per-department **cost attribution**; capacity dashboards.
- **CI/CD security gates** — every new MCP server/tool/agent passes automated policy, SBOM, and injection-eval checks before deployment; changes versioned and approved.
- **Continuous red-teaming + eval harness** — automated regression tests for prompt injection, authorization bypass, and data leakage on every change; periodic adversarial exercises.
- **Autoscaling + FinOps guardrails** — scale with demand; budget guardrails per department; capacity planning for growth.
- **Arabic-first validation** — formal accuracy, safety, and PII-handling evaluation in Arabic.
- **Curated agent knowledge** — version-controlled context bundles (git-managed markdown) served to agents via a read-only MCP server, so agent knowledge is auditable and portable.

---

## 6. Deployment / DR

- Primary: multi-AZ within a KSA region (or on-prem primary + on-prem DR if air-gapped).
- DR: second in-Kingdom site with tested failover, defined RTO/RPO.
- Confidential-computing nodes for the inference tier in both sites.
- Regular DR drills; document and rehearse the runbook.

---

## 7. Compliance mapping

| Requirement | Where satisfied in this design |
|---|---|
| **NCA ECC-2** (identity, least privilege, encryption, logging, monitoring) | §5.2 identity/ABAC, §5.4 audit+SIEM, §5.6 encryption/HSM, §5.7 segmentation, §5.9 observability |
| **NCA CCC** (cloud controls) | §5.3 sovereign in-Kingdom inference, §6 DR, §5.5 supply chain |
| **NCA CSCC** (critical systems — if designated) | §5.3 confidential computing, §5.7 micro-segmentation, §6 BC/DR, §5.9 continuous monitoring |
| **PDPL / SDAIA** (personal data) | §5.3 residency, §5.8 DLP, §5.6 tokenization + data minimization, §5.4 auditability |
| **SAMA CSF** (if financial) | §5.6 HSM, §5.2 PAM/JIT + separation of duties, §5.4 immutable audit, §6 BC/DR |

---

## 8. Technology choices (2026 — indicative, swap for approved equivalents)

- **Identity:** Entra ID / Keycloak (OIDC/SAML); OPA/Rego for policy-as-code.
- **Secrets:** HashiCorp Vault or cloud secrets manager with dynamic secrets; HSM (cloud HSM or on-prem) for key custody.
- **Workload identity:** SPIFFE/SPIRE + service mesh (mTLS everywhere).
- **Confidential computing:** AMD SEV-SNP / Intel TDX; confidential GPUs for inference.
- **Gateway:** custom service (the MCP broker) — this is bespoke; it is the core of the build.
- **Audit/SIEM:** WORM store + your SIEM (e.g. approved SOC platform).
- **Observability:** OpenTelemetry tracing + metrics + cost attribution.
- **CI/CD security:** SBOM generation (e.g. Syft), signing (e.g. cosign/Sigstore), admission control (e.g. OPA Gatekeeper/Kyverno).
- **Model access:** Anthropic Claude via an in-Kingdom sovereign/self-hosted deployment; use the MCP connector and tool-search features; confirm the model tier's data-retention behavior matches policy.

> All vendor choices must be from NCA/SDAIA-approved lists and deployed in-Kingdom. Confirm approvals before procurement.

---

## 9. Recommended build phases

Each phase is independently testable. Do not skip ahead.

1. **Foundation** — SSO/IdP integration, network segmentation, in-Kingdom inference tier with ZDR. *Acceptance: an authenticated user can reach a health endpoint; no traffic leaves the Kingdom.*
2. **Gateway core** — HA MCP Gateway with per-user authZ, vault-based secret injection, immutable audit → SIEM. *Acceptance: every tool call is authorized, logged immutably, and no secret appears in model context.*
3. **Isolation + guardrails** — ABAC + data classification, DMZ for 3rd-party servers, deny-by-default egress, rate limits + kill switch. *Acceptance: a user cannot invoke a tool above their clearance; egress to a non-allowlisted host is blocked.*
4. **Runtime safety + performance** — HITL approval, caching, dynamic tool discovery, circuit breakers. *Acceptance: an irreversible action requires human approval; latency/cost drop measurably under load.*
5. **Data + resilience** — DLP for Arabic PII, tokenization + HSM keys, confidential computing enclave, multi-AZ + DR. *Acceptance: PII is masked in/out; DR failover passes a drill.*
6. **Zero trust + supply chain** — SPIFFE/SPIRE, signed/pinned servers + SBOM + admission control, injection quarantine. *Acceptance: an unsigned server image is refused; injected content in a document cannot trigger a privileged tool.*
7. **Governance + ops** — policy-as-code, CI/CD security gates, PAM/JIT, continuous red-team + eval harness, autoscaling + FinOps, Arabic validation. *Acceptance: a new tool cannot deploy without passing injection/authz eval gates; red-team suite runs on every change.*

---

## 10. Acceptance criteria for "done"

- [ ] No data (at rest/in transit/in use) or inference leaves the Kingdom.
- [ ] Every tool call is authenticated, authorized against user clearance × data classification, and logged immutably to the SIEM.
- [ ] No secret ever enters model context; all credentials are short-lived and vault/HSM-managed.
- [ ] Untrusted content cannot invoke privileged tools (injection quarantine verified by red-team).
- [ ] Deny-by-default egress verified; exfiltration attempts blocked.
- [ ] Irreversible/outbound actions require human approval.
- [ ] Arabic PII (National ID/Iqama/IBAN) masked at the DLP edge and tokenized at the data layer.
- [ ] Multi-AZ HA + in-Kingdom DR pass a failover drill.
- [ ] Unsigned/unpinned MCP servers refused by admission control.
- [ ] Continuous injection/authz eval harness runs on every change and passes.
- [ ] Mapped controls satisfy NCA ECC-2/CCC (+ CSCC/SAMA if applicable) and PDPL — verified with the compliance/accreditation team.

---

## 11. The one thing to get right

**The HA MCP Gateway is the single mediated control plane.** Identity, authorization, credential injection, audit, human approval, and injection containment all live there. Build it first, harden it most, and make it impossible to bypass. Every other control attaches to it.

---

*End of build specification. Confirm the §2 open variables with the human before starting Phase 1.*
