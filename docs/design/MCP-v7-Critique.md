# Critique of MCP-Secure-Architecture-v7-BuildSpec

> Every wrong or bad thing found in v7, given the confirmed constraints:
> **government (non-financial) · ~300 employees · NCA CSCC applies · fully air-gapped on-prem · self-hosted open-weight models.**
> Items are grouped by severity. Each item states what is wrong, why it matters, and what the fix direction is.
> Verified against July-2026 primary sources (MCP spec 2025-11-25 + changelogs, NCA/SDAIA/DGA instruments, published injection-defense research).

---

## Category A — Fatal: the spec contradicts your confirmed constraints

**A1. The inference tier is built around a model you cannot run.**
§8 prescribes "Anthropic Claude via an in-Kingdom sovereign/self-hosted deployment." Claude's weights are not available for self-hosting, and a fully air-gapped environment has no path to any vendor API, sovereign region or not. The entire §5.3 inference tier — and every downstream assumption about model capability (tool search, MCP connector, injection robustness) — is void. The architecture must be rebuilt around self-hosted open-weight models, which are measurably weaker at agentic tool use and injection resistance, which in turn means **more** load on the surrounding controls, not the same.

**A2. "ZDR / minimal retention" is vendor-API language that is meaningless here.**
§5.3's zero-data-retention requirement governs a *provider's* retention of *your* prompts. When you host the weights, there is no provider; retention is entirely your own logging policy. Carrying this requirement forward shows the spec was written for a cloud deployment and never re-derived for air-gap. The real in-scope question — **what the org itself retains** (prompts, outputs, traces contain PII/classified data) — is unaddressed (see C7).

**A3. The identity stack is cloud-dependent in an air-gapped design.**
§8 names **Entra ID** as an IdP option. Entra ID is a cloud service; it cannot authenticate anyone in an air-gapped enclave. Same class of error: Sigstore/cosign as described (§8) depends on the public Fulcio CA and Rekor transparency log — both internet services. The spec's supply-chain controls as written cannot execute offline.

**A4. There is no offline update & ingress pipeline — the defining problem of air-gapped operation.**
Air-gapped security lives or dies on how software, model weights, CVE feeds, signatures, and threat intel *enter* the environment. v7 says nothing about: transfer media policy, an ingress sanitization station, private registry mirroring, offline vulnerability databases, private signing infrastructure, or how "continuous red-team + eval" tooling updates without internet. Every "continuous" control in §5.9 silently assumes connectivity.

**A5. Multi-AZ / sovereign-region DR language doesn't map to physical sites.**
§6 "multi-AZ within a KSA region" is cloud vocabulary. Your DR is a second physical facility with private fiber, replicated HSMs, key escrow, and offline backups — different engineering, different drills, and CSCC has explicit BC/DR expectations for it. Also: GPU capacity must be duplicated at the DR site or you must formally accept degraded-capability DR; v7 never surfaces this (expensive) decision.

**A6. Wrong scale.** Spec says ~500 employees; you are ~300. Minor alone, but sizing, licensing, GPU capacity and cost planning inherit the error — and it signals the spec was not re-checked against reality (consistent with A1–A5).

---

## Category B — Security design flaws (would exist even in the cloud version)

**B1. The injection quarantine (§5.4.9) is a label, not a design.**
"Untrusted content → tool-less path; only structured, validated results cross" hand-waves the single hardest problem in the system. Structured extraction does **not** neutralize injection: a string field extracted from a poisoned document still carries the payload into the privileged context. "Validated" is undefined. As of 2026 prompt injection remains unsolved in the general case; the state of the art is **architectural** — control/data-flow separation (CaMeL-style plan-then-execute with capabilities on data), taint/provenance tracking on every context element, quarantined-LLM processing of untrusted content with the privileged agent consuming only *references*, never raw text — plus egress control and HITL as backstops. v7 names none of the mechanisms, so a builder cannot implement it and a red team cannot test it. (State of the art: CaMeL, arXiv 2503.18813; the design-pattern canon in arXiv 2506.08837; Anthropic's own July-2026 position is explicit that injection defense reduces attack success — to ~1.4% in their best browser-use result — but "is not solved." Prompting-level defenses like spotlighting are shown bypassable, and even out-of-model defenses degrade under adaptive attack, arXiv 2606.26479 — hence backstops are mandatory, not optional.)

**B2. The shared semantic cache is a cross-user data-leak channel.**
§5.4.8 adds "prompt/response/semantic caching" with no partitioning rule. A semantic cache that serves user B an answer generated from user A's higher-clearance retrieval leaks classified data *through the performance layer* — and bypasses ABAC, DLP, and audit while doing it. Caches must be partitioned by (user, clearance, data-classification) or restricted to non-sensitive tiers; v7 doesn't say a word.

**B3. HITL as specified will collapse into rubber-stamping.**
"Human approval for every irreversible/outbound action" across 300 users is an approval-fatigue machine. Within weeks approvers click *approve* reflexively and the control becomes theater — worse than nothing, because it produces false assurance and an audit trail that says "a human checked." Needs: risk-tiered actions (policy-auto-approve low-risk writes), meaningful diff previews, batch approval UX, approver separation-of-duties, approval-rate/latency monitoring to detect rubber-stamping, and periodic canary actions to test that approvers actually look.

**B4. Tool metadata is trusted where it must not be.**
The gateway needs a per-tool risk registry of its own. MCP tool annotations (read-only/destructive hints) are **server-declared** and therefore attacker-controlled for any compromised or third-party server. v7's HITL and authorization tiers have no stated source of truth for "which tools are dangerous" — if that comes from the servers themselves, the control inverts: a malicious server labels its destructive tool read-only and walks through. Also unaddressed: **tool definition drift / rug-pull** (a server changing a tool's description or schema after approval must re-trigger review) — a documented MCP attack class since Invariant Labs' April-2025 disclosure. The MCP spec itself agrees: tool annotations are explicitly untrusted ("clients MUST consider them untrusted" — spec 2025-03-26 onward). v7 never engages with this.

**B5. No threat model exists, so "complete" is unfalsifiable.**
v7 lists controls but never enumerates adversaries (external attacker, malicious insider, compromised MCP server, poisoned model weights, malicious document/prompt injection, compromised admin, physical access at the DR site). Without a threat→control matrix you cannot argue any version is "the best": there is no definition of done. This is the meta-flaw that made v1→v7 an open-ended treadmill of "+5 fixes per version."

**B6. The model itself is missing from the supply chain.**
§5.5 signs and pins MCP *server images* but says nothing about **model weights** — which, self-hosted, are your largest untrusted artifact. Needs: weight provenance and hash verification at ingress, a signed model registry, license review, pre-deployment behavioral/backdoor evaluation, and governance for any fine-tuning on org data (a PDPL processing activity in its own right). Poisoned-weights supply chain is a documented attack class.

**B7. Where do agents actually run? The spec never says.**
One line ("hardened clients") covers the entire client tier. If agent loops execute on 300 user desktops, then tokens, context (with retrieved classified data), and tool-call construction all live on endpoints — the gateway mediates tool calls but a compromised endpoint still holds everything else. The 2026 answer for a CSCC environment is **server-side agent execution**: thin clients render UI; agent loops run in sandboxed, egress-controlled runtimes in the data center. v7 doesn't make this decision, and it's load-bearing.

**B8. DLP is on the wrong edge (only).**
The diagram places DLP between users and gateway. But the highest-volume PII path is **tool results flowing back from data-layer MCP servers into model context**, and the highest-risk path is **model output** synthesized from retrieved data. Inbound-user-text scanning misses both. DLP must sit on the gateway's tool-result path and response path. Additionally: regex-grade detection (ID/Iqama/IBAN) misses names, addresses, and health/context PII — Arabic NER is required, with a stated false-positive handling policy and a clearance-gated unmasking path, or masking breaks the very workflows the system exists for.

**B9. Tokenization/FPE without a detokenization design creates a new crown jewel.**
§5.6 tokenizes PII but never says who may detokenize, through what authorization, or where the token vault lives. The vault becomes the single most sensitive store in the org, and the detokenization API becomes the obvious target. Undesigned = insecure by default.

**B10. The audit log will become your highest-classification database — unprotected.**
§5.4.5 logs "what inputs, what result" for every call. Tool inputs and results contain the PII and classified data everything else in the spec works to contain. The WORM store therefore aggregates it all in one place, indexed and searchable via the SIEM — with no stated access control, field-level protection, retention limit (PDPL requires purpose-bound retention), or data-subject-rights handling. The audit system needs the same protection level as the data layer, and log content needs a minimization policy (hashes/pointers vs. full payloads, tokenized fields in logs).

**B11. The bespoke gateway — "the one thing to get right" — has no secure development story.**
§8 admits the gateway is custom code, the single mediation point for everything. v7 imposes SBOM/signing on third parties but no SDL on itself: no language/memory-safety choice, dependency policy, code review and pen-test requirement, fuzzing of the MCP parser (it parses attacker-influenced JSON-RPC all day), or independent security assessment before go-live. The most attacked component is the least governed.

**B12. Session- and protocol-level hardening is absent.**
Nothing on MCP transport security: session ID entropy/rotation and session hijacking, request smuggling through streaming responses, DNS-rebinding-class issues for any locally-run servers, JSON-RPC batch abuse, schema validation of tool arguments **and results** against declared schemas, or size/recursion limits on tool outputs (a 200 MB tool result is a DoS on the context pipeline). The gateway spec lists policy features but not parser/protocol defenses — and it never even states which MCP spec revision it targets. The current revision (2025-11-25) carries a normative Security Best Practices page with MUST-level rules v7 ignores: servers MUST NOT use sessions for authentication, session IDs must be non-deterministic and SHOULD bind to user identity, servers MUST return 403 on invalid Origin (DNS-rebinding defense), servers MUST NOT accept passthrough tokens not issued to them, clients must use RFC 8707 resource indicators. A 2026-07-28 revision (release candidate, stateless core, removes `Mcp-Session-Id`) lands this month — v7 has no protocol-versioning plan at all.

**B13. Unicode/RTL attack surface — ironic for an Arabic-first spec.**
Arabic-first processing means heavy bidi text. Bidi override characters (U+202E etc.), zero-width joiners, and Arabic-script homoglyphs are documented prompt-injection and content-spoofing vectors (text renders one way to the approving human, reads another way to the model — this directly subverts HITL diff previews). v7's "Arabic-first validation" tests model *accuracy*, not adversarial Unicode. Gateway must normalize (NFKC), strip/flag bidi controls, and render approval previews from the *normalized* form.

**B14. Memory/knowledge poisoning is out of scope but shouldn't be.**
§5.9's "curated agent knowledge" (git-managed bundles) and any RAG index are persistent injection surfaces: one poisoned document in the corpus is a *stored* attack executing across users and sessions — nastier than transient injection. Needs: provenance and review gates on corpus writes, signed knowledge bundles, index rebuild policy, and inclusion in red-team scope. Same for any conversation-memory feature.

**B15. Anomaly detection and SIEM are named, not designed.**
No detection use-cases are defined (what does the SOC actually alert on: tool-call sequence anomalies? first-time tool per user? volume spikes? approval-bypass attempts? egress denials?). No IR playbooks exist for the novel incident classes this system creates: prompt-injection incident, model-behavior incident, tool-compromise incident, mass-exfiltration-via-agent. "Stream to SIEM" without content is a checkbox.

---

## Category C — Operational & realism flaws

**C1. The stack is oversized for the team that must run it.**
K8s + service mesh + SPIFFE/SPIRE + OPA + Vault + HSM + confidential computing + SIEM + custom gateway + GPU inference + DLP + red-team harness — this is a 10–15 FTE platform, run air-gapped (harder), for a 300-person org. Unmaintained complexity decays into misconfiguration, which is itself a top breach cause. The "best" architecture is the one whose controls are *operable* by the actual team; v7 never asks who operates it. Consolidation (e.g., Cilium-native mTLS instead of a full mesh; OpenBao instead of BSL-licensed Vault if licensing matters; one well-integrated platform rather than ten best-of-breed parts) is a security decision, not a convenience.

**C2. Confidential computing is cargo-culted into a threat model where it's weakest-value.**
SEV-SNP/TDX/confidential GPUs primarily defend against an **untrusted host/cloud operator**. In your own air-gapped facility, you *are* the operator; the marginal threat CC addresses is your own rogue infrastructure admin — real, but it's cheaper and more effective to address with PAM, two-person rules, and physical controls first. The July-2026 facts sharpen this: Hopper-class GPU CC is GA and the throughput overhead is near zero for 70B-class models (measured ~0% for Llama-3.1-70B 4-bit) — but **NVIDIA offers no officially supported fully-offline attestation workflow** (the local verifier still performs OCSP checks against NVIDIA cloud; open request nvtrust #135). So v7's unconditional "confidential GPUs + remote attestation" requirement is literally not implementable as specified in an air gap — only an unsupported DIY pattern (mirrored RIMs, cached CRLs) exists. CC must be a justified, phased decision — not an unconditional requirement inherited from the cloud version.

**C3. No GPU capacity model, so performance for 300 users is a hope.**
Self-hosted inference is capacity-bound. v7 offers caching and autoscaling — but you cannot autoscale air-gapped GPUs you didn't buy. Needs: a sizing model (concurrent users × tokens/sec × model size), queueing with priority classes, degradation policy (who gets slowed first), and procurement-lead-time planning. The published data makes this concrete: 4× H100 (FP8, 70B-class) sustains ~250 concurrent requests at ~31 tok/s/user (NVIDIA NIM benchmarks), and a documented VMware case served 300 concurrent users on 4× H100 with a 120B MoE — while an undersized 2× H100 collapses to ~89 s time-to-first-token at the same load. Sizing is the difference between a usable system and a visible failure, and v7 doesn't attempt it.

**C4. "Continuous red-team + eval harness" has no offline supply line.**
Injection attack corpora, eval frameworks, and guardrail models all update constantly — from the internet. Without an ingress channel for security content (mirrored, verified, on media), "continuous" degrades to "frozen at go-live." Ties to A4.

**C5. No people/process layer.**
CSCC and ECC-2 expect security training, personnel vetting for privileged roles, acceptable-use policy, and data-handling SOPs. An AI system adds: user training on injection/social-engineering-via-agent, approver training for HITL, and an AI acceptable-use policy. v7 has zero process controls.

**C6. No governance body or risk-acceptance mechanism.**
Who owns residual risk? Who approves a new tool's risk tier, an ABAC policy change, a model upgrade? v7 has CI/CD gates (automation) but no named human governance (an AI risk board / change advisory with security, data, legal/PDPL seats) and no exceptions register. Compliance audits ask for this on day one.

**C7. Org-side retention policy missing** (the flip side of A2): how long are prompts, outputs, traces, and caches kept; who can query them; how are data-subject requests (PDPL) executed against them. Undefined.

**C8. The kill switch has no drill.**
§5.4.6's global kill switch is only real if it's tested: break-glass procedure, authority to pull it (two-person?), monthly test, and a defined blast radius (per-tool, per-user, per-server, global). Untested kill switches fail when finally pulled.

---

## Category D — Compliance gaps (KSA-specific)

**D1. The spec invents its own data classification scheme instead of using the national one.**
KSA government data classification is set by the NDMO/SDAIA Data Classification Policy (National Data Governance framework, mandatory for public entities): **four levels — Top Secret (سري للغاية), Secret (سري), Restricted (مقيد), Public (عام)** — assigned by impact assessment, with a classification register and handling controls per level. ABAC labels, DLP rules, and audit categories must bind to *those* levels or the compliance mapping in §7 is fiction. v7 also misses **NCA DCC-1:2022** (Data Cybersecurity Controls) and the **National Cryptographic Standards (NCS-1:2020)** — both directly govern the data layer it designs.

**D2. DGA is absent.**
A Saudi government entity answers to the **Digital Government Authority**. The Cloud First Policy makes cloud the default for government IT; an air-gapped on-prem build must either invoke the formal **"Exception from Adopting Cloud Services"** process (DGA, via the RAQMI platform, ~25-day decision) or ground the exception in the CSCC critical-system restriction — either way, a documented filing v7 never mentions. Digital Government Policies V2.0 (March 2024) also applies. v7 maps NCA and SDAIA only.

**D3. SDAIA AI-specific instruments are absent.**
Applicable as of July 2026: **AI Ethics Principles v2 (2023)**, **Generative AI Guidelines for Government** (Jan 2024, refreshed 2025 — requires data-classification compliance before GenAI use and prohibits classified data in external GenAI tools), **AI Adoption Framework** (Sept 2024), and — most importantly — the **draft SDAIA Responsible AI Policy** (public consultation closed May 3, 2026: risk-tiered classification, AI-system registration, audit/assurance for high-risk systems). A government LLM on a CSCC-designated system will almost certainly land in the critical/high tier when it's enacted — the architecture must be designed registration- and audit-ready *now*. v7 treats PDPL as SDAIA's only relevant output.

**D4. Compliance mapping is section-level, not control-level.**
§7 maps to framework *names*. Auditors ask for control-ID-level traceability (ECC-2 control x.y.z → implementing mechanism → evidence). Without a traceability matrix the mapping can't be verified — acceptance criterion #11 is currently untestable.

**D5. PDPL specifics missing:** records of processing activities (RoPA) for the AI pipeline, DPO involvement, privacy impact assessment before go-live, and data-subject rights execution (access/deletion) against logs, caches, and any fine-tuned artifacts.

---

## Category E — Document-quality flaws

**E1. §4's "each version fixed exactly 5 weaknesses" is numerology.** Real defect discovery doesn't quantize to 5 per iteration; forcing it means some listed fixes are padding and some real gaps went unlisted (Categories B–D above prove the latter).
**E2. No stopping criterion.** The v1→v7 narrative has no definition of "best," so v7's implied completeness is rhetorical. The fix is the threat-model matrix (B5) + explicit residual-risk register: *best = every enumerated threat has a mapped, tested, operable control, and remaining risk is bounded by 2026 technology, not by design choices.*
**E3. §0 tells the builder to "resolve two open variables" but §2 lists three.** Sloppy, and now moot — all are resolved.
**E4. Acceptance criteria (§10) aren't all testable as written.** E.g. "no data leaves the Kingdom" is trivially true when air-gapped, while the *actual* risky path (what crosses the air gap on media, in both directions) has no criterion at all.

---

## Verdict on v7

v7 is a competent **cloud** architecture pointed at the wrong deployment. Its core instinct — centralize and mediate MCP through a hardened gateway — survives. Almost everything around that instinct must be re-derived for air-gapped + CSCC + open-weight reality, and the deep gaps (B1–B15) must be closed with named mechanisms, not labels. The next iterations (v8 → final) do exactly that.
