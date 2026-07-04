# MCP Security Blueprint & Project Context

> **Purpose of this file:** A self-contained handoff document for another AI instance (or engineer). It captures (1) the project context, (2) the agreed architecture, and (3) a complete enterprise/government-grade security blueprint for on-premise AI agents connected to internal systems via MCP servers. Everything here runs on-premise — no cloud dependency.

---

## 1. Project Context

**Organization:** A ~200-person, government-affiliated company (شركة تابعة للحكومة). Privacy and **data sovereignty are legally critical** — no company/citizen data may leave the organization's infrastructure.

**Setup:**
- AI agents run **fully locally / on-premise** (local LLM, e.g., Llama/Mistral on on-prem GPU servers). Prompts and data never touch an external API.
- The organization is building **multiple MCP (Model Context Protocol) servers**, connected to a **single MCP gateway**, so local AI agents can read from and act on internal systems.
- Rollout is **incremental**: build the gateway first, then add one MCP server at a time (starting with Gitea, then database schema, then others). This is the correct, low-risk approach — MCP servers are independent, so adding one never breaks the others.

**What MCP is used for:** The local AI agent is otherwise just a chatbot with no access to internal systems. MCP is the bridge that lets it (1) **READ** real internal data, (2) **DO** things (take actions via tools), and (3) **follow the org's rules** (check work against policies/regulations). An MCP server exposes **Tools** (actions), **Resources** (readable data), and **Prompts** (templates) to the agent.

---

## 2. Architecture: How Many Servers, and What They Are

**Model: multiple MCP servers (one per backend system / department), all behind ONE gateway.** Not a single mega-server (security nightmare, no permission separation, single point of failure) and not 40 micro-servers (unmanageable sprawl).

- **The MCP Gateway** = a server too, but a *different kind*. It is the **front door / security desk**: it does authentication, authorization, audit logging, and routing. It holds no business data itself.
- **Each domain MCP server** (Procurement MCP, HR MCP, etc.) = a program that exposes the actual tools for that system. **"Server" is a technical word for a program, not a big machine.**

**Analogy:** The gateway is the reception + security desk at a building entrance (checks your badge, logs entry, points you to the right office). Each department MCP is an office that does the real work.

### How to derive the exact server list (don't copy a template — derive from what you have)
1. **Org chart** — each major department = one candidate MCP server (they are already privacy-isolated by role/law — exactly the boundary you want).
2. **Systems inventory** — each backend system = one candidate MCP server. If HR and Finance are different modules with different owners, keep them as **two servers** so permissions stay separate.

### Candidate servers for a government-affiliated entity
| MCP Server | Real gov function it wraps | Backend system |
|---|---|---|
| Correspondence & Diwan MCP | Official letters, reference numbers, approval routing (المعاملات/الديوان) | Correspondence/Diwan system, DMS |
| Archive & Records MCP | Official archive, historical decisions, retrieval by reference number | Records/archive system |
| Circulars & Regulations MCP | Laws, ministerial circulars, internal policies | Policy repository |
| HR / Civil Service MCP | Employee affairs under civil-service rules (grades, leave, allowances) | HR system (Oracle HCM / SAP) |
| Finance & Budget MCP | Budget execution, spending vs. allocation, reporting to ministry | ERP (SAP / Oracle Financials) |
| Procurement & Tenders MCP | Tenders, vendor eligibility, purchase compliance | Procurement/tenders system |
| Citizen/Beneficiary Services MCP | Public applications, permits, complaints, status tracking | Services/CRM |
| Audit & Compliance MCP | Audit trail, evidence gathering, responses to state audit body | Audit logs + records |

### Development / IT department MCP servers
Git/Source Code (Gitea), Code Review, CI/CD Pipeline, Issue Tracker, Logs & Monitoring, Internal Documentation, Database Schema (read-only), Artifact/Package Registry, Security & Vulnerability, Legacy Code Understanding, API Catalog, Test Generation. **Killer starting trio:** Git + Docs + Code Review.

**Recommended target:** ~6–10 servers total (one per major system/domain), all behind one gateway. **Never** merge HR/Finance/Legal into a shared server — keep sensitive domains isolated.

---

## 3. Security Blueprint (Enterprise / Government-Grade)

> Researched across authoritative sources (NIST, CISA/Five-Eyes, OWASP, IETF, ISO, MITRE ATLAS, MCP spec, and reputable MCP security writeups). Full source list in Section 6.

### The One Principle Everything Hangs On
**The MCP gateway is your single Zero-Trust Policy Enforcement Point (PEP). Every agent→tool call passes through it; nothing reaches an MCP server directly. Each AI agent is a Non-Person Entity (NPE) that acts with the *calling user's* own privileges — never a shared super-account.** This was independently endorsed by NIST 800-207, OWASP, CISA, Docker, and the MCP spec.

**Critical scoping caveat:** The MCP spec itself only covers **authentication/authorization**. It says **nothing** about TLS/mTLS, DLP, PII redaction, or data minimization. Every data-protection control below is a layer you add *on top of* MCP — MCP compliance alone guarantees none of them.

---

### Layer 1 — Zero Trust (NIST SP 800-207)
- Treat each MCP server (Gitea, DB, HR, finance, correspondence) as a **separate protected resource**. Network location confers no trust.
- **Authorize per-call, not per-session** — the gateway checks *which user*, *which tool*, *which parameters* on every call. This is what stops a prompt-injected agent: even if the model is tricked, it still cannot call a tool the user isn't allowed to use (enforced in code, not by model good behavior).
- **Enforce on the action, not just the connection** — authorize the tool call *with its arguments*.
- **PDP/PEP mapping:** the gateway = the **Policy Enforcement Point**; a policy engine (e.g., **OPA / policy-as-code**) = the **Policy Decision Point**; your IdP + agent telemetry = Policy Information Points.
- **Control/data-plane split (NIST requirement):** run the policy engine and gateway admin interface on a **separate management VLAN**, unreachable from the MCP servers or the agent data path.
- Build a **kill-switch** at the gateway to revoke an agent instantly (NIST AI RMF MANAGE 2.3–2.4).
- Corroborating: CISA Zero Trust Maturity Model v2.0 (Identity pillar explicitly covers non-person entities); CSA "Tool-Gateway Chokepoint" concept.

### Layer 2 — Identity & Access (two questions on every call)
| Question | Answer |
|---|---|
| **Which service is calling?** (agent→gateway→server, "workload identity") | **SPIFFE/SPIRE + mTLS.** Each workload gets a short-lived, auto-rotating SVID (prefer X.509). SPIRE does node + workload attestation, eliminating long-lived static credentials. Right-sized for you: a 2-node SPIRE HA pair (PostgreSQL backend) needs ~1 CPU / 1 GB. **Note: SPIFFE = authentication only, not authorization.** |
| **On whose behalf?** (which user, "identity propagation") | **OAuth 2.0 Token Exchange (RFC 8693).** The gateway exchanges the user's token for a new, **downstream-scoped, audience-bound (RFC 8707), short-lived** token where subject=user, actor=gateway/agent, audience=the specific target server. This is **delegation, not impersonation** — bounded by the user's own rights. Microsoft Entra "On-Behalf-Of" is a production reference for the same semantics. |

- **The gateway holds distinct, least-privilege credentials per backend** — never one omnipotent agent account. (A gateway aggregating every backend is a high-value target; per-backend scoping limits blast radius.)
- **Token passthrough is FORBIDDEN by the MCP spec** — "MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server." If a server calls an upstream API it MUST obtain a *separate* token. Passthrough breaks audit, bypasses downstream controls, enables replay.
- **Confused-deputy defense (the central agentic risk):** maintain a **per-client, per-user consent registry** checked before forwarding to any auth server; exact `redirect_uri` matching; PKCE (S256) mandatory.
- **Authorization in depth:** primary PEP at the gateway; where feasible, each MCP server also filters which tools/resources it exposes to a given user (authorization *before visibility* — strip unauthorized tools from `tools/list`). Use a shared policy engine (OPA) so rules are version-controlled.
- **Secrets management (on-prem, sovereign):** self-host **OpenBao** or **Infisical CE** (HashiCorp Vault is now BSL-licensed). Use **dynamic DB credentials** — a unique, short-lived (~1h TTL) credential generated per request, auto-revoked. **Never** put secrets in `mcp.json` / `.env` (documented git-leak vector); inject at process spawn / retrieve at runtime from the vault, not as persistent env vars.
- **PKI / key protection:** internal CA (step-ca, OpenBao PKI, or AD CS) issuing short-lived (24–72h) auto-rotated certs. For key custody, an on-prem **HSM** with a **current FIPS 140-3** cert (verify in NIST CMVP database). Budget/air-gap note: native HSM auto-unseal needs Vault Enterprise; an OSS-compatible path is a dual-HA **Transit auto-unseal** cluster kept fully on-prem.

### Layer 3 — Network Isolation
- **Microsegment: one isolated zone per MCP server** (Gitea, DB, HR, finance, correspondence each get their own zone). Default posture between zones = **deny**. The *only* permitted east-west path into each zone is **from the gateway, over mTLS, to that one server's port.** MCP servers cannot talk to each other at all — this kills "tool shadowing" at the network layer. (CISA now frames microsegmentation as a foundational, prioritize-early control; lateral movement appeared in 44% of 2025 breaches.)
- **Default-deny egress** on every MCP server and the agent runtime. This prevents data exfiltration and C2 callbacks if a server is compromised. **Since agents are fully local, NO MCP server needs internet access at all — enforce as a hard rule.** Allow only specific internal destinations (its backend, the vault, the SPIRE server). Apply at initial deployment (far easier than retrofitting).
- **Right-sizing (important):** a full Istio/Linkerd **sidecar service mesh is likely OVERKILL** for a handful of internal servers. **Recommended baseline:** each server in its own VM/container with host firewalls + **Kubernetes NetworkPolicy set to default-deny ingress+egress** on a CNI that enforces it (**Calico, Cilium, or Antrea** — a bare NetworkPolicy object does nothing without one). NetworkPolicy is L3/L4 only. **Add a mesh only if** you later want L7 identity-based authz — **Linkerd** is simpler than Istio for a small team (but it accepts plaintext from non-meshed sources by default, so mesh every pod); **Istio** is more powerful (its `AuthorizationPolicy` can restrict *which SPIFFE identity* may call a service) but defaults to permissive mTLS + allow-all until you set STRICT + explicit ALLOW policies.
- **Air-gap** the whole stack (agents, gateway, servers, IdP, vault, SPIRE, HSM) with **no cloud KMS/IdP dependency** (self-hosted Keycloak IdP + Vault/OpenBao Transit unseal). This directly satisfies the legal data-sovereignty requirement.

### Layer 4 — MCP / LLM-Specific Threats (the new attack surface)
MCP's structural weakness: **tool descriptions AND tool outputs are injected into the model as trusted instructions**, while the agent holds real state-changing access. These are documented with real CVEs — not theoretical.

| Attack | What it is | Defense |
|---|---|---|
| **Tool poisoning** (OWASP MCP03) | Malicious instructions hidden in a tool's *description*, invisible in the UI but read by the model as ground truth (Invariant Labs PoC exfiltrated SSH keys via a trivial `add()` tool) | Scan with **MCP-Scan** (runs locally/air-gapped) |
| **Tool shadowing** | A malicious server's tool description overrides the behavior of a *different trusted* server in the same session (e.g., silently redirect `send_email`) | Network isolation + gateway per trust boundary |
| **Rug-pull** | An approved tool's definition silently changes later (MCP caches approval, never re-checks) | **Hash-pin every tool definition (SHA-256) at approval; re-verify before every call; alert on mismatch.** One-time approval is insufficient. |
| **Indirect prompt injection** | Malicious instructions inside data the agent *reads* — a poisoned Git issue, a DB row, an incoming correspondence doc (the "GitHub MCP" case exfiltrated private-repo data via a public issue) | Treat all read-in data as hostile; **sanitize tool outputs** (strip `<IMPORTANT>`, hidden HTML, imperative verbs) before they re-enter model context; prefer structured data over raw HTML |
| **Lethal trifecta** | Private data + untrusted content + an exfil channel present in one session | Break at least one leg — isolate scope per session (e.g., one-repo-per-session for Gitea) |
| **Confused deputy (OAuth)** | Static client_id + prior consent cookie → auth code issued to attacker | Per-client consent registry, exact redirect-URI match |
| **Token passthrough** (spec-forbidden) | Server accepts/forwards a token not issued for it | Enforce audience binding at the gateway |
| **SSRF via OAuth metadata discovery** | Malicious server points discovery URLs at internal IPs / `169.254.169.254` | Block private/link-local ranges; enforce HTTPS |
| **Over-broad scopes** (OWASP MCP02) | Wildcard `files:*` / `admin:*` → one leaked token grants everything | Scope minimization; per-tool scopes, no wildcards |

**Real published CVEs / incidents (proof this is not theoretical):**
- **CVE-2025-6514** — `mcp-remote` OAuth proxy (~437k downloads): malicious server → OS command injection / full RCE. CVSS 9.6. **Fix: ≥ 0.1.16.**
- **CVE-2025-49596** — Anthropic MCP Inspector unauthenticated proxy → RCE via DNS-rebinding. CVSS 9.4. **Fix: ≥ v0.14.1** (or remove from prod).
- **Asana MCP (Jun 2025)** — tenant-isolation bug exposed ~1,000+ orgs' data across tenants.
- **Backslash "NeighborJack"** — hundreds of public MCP servers bound to `0.0.0.0` (whole-LAN exposure). **Ensure no server binds to `0.0.0.0` on an untrusted LAN.**
- **OX Security (Apr 2026)** — systemic RCE-class issue in official MCP stdio SDKs (est. 200,000+ servers). **Treat every locally-run MCP server — even "official" ones — as code you must vet and sandbox.**

**OWASP Top 10 for LLM Applications 2025** (most relevant to MCP in bold): **LLM01 Prompt Injection**, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, **LLM06 Excessive Agency**, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption. Also consult the **OWASP MCP Top 10 (beta)** and **OWASP Top 10 for Agentic Applications 2026**.

**Human-in-the-loop is MANDATORY (a security requirement in the MCP spec, not UX):**
- Default all agents to **read-only**; every **write/state-changing** action (DB write, fund transfer, sending correspondence, Git push/merge) requires **explicit human approval**.
- Show the **complete, unsummarized** tool parameters to the approver.
- The confirmation UI **must not be bypassable** by LLM-generated content; never auto-approve in a multi-server environment.
- Do **not** trust tool annotations (`readOnlyHint`, `destructiveHint`) for auto-approval unless the server is a trusted tier — the spec says clients MUST treat annotations as untrusted otherwise.
- Use MCP **Elicitation** (spec 2025-06-18) for structured, schema-validated confirmation dialogs.

**Gateway hardening controls:** default-deny **tool allow-list** scoped by role; **separate gateway instances per trust boundary** (e.g., finance/HR surface separate from general dev-assist); detect/block "shadow" MCP servers; strict **input validation** (JSON Schema with `additionalProperties:false`, enums/regex instead of free-text/URLs, never build shell/SQL by string concatenation — use `execFile`/`spawn` arg arrays + parameterized queries); **sanitize/validate tool outputs** before they re-enter context. Deployable on-prem gateways: `lasso-security/mcp-gateway`, `agentic-community/mcp-gateway-registry`, **Docker MCP Gateway** (each server in its own container, no host FS by default, `no-new-privileges`, signed catalog images with SBOMs).

### Layer 5 — Runtime & Supply-Chain Hardening
- **Container baseline for every MCP server** (OWASP Docker Cheat Sheet, NIST SP 800-190): rootless/non-root, `--cap-drop all` (add back only what's needed), `--read-only` root FS + `--tmpfs` for writable paths, `--security-opt no-new-privileges`, CPU/mem limits, no host network, bind only to needed interfaces (never blanket `0.0.0.0`).
- **Stronger sandboxing for code-executing servers** (anything running shell/model-generated/third-party code): **gVisor** (user-space kernel, drop-in with Docker/containerd) or **Firecracker** microVMs (own kernel per workload, VM-grade isolation between sensitivity tiers). Standard containers share the host kernel and are a weaker boundary (NIST 800-190 caveat).
- **Kernel-level MAC / syscall filtering:** keep **seccomp** (Docker default blocks ~44 dangerous syscalls; tighten per server) + **AppArmor or SELinux** profiles. In K8s: `securityContext.seccompProfile: RuntimeDefault` + `readOnlyRootFilesystem: true` (NSA/CISA K8s Hardening Guidance).
- **Least-privilege service accounts — one per MCP server** (NIST SP 800-53 AC-6; strongest blast-radius control): a **dedicated minimally-scoped DB account per server** (correspondence server reads correspondence tables only; finance server cannot touch HR schemas; read-only where the agent only reads). Separate OS user + separate credentials + separate segment per server. No shared "god" account. Progressive scope elevation, never up-front wildcards.
- **Supply chain:** generate an **SBOM** per image (**Syft**; CISA 2025 Minimum Elements); scan every build (**Trivy / Grype**, gate/block on criticals, re-scan on rebuild); **sign every image** with **Sigstore/cosign** (keyless OIDC works on-prem with your IdP) and **enforce signed-only via an admission controller**; target **SLSA Build L2+** (aim L3 for most sensitive servers) for cryptographically signed build provenance. Closes the rug-pull / trojaned-package gap at the infra layer.
- **Governance backdrop for a gov body:** align docs with **NIST AI 600-1** (its "Value Chain and Component Integration" risk maps to third-party MCP servers), **NIST SP 800-161** (C-SCRM — vet servers before connection), **NIST SP 800-218A** (secure GenAI dev), and joint **CISA/NSA "Deploying AI Systems Securely."**

### Layer 6 — Data Protection
- **Encryption in transit:** TLS 1.3 (min 1.2) on **every hop** — don't trust the internal LAN. Prefer **stdio** for co-located agent↔server pairs (no network TLS concern); standardize on **Streamable HTTP** for remote and **retire legacy SSE** (DNS-rebinding weakness). Terminate TLS at the gateway (agent→gateway carries OAuth/JWT user identity), then **mTLS gateway→each server** via internal CA with short-lived auto-rotated certs. Note: TLS alone is insufficient — a compromised proxy can alter payloads after termination; for provable end-to-end integrity add application-layer message signing (ECDSA P-256, fail-closed). A content-inspecting DLP gateway must terminate TLS — document this as a hardened trust boundary.
- **Encryption at rest** (NIST SC-28/SC-12/IA-5): LUKS2 (Linux) / BitLocker+TPM+PIN (Windows); harden hosts with CIS Benchmarks. DB: MySQL/MSSQL have native TDE; **PostgreSQL has no built-in TDE** — use LUKS + `pgcrypto` for the most sensitive columns. Store keys separately from data.
- **Data classification (load-bearing control):** adopt a 4-tier, ISO-aligned, CUI-compatible scheme — **Public / Internal / Confidential (HR-PII, finance, contracts ≈ CUI Basic) / Restricted (credentials, export-controlled ≈ CUI Specified).** **Tag every MCP server (not just documents) with a max classification tier at registration** — this is the load-bearing control since per-server enforcement is unreliable. Default-deny at the gateway; the session **inherits the human user's clearance**, never a shared high-privilege identity. Tier → capability: Public/Internal = read+write autonomous; Confidential = read autonomous, **writes require human confirmation/step-up**; Restricted = **read-only, broker-mediated, purpose-bound, no write tools, named approver, network-isolated.**
- **DLP for tool outputs (self-hosted, inline):** most gateways control *which* tools an agent reaches but never inspect the *data inside* the call. Add a self-hosted inline DLP layer at the gateway inspecting the **payload** at two points — **pre-call** (tool arguments, before they hit internal systems) and **post-call** (tool response, before it enters LLM context) — **fail-closed** on scanner error/timeout. Two-layer detection: **regex** (national IDs, cards, API keys) + self-hosted **NER** for unstructured PII. Roll out in **warn/log-only mode first** to tune false positives, then switch to block/redact. Buffer streaming responses fully before scanning.
- **Tokenization & PII redaction before the LLM context:** self-host **Microsoft Presidio** as a sidecar at the gateway's **post-tool hook** (correct interception point for HR/finance/correspondence responses). Add custom recognizers for national-ID / employee-ID / case-file formats. Per-tool policies: "draft reply to citizen X" needs the name → **reversible tokenization** (per-session token↔value map held **inside the trust boundary only**, rehydrated at final human output); "quarterly finance summary" → **irreversible redaction**. The token-mapping store never appears in LLM context, logs, or cache. Treat redaction as a second layer (not 100% recall) paired with field-level scoping.
- **Data minimization in tool responses** (GDPR Art. 5(1)(c); goes beyond MCP/OWASP baseline): **never expose a generic `execute_sql`/`run_query` tool** — replace with **narrow parameterized tools** (`get_revenue_for_month(month, year)`) whose field list is fixed by the author (structural column minimization). Enforce **hard row caps at the gateway** (default 50–100, ceiling 500–1,000, auto-inject `LIMIT`, fetch `limit+1` to compute `has_more`, honest `total_count` with explicit truncation notices). Field-level allow-lists per tool keyed to user/agent role at the server's serialization layer; use the gateway for **filtered discovery** (strip unauthorized tools/fields from `tools/list`).

### Layer 7 — Detection, Response & Governance
- **SIEM integration:** MCP defines no mandatory audit format, so the **gateway is the single logging choke-point.** Log per tool call (structured JSON): correlation/request UUID, UTC timestamp, authenticated user/agent + session ID, target server, MCP sub-activity (`initialize`/`tools/list`/`tools/call`), tool name, **input params scrubbed of secrets/PII** (mark `payload_redacted:true`), authorization decision + reason, response status/size, success/error code, latency, source IP. On-prem stack: **Wazuh** (open-source SIEM/XDR; built-in PCI-DSS/GDPR/NIST dashboards; ~8 vCPU/16 GB handles ~500 endpoints) + **Graylog/OpenSearch** for high volume. Correlate tool-call logs with identity/auth logs (impossible-travel, failed logins).
- **Immutable / tamper-evident audit logging** (NIST SP 800-53 **AU-9(1)** write-once + **AU-10** non-repudiation — effectively mandatory for gov systems): gateway writes each event into an **append-only, hash-chained log** (each entry stores `sequence_number`, `entry_hash` = HMAC-SHA256 over canonical fields, `prev_entry_hash`; HMAC key held only by the logging service). Periodically checkpoint chain hashes to **WORM on-prem storage**; run scheduled chain-verification; keep the audit store in a **separate trust domain** from the gateway it audits. **Gov records caveat:** AI prompts/outputs by government employees are likely **public records** subject to disclosure/retention — resolve per data category (raw prompts may be transitory; AI outputs feeding official work inherit that product's retention schedule). Keep logs **retrievable** for FOIA-style requests.
- **Anomaly detection & UEBA (agent as a non-human identity):** baseline each agent/service account over a 2–60 day window (typical tool-call volume, hours, servers, response sizes). Alert on: volume/error spikes ("identity saturation" → compromised credential); off-hours or out-of-sequence tool chains (prompt-injection indicator); credential used outside its normal resource context (confused-deputy/privilege abuse); internal→cross-boundary latency shift (exfil proxy). Anchor to **MITRE ATLAS** — **AML.T0085.001 (AI Agent Tools)** "tool invoked outside scope/sequence/rate envelope" and **AML.T0024 (Exfiltration via AI Inference API).** Correlate the input (prompt) event to the downstream tool action — single-surface monitoring is insufficient. Alert on **deviation + a sensitive-data-classification signal in the same event**, not volume alone.
- **Rate limiting at the gateway** on **three independent keys**: **per-user/identity** (contain a runaway session), **per-tool** (tight ceilings on expensive/destructive ops — e.g., ~3/min for DB writes/bulk email vs ~10/min for cheap reads), **per-MCP-server** (stop one compromised server cascading). Prefer **token-bucket** (absorbs bursty list-then-read). Start at ~95th percentile of normal usage; return machine-readable **HTTP 429 + `Retry-After`** — **never silently return empty data.** Feed every 429 to the SIEM as an anomaly indicator. (OWASP LLM06 core Excessive-Agency control.)
- **SOC operations & incident response** (NIST SP 800-61r3, 2025, aligned to CSF 2.0's six functions): build a **lightweight AI-agent IR playbook** with agent-specific containment — (a) **suspend the specific tool/route binding at the gateway** as the *first* step (not a full agent shutdown); (b) **identity-scoped access revocation** (preserve unrelated access); (c) escalate data-classification thresholds on affected routes. Decision tree: *"prompt injection, compromised MCP server, or misconfiguration?"* Every response depends on **correlation-ID-based log reconstruction.** Run **≥1 tabletop/year** simulating: agent compromised via indirect prompt injection → accessed HR/finance records → attempted exfiltration via the correspondence/email MCP server. **Precedent:** Anthropic's Nov 2025 disclosure of the first AI-orchestrated cyber-espionage campaign (targets included government agencies) named four org failures that map exactly here: no centralized AI-usage visibility, absent per-agent access controls, SIEM not ingesting AI logs at agent volume, no audit trail to reconstruct agent actions.

### Governance & Compliance Framework Convergence
All five frameworks point to the **same control spine:** *registry/inventory of MCP servers → third-party vetting before onboarding → least-privilege per-tool RBAC enforced at the gateway → immutable invocation logging to SIEM → change-controlled onboarding with segregation-of-duties sign-off → periodic re-certification.* (CSF GV.SC ↔ ISO A.5.19–5.23 ↔ SOC 2 CC8/CC9 ↔ AI RMF Value Chain ↔ SSDF/SP 800-53.)

- **NIST CSF 2.0:** new **Govern (GV)** function; **GV.SC (Supply Chain, 10 subcategories)** is the anchor for treating each MCP server as a "supplier" (policy, contractual reqs, pre-onboarding due diligence, ongoing monitoring, IR inclusion, decommission). Identify = live register; Protect = least-privilege at gateway; Detect = tool-invocation anomaly detection; Respond = agent-misuse runbook; Recover = instant single-server disable/rollback. (NIST extending to AI via draft IR 8596 "Cyber AI Profile.")
- **ISO/IEC 27001:2022 (+ 42001:2023):** treat each server as a supplier, each tool call as privileged access. Key Annex A: **A.5.19–A.5.23** (supplier/ICT supply chain), A.5.15 access control, **A.8.2 privileged access**, A.8.9 config mgmt, **A.8.15/8.16 logging**, A.8.24 crypto, A.8.29 security testing before prod, **A.8.32 change mgmt**, A.5.9/5.12/5.13 classification. **ISO/IEC 42001** (first AI management-system standard) adds AI impact assessment, lifecycle, model provenance — position for combined **27001 + 42001** cert. Maintain an **"MCP Server Onboarding & Supplier Register"** mapping each server to an A.5.19–5.23 checklist **before the gateway grants a route.**
- **SOC 2 (Trust Services Criteria):** **CC6 Logical Access** (restrict + quarterly review which agents reach which servers; least-privilege scopes; time-bound elevation; treat agents as service accounts); **CC7 Operations** (continuous monitoring + immutable time-synced logs; AI-misuse IR); **CC8 Change Mgmt** (MCP onboarding change log with initiator/justification/risk/approval + version control over configs/system prompts/tool manifests); **CC9 Risk** (vendor/subprocessor incl. data-residency). Add **Confidentiality** + **Processing Integrity** (input validation + approval gates before an agent commits code or sends email).
- **NIST AI RMF (AI 100-1) + Gen-AI Profile (AI 600-1):** Govern/Map/Measure/Manage. Most relevant AI 600-1 risks: **Value Chain & Component Integration** (third-party MCP servers → provenance records, integration testing, MG-3 continuous monitoring), Data Privacy, Information Integrity/Confabulation (agents acting on unverified tool outputs), Human–AI Configuration.

### Governance process for approving/registering a NEW MCP server
Synthesized from NIST SSDF (SP 800-218/218A), SP 800-53 (CM/SA/AC), SP 800-161, SLSA v1.1:
- **Step 0 — Registry gate (no shadow servers):** single authoritative inventory of approved, version-pinned servers; install from a *private* registry, never direct public install.
- **Step 1 — Change request + impact analysis** (CM-3/CM-4): change-control board decision + written downstream-impact analysis.
- **Step 2 — Vendor/supply-chain risk assessment** (SA-9/SA-22): provenance, maintainer stability, foreign ownership/control, cyber hygiene.
- **Step 3 — Code/config/provenance review** (SSDF PW.4/PW.7): SBOM + CVE scan, signature integrity, expert review for backdoors, verify signed provenance (SLSA L2/L3), **pin tool definitions by cryptographic hash**.
- **Step 4 — Least-privilege scoping** (CM-7): mission-essential only, **per-tool** scoping, no wildcards, per-server scoped short-lived credentials, OAuth 2.1 + PKCE + **RFC 8707 audience-bound tokens**, token passthrough forbidden.
- **Step 5 — Sandbox/staging test** with minimal privileges before production.
- **Step 6 — Sign-off + gateway registration** as the single enforcement point.
- **Step 7 — Ongoing re-certification** (SA-9/RV.1.1): continuous compliance monitoring, re-review on new CVEs, automated drift detection (`mcp-scan`), defined re-cert cadence.

### Change control & access governance
- **NIST RBAC** with roles split by tool risk (**read-only / write-mutate / admin**), justified by **AC-6**. Gateway must **mechanically enforce** (AC-3 default-deny tool ACLs + filtered discovery), not merely document.
- Each **agent-persona = a governed non-human identity** with a named human owner, scoped credentials, business purpose, expiration, revocation path — centralized in the IdP (Keycloak), with **just-in-time step-up** for high-privilege tools rather than standing grants.
- **Segregation of duties (AC-5):** the requester of a tool grant must not be its approver; access-admin ≠ audit-admin.
- **Access-review cadence:** quarterly baseline; **monthly/continuous for write-capable agents**; auto-disable expired/inactive identities (AC-2(3)).

---

## 4. Prioritized Rollout (highest leverage first)

**Items 1–5 are largely configuration changes, not architecture — achievable in hours/days:**

1. **Unique scoped identity per agent, with a named human owner. Kill every shared/broad service account.** — highest-leverage single control. *"If the agent doesn't have a permission, it can't be tricked into using it."*
2. **Default-deny at the gateway; agent session inherits the user's clearance; per-tool scopes; short-lived credentials; forbid token passthrough; default read-only + human approval for writes (full unsummarized params shown).**
3. **Secrets out of config files** → OpenBao/Infisical CE + dynamic short-lived DB creds. Disk encryption (LUKS2/BitLocker) + CIS baselines.
4. **Centralized immutable, hash-chained logging → self-hosted Wazuh from day one** (AU-9/AU-10 into WORM). Ensure logs retrievable for records/FOIA obligations.
5. **Post-tool DLP/redaction hook (self-hosted Presidio), fail-closed, warn-mode first.**
6. **Microsegment** each server; **default-deny east-west + egress**; no server needs internet.
7. **mTLS gateway↔servers** via internal CA (auto-rotated short-lived certs); stdio for co-located pairs; retire SSE. **Container baseline** (non-root, cap-drop all, read-only FS, no-new-privileges, seccomp, resource limits).
8. **Hash-pin tool definitions** and alert on any change (MCP-Scan) — rug-pull defense; makes one-time approval durable.
9. **MCP Server Onboarding Register + approval gate** (Steps 0–7) with **segregation of duties** — blocks shadow servers; satisfies CSF GV.SC / ISO A.5.19–5.23 / SOC 2 CC8.
10. **Then the heavier layers:** SPIFFE/SPIRE + RFC 8693 token exchange; gVisor/Firecracker for code-executing servers; cosign signing + admission control; SLSA L2→L3; FIPS 140-3 HSM; **one AI-agent IR tabletop/year**.

**Patch immediately:** `mcp-remote` ≥0.1.16 (CVE-2025-6514), MCP Inspector ≥0.14.1 or remove (CVE-2025-49596). Ensure **no server binds to `0.0.0.0`** on an untrusted LAN.

**Operating posture (NCSC / Five-Eyes "walk before you run"):** pilot on low-risk tasks, keep a human-in-the-loop approving consequential/write actions on Confidential/Restricted data, expand only as monitoring maturity grows.

---

## 5. The Mental Model (one-paragraph summary)

Put **one MCP gateway** in front of **one MCP server per backend system/department**. The gateway is the Zero-Trust enforcement point: it authenticates the workload (SPIFFE/mTLS), carries the *user's* identity to each backend (RFC 8693 token exchange, audience-bound, no passthrough), authorizes every individual tool call against per-tool RBAC, redacts PII and runs DLP on the payload, enforces default read-only with human approval for writes, and writes an immutable hash-chained log of everything to a SIEM. Each server runs isolated (own network zone, own least-privilege DB account, own hardened container, default-deny egress). Treat all data the agent *reads* as hostile (prompt-injection defense), hash-pin tool definitions (rug-pull defense), and gate every new server through a change-controlled onboarding register (no shadow servers). Air-gap the whole stack — that is your data-sovereignty guarantee. **Principles: Zero Trust · Least Privilege · Defense in Depth · Assume Breach · Human in the Loop.**

---

## 6. Sources (authoritative)

**Standards & government:**
- NIST SP 800-207 *Zero Trust Architecture* — https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf
- CISA *Zero Trust Maturity Model v2.0* — https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf
- CISA *Microsegmentation in Zero Trust, Part One* (2025) — https://www.cisa.gov/sites/default/files/2025-07/ZT-Microsegmentation-Guidance-Part-One_508c.pdf
- NIST Cybersecurity Framework 2.0 (CSWP 29) — https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- NIST AI RMF (AI 100-1) — https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf ; Gen-AI Profile (AI 600-1) — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- NIST SP 800-53r5 (AU-9, AU-10, AC-4/5/6) — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-190 *Application Container Security* — https://csrc.nist.gov/pubs/sp/800/190/final
- NIST SP 800-61r3 *Incident Response* — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-188 *De-Identification* — https://csrc.nist.gov/pubs/sp/800/188/final
- NIST SP 800-161r1 *C-SCRM* — https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final ; SSDF SP 800-218/218A — https://csrc.nist.gov/pubs/sp/800/218/a/final
- Joint CISA/NSA *Deploying AI Systems Securely* (2024) — https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely

**MCP & LLM security:**
- MCP Security Best Practices — https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices ; Authorization — https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization ; Tools — https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- OWASP Top 10 for LLM Applications 2025 — https://genai.owasp.org/llm-top-10/ ; MCP Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html ; OWASP MCP Top 10 (beta) — https://owasp.org/www-project-mcp-top-10/
- Invariant Labs — Tool Poisoning — https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks ; MCP-Scan — https://invariantlabs.ai/blog/introducing-mcp-scan ; GitHub MCP exfiltration — https://invariantlabs.ai/blog/mcp-github-vulnerability
- Simon Willison — The Lethal Trifecta — https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- CyberArk — "Poison Everywhere" (output poisoning) — https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe
- JFrog — CVE-2025-6514 — https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/ ; Oligo — CVE-2025-49596 — https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596
- OX Security — systemic MCP SDK issue (2026) — https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
- Anthropic — first AI-orchestrated cyber-espionage campaign (2025) — https://www.anthropic.com/news/disrupting-AI-espionage

**Identity, network, runtime, supply chain:**
- IETF RFC 8693 *OAuth 2.0 Token Exchange* — https://datatracker.ietf.org/doc/html/rfc8693
- SPIFFE concepts / X.509-SVID — https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
- HashiCorp Vault DB dynamic secrets — https://developer.hashicorp.com/vault/tutorials/db-credentials/database-secrets (note: Vault now BSL — consider OpenBao/Infisical CE)
- OWASP Docker Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- gVisor — https://gvisor.dev/ ; Firecracker — https://firecracker-microvm.github.io/
- SLSA build levels — https://slsa.dev/spec/v1.0/levels ; Sigstore/cosign — https://docs.sigstore.dev/cosign/verifying/verify/ ; CISA 2025 SBOM Minimum Elements — https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom ; Syft — https://github.com/anchore/syft ; Trivy — https://github.com/aquasecurity/trivy
- MITRE ATLAS — https://atlas.mitre.org/
- ISO/IEC 42001 — https://www.iso.org/standard/42001 ; AICPA Trust Services Criteria (SOC 2) — https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

**Deployable on-prem gateways:** `lasso-security/mcp-gateway` — https://github.com/lasso-security/mcp-gateway ; `agentic-community/mcp-gateway-registry` — https://github.com/agentic-community/mcp-gateway-registry ; Docker MCP Gateway — https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/

---

## 7. Verification Caveats (be honest about these)
- **MCP security guidance is very new and iterating fast** — the auth spec changed materially across 2024 → 2025-06 → 2025-11. Cite the current spec but re-check before final adoption.
- **OWASP MCP Top 10** and **CSA agentic profiles (2026)** are **beta/draft**, not finalized standards — use for direction, verify against later revisions.
- Several **CISA/NIST PDFs bot-blocked** automated fetching; claims were cross-validated via secondary sources — **download the primary PDFs manually before quoting verbatim** in a formal document.
- Vendor market-share stats (e.g., "X% of MCP servers use static keys") are vendor-sourced/directional, not peer-reviewed.
- **No NIST-published agentic-AI/MCP-specific security profile exists yet** (as of mid-2026), and no authoritative government standard specifically on air-gapped AI for data sovereignty — treat these as documented gaps and rely on the frameworks above plus your national data-protection law.

---

*End of handoff document.*
