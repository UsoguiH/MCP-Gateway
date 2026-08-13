# Enterprise MCP Platform — Research & Planning (Phase 1: Research)

**Date:** 2026-07-02
**Scope:** How the biggest companies (Anthropic, OpenAI, Google, Microsoft, AWS, Block, Cloudflare, GitHub, and others) use the Model Context Protocol — their architectures, stacks, languages, and build approaches — plus the Saudi Arabia compliance/hosting landscape for a ~200-employee, sovereignty-first deployment.

---

## 1. What MCP Is and Who Governs It

- MCP is an open protocol (JSON-RPC based, client–server) created by **Anthropic**, launched **November 2024**. It standardizes how AI applications connect to tools, data, and prompts via three primitives: **Tools** (callable functions), **Resources** (file-like data), and **Prompts** (templates).
- Design was directly inspired by the **Language Server Protocol (LSP)**. It began as an internal Anthropic project (~July 2024) by two engineers frustrated with copy-pasting between Claude Desktop and IDEs; an internal hackathon validated it before public release.
- Transports: **stdio** (local process) and **Streamable HTTP** (remote; superseded HTTP+SSE).
- In late 2025 Anthropic **donated MCP to the Agentic AI Foundation under the Linux Foundation** — it is now a vendor-neutral standard backed by Anthropic, OpenAI, Google, Microsoft, AWS, and others. This matters for you: building on MCP is not a bet on one vendor.
- The **November 2025 spec revision requires OAuth 2.1 with PKCE (S256)** for any internet-accessible MCP server, with audience-bound scoped tokens.

## 2. Company-by-Company: How the Big Players Use MCP

### 2.1 Anthropic (creator)
- **Use:** MCP is the extension mechanism for Claude Desktop, Claude Code, and claude.ai "Integrations" (remote MCP servers reachable by URL).
- **Architecture:** Host app (Claude) embeds an MCP **client** per connection; servers run locally (stdio) or remotely (Streamable HTTP + OAuth 2.1).
- **Notable engineering guidance:** "Code execution with MCP" — for large tool catalogs, have the agent write code that calls MCP tools rather than loading every tool schema into context (token efficiency at scale).
- **Stack:** Reference SDKs in TypeScript and Python; protocol itself is language-agnostic JSON-RPC.

### 2.2 OpenAI
- **Adopted MCP March 2025** across products (ChatGPT desktop, Agents SDK, Responses API).
- **Architecture:** The **Agents SDK (Python/TS)** supports `MCPServerStdio`, `MCPServerSse`, `MCPServerStreamableHttp`, plus **HostedMCPTool** — the Responses API connects server-side to a remote MCP server so the model lists/invokes tools without a round-trip to your process.
- **ChatGPT Apps SDK** is built *on top of MCP*: an "app" in ChatGPT is an MCP server returning tools plus UI components.
- **Operational details:** every agent run calls `list_tools()`; they added tool-list caching and per-tool approval policies to manage latency and safety.
- **Language:** Python and TypeScript SDKs.

### 2.3 Google
- **Adopted MCP** for Gemini models/SDK (announced by Demis Hassabis; built into the Gemini API at I/O 2025). **Gemini CLI** is a first-class MCP client.
- **Flagship server: MCP Toolbox for Databases** (open source, **written in Go**, v1.0 April 2026) — a single declarative-config MCP server fronting BigQuery, Cloud SQL, AlloyDB, Spanner, PostgreSQL, etc., with connection pooling, auth, and prebuilt tools (`list_tables`, `execute_sql`). It's the reference pattern for **secure database access via MCP**: one hardened gateway server instead of ad-hoc DB credentials per agent.
- **Co-maintains the official Go SDK** for MCP.

### 2.4 Microsoft
- **Copilot Studio** has native MCP support: connect a server and its tools/knowledge auto-populate and stay updated in agents. MCP is also in **VS Code / GitHub Copilot**, Azure AI Foundry, and Windows.
- **Co-maintains the official C# SDK**; published reference architectures for OAuth 2.1 MCP servers behind **Azure AD (Entra ID)** on Azure Container Apps.
- Pattern: MCP as the connector layer for enterprise agents, with identity centralized in Entra ID.

### 2.5 AWS
- **Amazon Bedrock AgentCore Gateway** — the clearest "enterprise MCP platform" blueprint from a hyperscaler: a **fully managed MCP gateway** that fronts many targets (Lambda functions, OpenAPI/Smithy APIs, and existing MCP servers) behind **one MCP endpoint**.
- **Security model:** dual-sided — OAuth authorizer (e.g., Cognito or your IdP) validates inbound tool calls; outbound credential management connects to targets. Adds semantic tool search, routing, observability, and zero-trust identity propagation.
- Also ships **awslabs/mcp**: ~50+ open-source MCP servers for AWS services (mostly **Python**).

### 2.6 Block (Square/Cash App) — the best real-world enterprise case study
- Built **Goose**, an open-source, LLM-agnostic agent (CLI + desktop, core in **Rust**, UI in TypeScript/Electron) that speaks MCP natively.
- **Deployment:** Goose is **auto-installed and auto-updated on every Block laptop**; **60+ internal MCP servers** are authored in-house and **bundled** — employees install nothing.
- **Internal servers:** Snowflake, GitHub, Jira, Slack, Google Drive, internal compliance/support-triage APIs.
- **LLM hosting:** models (Claude, OpenAI) accessed through **Databricks-hosted, enterprise-managed endpoints** under corporate DPAs — no direct-to-vendor calls from laptops. (This is the pattern to copy for sovereignty: swap Databricks for a KSA-resident model endpoint.)
- **Security:** OAuth per service with tokens in OS keychains; LLM allowlists per tool; tools classified **read-only vs destructive** (destructive requires confirmation); centralized policy, telemetry, and endpoint management.
- **Results:** thousands of daily users; employees report 50–75% time savings on common tasks.
- **Lessons:** pre-installation + bundled defaults drove adoption; weekly education sessions were essential; centralized onboarding scaled best practices.

### 2.7 Cloudflare
- Became the **hosting platform for remote MCP servers**: Anthropic, Atlassian, Asana, Block, Intercom, Linear, PayPal, Sentry, Stripe, and Webflow launched their remote MCP servers **on Cloudflare Workers**.
- **Architecture:** `McpAgent` class — **one Durable Object per client session** (stateful, persistent), SSE + Streamable HTTP transports, WebSocket hibernation (pay only when active).
- **`workers-oauth-provider`**: the MCP server acts as an OAuth **server** to clients and OAuth **client** to the upstream service — clients never see upstream API keys; permissions are scoped per user.
- **Language:** TypeScript on V8 isolates.

### 2.8 GitHub
- **github-mcp-server** — the most-used official MCP server; **written in Go** on the **official Go SDK**; runs both **local (Docker/stdio)** and **remote (hosted by GitHub, OAuth)**.
- Key design: **toolsets** — tools grouped by capability (repos, issues, PRs…) that can be enabled/disabled per deployment, plus read-only mode. Reduces context bloat and enforces least privilege. Copy this pattern.

### 2.9 SaaS leaders (Atlassian, PayPal, Stripe, Sentry, Shopify)
- All ship **official remote MCP servers** (mostly on Cloudflare) with **OAuth 2.1**, scoped permissions, and "data stays within permissioned boundaries" as the core promise.
- Atlassian: Jira/Confluence/Bitbucket via one remote server (OAuth 2.1 or API tokens). PayPal: agentic commerce (invoices, payments). Sentry: errors/issues from IDEs and assistants.

## 3. Stack & Language Landscape (what to build with)

**Official SDKs** (Agentic AI Foundation, each co-maintained by a major vendor):

| SDK | Co-maintainer | Notes |
|---|---|---|
| TypeScript | Anthropic | Tier-1, most feature-complete; what Cloudflare-hosted servers use |
| Python | Anthropic | Strong in data/ML; FastMCP framework popular; AWS servers use it |
| Go | Google | GitHub's and Google's production servers run on it; best for high-throughput single-binary services |
| Java | Spring AI team | Enterprise JVM shops |
| Kotlin | JetBrains | JVM/IDE tooling |
| C# | Microsoft | .NET/Azure shops |
| Rust | community/Anthropic | Goose (Block) is Rust |

**What the giants chose:** Go (GitHub, Google) for production servers; TypeScript (Cloudflare ecosystem, OpenAI Apps) for remote/hosted servers; Python (AWS labs, data teams) for breadth; Rust (Block's Goose) for the client agent.

## 4. Converged Enterprise Architecture Pattern

Every large deployment (Block, AWS AgentCore, Cloudflare, Microsoft) landed on the same shape:

```
Employees (Claude/Copilot/custom agent, IDE, chat)
        │  MCP (Streamable HTTP + OAuth 2.1/PKCE, SSO via IdP)
        ▼
┌─────────────────────────────────────────────┐
│           MCP GATEWAY (control plane)        │
│  • AuthN: OIDC/SSO, audience-bound tokens    │
│  • AuthZ: per-user, per-tool RBAC            │
│  • Tool registry/catalog (approved servers)  │
│  • Audit log of every tool invocation        │
│  • Rate limits, DLP/guardrails, telemetry    │
│  • Reissues narrow downstream tokens per hop │
└─────────────────────────────────────────────┘
        │ internal network only
        ▼
  Internal MCP servers (HR, ERP, DB, docs, ticketing…)
        +
  LLM access ONLY via enterprise-managed endpoint
  (Block uses Databricks; you'd use a KSA-resident endpoint)
```

Consensus best practices from the research:
1. **Gateway pattern, not point-to-point** — centralize auth, policy, audit (AWS AgentCore, all enterprise-gateway guidance).
2. **OAuth 2.1 + PKCE mandatory** for remote servers; short-lived audience-bound tokens; JWT validation locally, token introspection for destructive/PII tools.
3. **All internal servers authored in-house** (Block) — no unvetted community servers touching company data; mitigates tool-poisoning and shadow-MCP risk.
4. **Tool classification** — read-only vs destructive, with confirmation gates on destructive.
5. **Toolsets/least privilege** (GitHub) — expose only needed tool groups per role.
6. **Bundle and pre-install** the client for adoption (Block); centralize model access behind managed endpoints.

## 5. Saudi Arabia Compliance & Hosting Landscape

**Regulatory surface (one compliance stack, four bodies):**
- **PDPL** (Personal Data Protection Law, enforced by SDAIA/NDMO) — Saudi-residency defaults, strict cross-border transfer rules.
- **NCA controls** — ECC-1 (Essential Cybersecurity Controls), **CCC-1 (Cloud Cybersecurity Controls)**, CSCC (critical systems). Every cloud workload must map to ECC + CCC.
- **CST CCRF** — Cloud Computing Regulatory Framework (provider registration, data classification levels).
- **SAMA CSF** — additionally, if any fintech/banking data is involved.
- Practical bar: personal and classified data **stays in-Kingdom**, including backups, telemetry, and support access; document subprocessors and whether any data leaves KSA (it shouldn't).

**In-Kingdom hosting options (as of mid-2026):**
- **Google Cloud — Dammam region: live since 2023** (Compute, GKE, BigQuery, Vertex AI-class services, in-country residency).
- **Oracle — Riyadh + Jeddah regions live**; sovereign-cloud JV models with **stc**.
- **Microsoft Azure — Eastern Province datacenters built; full region launching ~2026.**
- **AWS — KSA region launching 2026** ($5.3B; Riyadh/Jeddah/Dammam/NEOM phases).
- **Local sovereign options:** STC Cloud, Mobily, Zain, and **HUMAIN** (PIF-backed AI company — in-Kingdom GPU capacity and model hosting).
- **Key implication for the LLM itself:** the Block pattern (models behind an enterprise-managed endpoint) maps to KSA as: self-hosted open-weight models on in-Kingdom GPUs, or a hyperscaler AI service in a KSA region, or HUMAIN-hosted models — *not* direct calls to US-hosted APIs for regulated data.

## 6. What This Means for Our Platform (planning inputs, no build yet)

1. **Adopt the gateway architecture** (Section 4) — it is the unanimous pattern at Block, AWS, and Microsoft, and it's exactly what centralized audit/RBAC for PDPL/NCA compliance requires.
2. **Language/stack shortlist:** Go (GitHub/Google precedent, single-binary servers, easy container hardening) or TypeScript (richest SDK) for MCP servers; Python acceptable for data-team servers. Decide by team skills, not capability — all official SDKs are production-grade.
3. **All MCP servers authored/vetted in-house**, deployed on in-Kingdom infrastructure (Google Cloud Dammam or Oracle Riyadh today; Azure/AWS KSA once live), private network only, behind the gateway.
4. **Identity:** integrate the gateway with the company IdP (Entra ID/Keycloak) — OAuth 2.1 + PKCE, per-user identity propagated to every tool call, full audit trail.
5. **Model hosting is the hardest sovereignty decision** — evaluate: self-hosted open-weight models in-Kingdom vs hyperscaler KSA-region AI services vs HUMAIN. This gates everything else and should be the first planning workshop.
6. **Adoption playbook from Block:** pre-installed client, bundled approved servers, weekly enablement sessions, centralized onboarding.

---

## Sources

- [Introducing the Model Context Protocol — Anthropic](https://www.anthropic.com/news/model-context-protocol)
- [Donating MCP and establishing the Agentic AI Foundation — Anthropic](https://www.anthropic.com/news/donating-the-model-context-protocol-and-establishing-of-the-agentic-ai-foundation)
- [Code execution with MCP — Anthropic Engineering](https://www.anthropic.com/engineering/code-execution-with-mcp)
- [MCP — OpenAI Agents SDK](https://openai.github.io/openai-agents-python/mcp/)
- [MCP server concepts — OpenAI Apps SDK](https://developers.openai.com/apps-sdk/concepts/mcp-server)
- [Building MCP servers for ChatGPT Apps and API — OpenAI](https://developers.openai.com/api/docs/mcp)
- [Google Embraces MCP — The New Stack](https://thenewstack.io/google-embraces-mcp/)
- [MCP Toolbox for Databases — googleapis (GitHub)](https://github.com/googleapis/mcp-toolbox)
- [Spanner with MCP Toolbox — Google Cloud docs](https://cloud.google.com/spanner/docs/pre-built-tools-with-mcp-toolbox)
- [Introducing MCP in Copilot Studio — Microsoft](https://www.microsoft.com/en-us/microsoft-copilot/blog/copilot-studio/introducing-model-context-protocol-mcp-in-copilot-studio-simplified-integration-with-ai-apps-and-agents/)
- [Secure MCP Server with OAuth 2.1 and Azure AD — Microsoft ISE](https://devblogs.microsoft.com/ise/aca-secure-mcp-server-oauth21-azure-ad/)
- [Introducing Amazon Bedrock AgentCore Gateway — AWS](https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-gateway-transforming-enterprise-ai-agent-tool-development/)
- [Unite MCP servers through AgentCore Gateway — AWS](https://aws.amazon.com/blogs/machine-learning/transform-your-mcp-architecture-unite-mcp-servers-through-agentcore-gateway/)
- [MCP in the Enterprise: Real World Adoption at Block](https://dev.to/blockopensource/mcp-in-the-enterprise-real-world-adoption-at-block-ci5)
- [From Experiment to Enterprise: How Block Scaled MCP — Glama](https://glama.ai/blog/2025-07-22-from-experiment-to-enterprise-scaling-mcp-at-block)
- [Block introduces codename goose](https://block.xyz/inside/block-open-source-introduces-codename-goose)
- [Build and deploy remote MCP servers — Cloudflare](https://blog.cloudflare.com/remote-model-context-protocol-servers-mcp/)
- [MCP, authn/authz, and Durable Objects — Cloudflare](https://blog.cloudflare.com/building-ai-agents-with-mcp-authn-authz-and-durable-objects/)
- [MCP Demo Day: 10 leading AI companies on Cloudflare](https://blog.cloudflare.com/mcp-demo-day/)
- [GitHub official MCP server (Go)](https://github.com/github/github-mcp-server)
- [Official MCP SDKs — modelcontextprotocol.io](https://modelcontextprotocol.io/docs/sdk)
- [Official Go SDK for MCP](https://github.com/modelcontextprotocol/go-sdk)
- [Atlassian Remote MCP Server](https://www.atlassian.com/blog/announcements/remote-mcp-server)
- [MCP OAuth 2.1 authorization spec analysis](https://dasroot.net/posts/2026/04/mcp-authorization-specification-oauth-2-1-resource-indicators/)
- [MCP server authentication best practices — RTS Labs](https://rtslabs.com/mcp-server-authentication)
- [MCP security: authn and authz — Red Hat](https://www.redhat.com/en/blog/mcp-security-implementing-robust-authentication-and-authorization)
- [Cloud Cybersecurity Controls — NCA](https://nca.gov.sa/en/regulatory-documents/controls-list/ccc/)
- [Saudi data sovereignty guide (NDMO, PDPL, sovereign cloud)](https://jmminnovations.com/insights/saudi-data-sovereignty-guide)
- [Saudi Arabia cloud compliance — Morgan Lewis](https://www.morganlewis.com/blogs/sourcingatmorganlewis/2026/03/saudi-arabia-cloud-compliance-part-1-data-residency-and-contractual-expectations)
- [Cloud computing in Saudi Arabia (Google, Oracle, AWS)](https://vision2030.ai/sectors/technology/cloud-computing/)
- [AWS Saudi region 2026 — DCD](https://www.datacenterdynamics.com/en/news/aws-plans-to-launch-saudi-arabian-cloud-region-in-2026-promises-53bn-investment/)
