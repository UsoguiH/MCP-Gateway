# MCP Gateway — Authentication Redesign Plan

> Synthesis of a 10-track research pass (2026) into a single migration plan that replaces the current
> dev-grade authentication with an air-gapped, FIPS/NCA-aligned, MCP-spec-conformant identity stack.
> Scope: **authentication and identity only** — authorization (ABAC/tiers), taint, HITL, DLP, and audit
> logic already exist and are unchanged except where they consume new identity claims.

---

## 0. Why — the current failures (`gateway/app/auth.py`)

The current auth is a labelled dev stand-in. Concretely it is:

1. **Symmetric HS256 with a hardcoded shared secret** (`config.yaml: jwt_secret: "dev-only-change-me-2f8a1c"`) — anyone who reads that one string forges any user's token, including `admin`/`top_secret`. Structurally incompatible with multi-party RS/AS trust and RFC 8707 audience binding.
2. **Plaintext passwords in source** (`pass123`, `admin123`) — no hashing, no salt.
3. **Single factor, no MFA** — no phishing resistance.
4. **No IdP / OIDC** — a hand-rolled `USERS` dict is the whole identity system.
5. **No workload identity** — agent↔gateway↔server hops are not mutually authenticated (no mTLS/SPIFFE).
6. **No identity propagation** — the user's identity never reaches the downstream MCP server.
7. **8-hour static tokens, no revocation, no rotation, no JWKS, no `aud`/`iss`/`jti` validation.**
8. **No Origin validation** — a mandated MCP-spec MUST (DNS-rebinding defence) is absent.

**The single highest-priority fix is #1** — move off the shared symmetric secret to asymmetric signing.
Everything else layers on that.

---

## 1. Target architecture

Trust domain: one internal SPIFFE trust domain `spiffe://internal.gov.sa`. One self-hosted IdP as the
single Security Token Service (STS) and trust anchor. The gateway stays the single Zero-Trust PEP.

```
                       ┌─────────────────────────────────────────────┐
                       │  Keycloak 26.5 (self-hosted IdP / STS)        │
   user + FIDO2  ─────►│  - WebAuthn/FIDO2 (AAL2/AAL3)                 │
   hardware key        │  - OIDC ES256 + JWKS                          │
                       │  - RFC 8693 token exchange (per-backend)      │
                       │  - LDAP/AD federation                         │
                       └──────────────┬──────────────────────────────┘
                                      │ ID/access token (aud=mcp-gateway)
                                      ▼
  ┌────────────┐  mTLS (SPIFFE SVID)  ┌───────────────────────────┐  mTLS + exchanged token   ┌──────────────┐
  │ Agent      │─────────────────────►│  Envoy/nginx sidecar       │  (aud=servers/finance)    │ MCP server:  │
  │ runtime    │                      │  - terminates mTLS         │──────────────────────────►│  finance     │
  └────────────┘                      │  - injects X-Spiffe-Id     │                           │ (validates   │
                                      ├───────────────────────────┤                           │  aud/iss/    │
                                      │  FastAPI Gateway (PEP)     │  mTLS + exchanged token   │  scope)      │
                                      │  - verify_token (JWKS/ES256)│  (aud=servers/hr)        ┌──────────────┐
                                      │  - PDP: authz.decide       │──────────────────────────►│ MCP server:  │
                                      │  - RFC 8693 exchange client │                           │  hr          │
                                      │  - revoked-subject denylist │                           └──────────────┘
                                      └──────────────┬────────────┘
                                                     │ hvac (Transit sign, dynamic DB creds)
                                                     ▼
                       ┌─────────────────────────────────────────────┐
                       │  OpenBao 2.5 + YubiHSM 2 FIPS                 │
                       │  - Transit: token-signing key (never leaves) │
                       │  - PKI / step-ca: short-lived mTLS certs      │
                       │  - dynamic per-backend DB credentials        │
                       │  - dual Transit-cluster air-gap auto-unseal  │
                       └─────────────────────────────────────────────┘
```

**Core properties:** no shared secret; asymmetric signing with the private key sealed in HSM/Transit;
every user login is phishing-resistant MFA; the gateway carries the *user's* identity to each backend
via a per-backend audience-bound exchanged token (delegation, not impersonation, no passthrough);
every workload hop is mutually authenticated by SPIFFE mTLS; privilege is zero-standing with JIT
elevation; identity can be killed in <1s.

---

## 2. Consolidated stack decisions

| Layer | Decision | License / FIPS |
|---|---|---|
| **IdP / STS** | **Keycloak 26.5** — mature AD/LDAP federation, RFC 8693 GA (26.2+), FIPS mode via BouncyCastle-FIPS, native WebAuthn | Apache-2.0 ✓ |
| **User auth** | **FIDO2/WebAuthn hardware keys** (YubiKey 5 FIPS, CMVP #5291); **AAL3** for approvers/admins, **AAL2-min** general; enterprise attestation for offline; Argon2id (m=128MB,t=4,p=1) only if passwords retained | FIPS 140-3 ✓ |
| **Token format** | **ES256** (ECDSA P-256; P-384 for classified) — **not EdDSA** until NCA confirms NCS-1:2020 status; RFC 9068 profile; 5–15 min access TTL; refresh rotation + reuse detection; JWKS `kid` rotation | FIPS 186-5 / verify NCA |
| **Sender-constraint** | **mTLS-bound tokens (RFC 8705)** `cnf.x5t#S256` — fits the closed mTLS mesh; DPoP only as fallback for cert-less tooling | — |
| **Delegation** | **RFC 8693 token exchange at Keycloak**, one client per backend MCP server; `sub`=user, `act`=gateway, `aud`=specific server (RFC 8707); cache by `(user, aud, scope)` | — |
| **Workload identity** | **step-ca + cert-manager** issuing SPIFFE-ID-shaped SAN certs now (graduate to full SPIRE only past ~dozens of servers); mTLS terminated at **Envoy/nginx sidecar** (FastAPI can't extract peer cert) | Apache-2.0 ✓ |
| **PKI / secrets** | **OpenBao 2.5** control plane — PKI, dynamic per-backend DB creds, **Transit token-signing (gateway never holds the private key)**, dual Transit-cluster air-gap auto-unseal; `hvac` client | MPL-2.0 ✓ (avoids Vault BSL) |
| **Key custody** | **YubiHSM 2 FIPS (CMVP #5302)** for root-CA + Transit key; offline root, **M-of-N key ceremony**, short-lived (24h) leaf certs | FIPS 140-3 L3 ✓ |
| **Gateway shape** | **Keep in-process FastAPI** — no sidecar swap, no adopting another OSS base; split `current_user` → `verify_token` + PDP contract; embedded OPA optional later. Borrow layering from IBM ContextForge (same stack) | — |
| **Privileged access** | **Zero standing privilege + JIT elevation** reusing the existing Tier-2/3 approval infra; revoked-subject deny-list (<1s kill); RFC 9470 step-up on Tier-2/3 | — |

---

## 3. What changes in the code (the seam)

The existing gateway was built so this swap is contained. Downstream authz/HITL/DLP/audit only depend on
the decoded claims `{sub, role, clearance}`, so they are untouched.

**`app/auth.py`** — replace HS256 encode/decode with asymmetric verify + JWKS + full claim validation:

```python
_jwks = PyJWKClient(CONFIG["auth"]["jwks_url"], cache_keys=True, lifespan=3600)  # local IdP, offline

def verify(token: str, cert_thumbprint: str | None) -> dict | None:
    try:
        key = _jwks.get_signing_key_from_jwt(token)             # kid-based
        claims = jwt.decode(token, key.key, algorithms=["ES256"],
            issuer=CONFIG["auth"]["issuer"], audience="mcp-gateway",
            leeway=60, options={"require": ["exp","iat","nbf","jti","sub","cnf"]})
    except jwt.PyJWTError:
        return None
    if claims["exp"] - claims["iat"] > 300: return None          # short-TTL ceiling
    if _jti_seen(claims["jti"]): return None                     # replay defence
    if claims["sub"] in _revoked_subjects: return None           # <1s identity kill
    if claims.get("cnf",{}).get("x5t#S256") != cert_thumbprint: return None  # RFC 8705 bind
    return claims
```

**`app/main.py`** — the two `verify(token)` call sites take the verified client-cert thumbprint from the
mTLS-terminating sidecar (trusted header, rejected from any non-sidecar source); add Origin-validation
middleware (403 on bad Origin); add `WWW-Authenticate` on 401.

**New `app/exchange.py`** — an `ExchangeClient` that, per tool call, POSTs an RFC 8693 exchange to Keycloak
for an `aud`-scoped downstream token, caches it by `(sub, server_uri, scope)`, and attaches it to the
outbound MCP call. The original user token is never forwarded.

**`app/authz.py`** — unchanged logic, but reshaped behind a clean PDP contract
`decide(subject, action, resource, context) -> Decision` so OPA/Rego can slot in later without touching
the FastAPI layer. Add a `require_step_up(min_aal, max_age)` dependency on the Tier-2/3 approval endpoints
that checks `auth_time`/`amr`/`acr`.

**`app/audit.py`** — upgrade the hash chain from plain SHA-256 to **keyed HMAC-SHA256** (key held only by
the logging service) and stream to WORM for NDMO immutability/retention.

**`config.yaml`** — drop `jwt_secret` and `token_ttl_minutes`; add `jwks_url`, `issuer`, `audience`,
`alg`, and the OpenBao/Transit endpoints. Each MCP server becomes an OAuth resource server validating
`aud`/`iss`/`scope`.

---

## 4. Phased migration plan

Dependencies: **Phase 1 (crypto/procurement) is the long pole and gates 2–4.** Phase 0 ships immediately
with no dependency. Critical path: **Phase 1 procurement → Phase 2 IdP → Phase 4 delegation.**

| Phase | What | Effort | Depends on |
|---|---|---|---|
| **0 — Quick wins** | Origin-validation middleware (MUST, missing today); remove plaintext passwords + hardcoded secret; kill the 8h TTL; strict claim-validation scaffolding; MCP-Protocol-Version negotiation. Ship now, independently. | **S** (days) | — |
| **1 — Crypto foundation** | Procure YubiHSM 2 FIPS (verify live CMVP cert first). Stand up OpenBao 2.5 (dual Transit-cluster unseal), step-ca / OpenBao PKI. Root-key **M-of-N ceremony** (recorded). Dynamic per-backend DB creds. Token-signing key in Transit. | **M** (6–10 wk, procurement-bound) | procurement |
| **2 — IdP + token model** | Keycloak 26.5 (FIPS mode), federate AD/LDAP. ES256 + JWKS. Replace `auth.py` HS256 with JWKS verify + full claim validation. Short TTL + refresh rotation + reuse detection. WebAuthn/FIDO2 enrollment (2 keys/user), `acr`/`amr`→AAL mapping. | **M/L** | Phase 1 (signing key custody) |
| **3 — Workload identity + mTLS** | step-ca + cert-manager, SPIFFE-shaped SANs. Envoy/nginx mTLS-terminating sidecar in front of FastAPI, inject verified `X-Spiffe-Id`. East-west mTLS gateway→each MCP server, authorize by SPIFFE ID. Bind tokens to cert (`cnf.x5t#S256`). | **M** | Phase 1 (CA) |
| **4 — Delegation + no-passthrough** | RFC 8693 exchange at Keycloak, one client per backend. Gateway `ExchangeClient` + caching. **Each MCP server retrofit to validate `aud`/`iss`/`scope`** (the long pole — one straggler = residual passthrough hole). RFC 9728 protected-resource-metadata + `WWW-Authenticate`. | **M/L** | Phases 2 + 3 |
| **5 — Privileged access + continuous authz** | Zero standing privilege + JIT elevation (reuse Tier-2/3 approval flow). Revoked-subject deny-list middleware (<1s kill). RFC 9470 step-up on Tier-2/3, phishing-resistant factor required for Tier-3. Monthly access review, auto-disable inactive. | **M** | Phase 2 |
| **6 — Compliance evidence** | CMVP cert numbers for every module in the auth path; crypto-standard doc mapped to NCS-1:2020; key-rotation runbook; DPIA; NDMO immutable in-Kingdom ≥2-yr audit store (HMAC-chained → WORM). Obtain NCA written confirmation on open items (§5). | **M** (parallel) | all |

**Interim hardening:** Phase 2 can start with **Keycloak-managed ES256 keys** to get off HS256 immediately,
then migrate signing into Transit/HSM when Phase 1 hardware lands — so the biggest vuln (shared secret) is
closed early rather than blocked on procurement.

---

## 5. Compliance guardrails & open items needing NCA confirmation

**Hard mandates that constrain design:**
- **FIPS 140-3 validated modules** for every signing/TLS/HSM component; verify the *live* CMVP certificate
  (exact firmware + mode), not vendor marketing. FIPS 140-2 certs go historical **21 Sept 2026** — procure 140-3 only.
- **Phishing-resistant MFA** is SHALL-level at AAL2+ and NCA-preferred for privileged/remote access — rules
  out password+SMS-OTP for admins/approvers.
- **Software-only signing keys are banned at ADVANCED classification (NCS-1:2020)** — a homegrown in-memory
  JWT signer is non-compliant by design; this forces the HSM decision early (aligns with Phase 1).
- **NDMO:** auth logs immutable, in-Kingdom, **≥2-year** retention — no cross-border/SaaS log shipping.

**Open items — get written NCA confirmation before finalizing (do not infer):**
1. **EdDSA/Ed25519 approval status** under NCS-1:2020 (public list names RSA/DH/ECDSA only). **Default ES256/RSA;
   keep the signer alg-pluggable** so EdDSA is a config swap if later approved.
2. **TLS cipher-suite annex** of NCS-1:2020 (PDF didn't OCR cleanly). Use TLS 1.3 + AES-256-GCM + ECDHE-P-384
   as an industry-safe superset pending confirmation.
3. **Numeric session/inactivity timeouts** — none surfaced in NCA text; adopt NIST 800-63-4 ceilings
   (AAL2 reauth ≤24h/idle ≤1h; AAL3 ≤12h/idle ≤15min) as documented "NIST-aligned, pending NCA."
4. Verify ECC-2:2024 / CSCC-1:2019 / DCC-1:2022 control numbering against the **official Arabic/English PDFs**,
   not the secondary compliance-vendor summaries this research relied on.

**Framing note:** the binding stack for this entity is **NCA (ECC/CSCC/DCC/NCS) + PDPL + NDMO**; NIST 800-63-4
and FIPS are imported as best-practice benchmarks, not legal mandates — don't over-claim them in accreditation docs.

---

## 6. Top program risks

1. **HS256 shared secret is the live vulnerability** — fix asymmetric signing first (Phase 2 interim), don't
   let it wait on HSM procurement.
2. **Backend-server retrofit is the long pole** — every MCP server must validate `aud`/`iss`/`scope`; one
   straggler still accepting unvalidated tokens re-opens the confused-deputy/passthrough hole even after the
   gateway is fixed.
3. **"Pass NIST, fail NCA" algorithm trap** — EdDSA is FIPS-approved but possibly not NCA-approved; default to
   ECDSA/RSA and confirm before relying on EdDSA above Public/Internal classification.
4. **Air-gapped key/JWKS/policy distribution drift** — JWKS rotation, revocation lists, and OPA/policy bundles
   all need a disciplined offline update channel; design the sneakernet/rotation runbook alongside the redesign,
   not after. Order JWKS-publish strictly before key cutover with a conservative overlap window.
5. **FastAPI can't extract the mTLS peer cert** — budget the Envoy/nginx sidecar from day one; don't hand-roll
   fragile `ssl_object.getpeercert()` middleware.
6. **Continuous-authz blind spots** — the refresh endpoint must actually re-check policy (else it's a long-lived
   token in disguise); the revoked-subject deny-list must replicate across workers within <1s with the short TTL
   as backstop.

---

## 7. Research provenance

This plan synthesizes ten parallel 2026 research tracks: (1) self-hosted OIDC IdPs, (2) SPIFFE/SPIRE workload
identity, (3) RFC 8693 delegation, (4) token security & sender-constraining, (5) phishing-resistant MFA,
(6) PKI/HSM/secrets custody, (7) MCP-spec auth conformance, (8) gateway auth reference patterns, (9) PAM/JIT/
step-up/revocation, (10) FIPS/NCA/PDPL/NDMO compliance mapping. Full source citations live in each track's brief.
