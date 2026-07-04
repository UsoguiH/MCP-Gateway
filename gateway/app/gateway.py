"""Gateway orchestrator — the mediated control plane (spec §4.4, §11).

This is where every control composes on the path of a single tool call:

  1. kill switch            -> instant disable (§4.4.8)
  2. rate limit             -> per-user budget (§4.4.8)
  3. registry lookup        -> tool known + active, not quarantined (§4.4.3)
  4. Unicode sanitize args  -> NFKC, strip bidi/zero-width (§4.4.7)
  5. size limits            -> protocol hardening (§4.4.5)
  6. taint check            -> tainted args escalate to human approval (§4.5)
  7. ABAC decision          -> role x tier x taint (§4.1/§5)
  8. HITL if needed         -> tier 2 one approver, tier 3 two (§5)
  9. dispatch to server     -> MCP call (§4.6)
 10. Unicode + DLP on result-> mask Saudi PII, record taint (§4.8/§4.5)
 11. audit every step       -> hash-chained WORM (§4.9)

The planner is the *client's* local LLM (it connects via the inbound MCP endpoint
in mcp_server.py); it only proposes calls, the gateway disposes. Secrets are never
in model context — the vault injects per-call backend credentials at dispatch.
"""
import json
import time

from . import audit, authz, classification, dlp, unicode_guard
from .approvals import ApprovalStore
from .config import GATEWAY, clearance_rank
from .controls import kill_switch, rate_limiter, server_limiter, tool_limiter
from .mcp_manager import MCPManager
from .registry import Registry
from .taint import TaintStore
from .vault import vault

MAX_RESULT = GATEWAY["max_tool_result_bytes"]
MAX_ARG = GATEWAY["max_arg_string_len"]
_INJECTED_PARAM = "credential"   # gateway-injected; hidden from the model, stripped from its args


class Gateway:
    def __init__(self):
        self.mcp = MCPManager()
        self.registry = Registry()
        self.approvals = ApprovalStore()
        self.taint = TaintStore(GATEWAY["taint_min_len"])
        self.started = False
        # circuit breaker: per-server consecutive-failure tracking -> auto-open
        self._breaker: dict[str, dict] = {}
        self._breaker_threshold = GATEWAY.get("breaker_failure_threshold", 5)
        self._breaker_cooldown = GATEWAY.get("breaker_cooldown_seconds", 30)

    # ---- circuit breaker (contain a failing/compromised server) ----
    def _breaker_open(self, server: str) -> bool:
        b = self._breaker.get(server)
        return bool(b and b.get("open_until", 0) > time.time())

    def _breaker_trip(self, server: str):
        b = self._breaker.setdefault(server, {"fails": 0, "open_until": 0})
        b["fails"] += 1
        if b["fails"] >= self._breaker_threshold:
            b["open_until"] = time.time() + self._breaker_cooldown
            audit.record("circuit_open", server=server, cooldown_s=self._breaker_cooldown)

    def _breaker_reset(self, server: str):
        if server in self._breaker:
            self._breaker[server] = {"fails": 0, "open_until": 0}

    async def startup(self):
        await self.mcp.start_all()
        events = self.registry.reconcile(self.mcp.all_tools())
        for e in events:
            audit.record("registry_event", **e)
        self.started = True

    async def shutdown(self):
        await self.mcp.stop_all()

    # ---- tool surface for the planner (spec §4.4.4 dynamic discovery) ----
    def visible_tools(self, claims: dict) -> list[dict]:
        role_ceiling = _role_ceiling(claims)
        out = []
        for t in self.mcp.all_tools():
            entry = self.registry.get(t["server"], t["name"])
            if not entry or entry["status"] != "active":
                continue
            if entry["tier"] > role_ceiling:
                continue
            out.append({**_strip_injected(t), "tier": entry["tier"]})
        return out

    # ---- main entry: one tool call proposed by the client's LLM (MCP tools/call) ----
    async def call_tool(self, claims: dict, server: str, tool: str, arguments: dict) -> dict:
        """Execute a single named tool call through every control and return the
        step dict. Taint is keyed to the caller's subject (per-user session)."""
        return await self._execute_call(
            claims, claims["sub"], {"server": server, "tool": tool, "arguments": arguments})

    # ---- a single proposed tool call goes through every control ----
    async def _execute_call(self, claims: dict, session: str, call: dict) -> dict:
        server = call.get("server", "")
        tool = call.get("tool", "")
        arguments = call.get("arguments", {}) or {}
        user = claims["sub"]

        # 1. kill switch
        blocked = kill_switch.blocked(user=user, server=server, tool=tool)
        if blocked:
            return self._blocked(server, tool, f"kill switch active: {blocked}", user, arguments)

        # 2. rate limit — three independent keys
        if not rate_limiter.allow(user):
            return self._blocked(server, tool, "rate limit exceeded (per-user)", user, arguments)
        if not tool_limiter.allow(f"{user}:{server}:{tool}"):
            return self._blocked(server, tool, "rate limit exceeded (per-tool)", user, arguments)
        if not server_limiter.allow(server):
            return self._blocked(server, tool, "rate limit exceeded (per-server)", user, arguments)

        # 3. registry
        entry = self.registry.get(server, tool)
        if not entry:
            return self._blocked(server, tool, "tool not in registry", user, arguments)

        # 3b. circuit breaker: a server that keeps failing is temporarily quarantined
        if self._breaker_open(server):
            return self._blocked(server, tool, "circuit open: server temporarily quarantined",
                                 user, arguments)

        # 4. Unicode sanitize arguments
        clean_args, arg_flags = unicode_guard.sanitize_obj(arguments)
        clean_args.pop(_INJECTED_PARAM, None)   # the model may never supply the injected credential

        # 5. size limits
        for k, v in clean_args.items():
            if isinstance(v, str) and len(v) > MAX_ARG:
                return self._blocked(server, tool, f"argument '{k}' exceeds size limit", user, clean_args)

        # 5b. strict schema validation (W9.6): args must match the tool's declared
        # input schema with additionalProperties=false — no unexpected/typo'd fields.
        ok, why = _validate_args(self.mcp.find_tool(server, tool), clean_args)
        if not ok:
            return self._blocked(server, tool, f"argument schema violation: {why}", user, clean_args)

        # 6. taint
        taint_hits = self.taint.check_args(session, clean_args)

        # 7. ABAC
        decision = authz.decide(claims, entry, clean_args, taint_hits, arg_flags)

        audit.record(
            "authz_decision",
            user=user, role=claims["role"], server=server, tool=tool,
            tier=decision.tier, outcome=decision.outcome, reason=decision.reason,
            taint=[t["arg"] for t in taint_hits], unicode_flags=arg_flags,
            args_digest=audit.payload_digest(clean_args),
        )

        if decision.outcome == "deny":
            return {"server": server, "tool": tool, "status": "denied",
                    "reason": decision.reason, "tier": decision.tier,
                    "taint": taint_hits, "unicode_flags": arg_flags}

        if decision.outcome == "approve":
            preview = _preview(server, tool, clean_args, taint_hits)
            appr = self.approvals.create(
                requester=user, server=server, tool=tool, arguments=clean_args,
                tier=decision.tier, approvals_required=decision.approvals_required,
                preview=preview, taint=taint_hits,
            )
            audit.record("approval_requested", user=user, server=server, tool=tool,
                         approval_id=appr["id"], tier=decision.tier,
                         approvals_required=decision.approvals_required)
            return {"server": server, "tool": tool, "status": "pending_approval",
                    "approval_id": appr["id"], "tier": decision.tier,
                    "approvals_required": decision.approvals_required,
                    "preview": preview, "taint": taint_hits, "reason": decision.reason}

        # allow -> dispatch
        return await self._dispatch(claims, session, server, tool, clean_args, decision.tier)

    async def execute_approved(self, approval: dict, claims_by_user: dict) -> dict:
        """Run a call that has cleared HITL. Uses the *requester's* clearance for DLP."""
        requester_claims = claims_by_user(approval["requester"])
        session = approval["requester"]
        return await self._dispatch(
            requester_claims, session, approval["server"], approval["tool"],
            approval["arguments"], approval["tier"], approved_id=approval["id"],
        )

    async def _dispatch(self, claims, session, server, tool, arguments, tier, approved_id=None):
        # Vault: mint a short-lived, per-(server,user) credential and inject it into
        # the call. The secret is never in model context and never in the audit payload.
        cred = vault.issue(server, claims["sub"]) if vault.manages(server) else None
        call_args = dict(arguments)
        if cred:
            call_args[_INJECTED_PARAM] = cred["secret"]
        try:
            raw = await self.mcp.call(server, tool, call_args)
        except Exception as exc:
            if cred:
                vault.revoke(cred["lease"])
            self._breaker_trip(server)          # circuit breaker: track failures
            audit.record("tool_error", user=claims["sub"], server=server, tool=tool,
                         error=str(exc)[:200])
            return {"server": server, "tool": tool, "status": "error",
                    "reason": f"tool call failed: {exc}", "tier": tier}
        self._breaker_reset(server)
        if cred:
            audit.record("credential_injected", user=claims["sub"], server=server, tool=tool,
                         lease=cred["lease"], secret_digest=audit.payload_digest(cred["secret"]))
            vault.revoke(cred["lease"])          # per-call lease, revoked immediately after use

        # size limit on result
        if len(raw.encode("utf-8")) > MAX_RESULT:
            raw = raw[:MAX_RESULT]
            truncated = True
        else:
            truncated = False

        # parse if JSON for structured DLP/taint; else treat as text
        try:
            parsed = json.loads(raw)
            is_json = True
        except json.JSONDecodeError:
            parsed = raw
            is_json = False

        # Unicode sanitize result (untrusted content!)
        parsed, res_uflags = unicode_guard.sanitize_obj(parsed)

        # Record taint: everything a tool returns is untrusted content.
        self.taint.add_untrusted(session, json.dumps(parsed, ensure_ascii=False) if is_json else parsed,
                                 source=f"{server}.{tool}")

        # Classification propagation (W3.3): the tool's max data classification is the
        # DLP unmask threshold — a caller sees fields in the clear only if cleared for it.
        data_class = classification.tool_classification(self.registry.get(server, tool))
        caller_cleared = classification.dominates(claims.get("clearance", "public"), data_class)

        # DLP: mask PII the caller is not cleared to see in the clear.
        detections_meta = []
        masked = parsed
        det = dlp.scan(json.dumps(parsed, ensure_ascii=False) if is_json else parsed)
        pii_masked = bool(det) and not caller_cleared
        if det and not caller_cleared:
            masked, detections_meta = dlp.mask_obj(parsed)
        elif det:
            detections_meta = det

        audit.record(
            "tool_call", user=claims["sub"], server=server, tool=tool, tier=tier,
            approved_id=approved_id, truncated=truncated, classification=data_class,
            result_digest=audit.payload_digest(parsed),
            pii_detected=[d["type"] for d in detections_meta],
            pii_masked=pii_masked, result_unicode_flags=res_uflags,
        )

        return {
            "server": server, "tool": tool, "status": "executed", "tier": tier,
            "result": masked, "truncated": truncated, "classification": data_class,
            "pii_detected": [d["type"] for d in detections_meta],
            "pii_masked": pii_masked, "result_unicode_flags": res_uflags,
            "approved_id": approved_id,
        }

    def _blocked(self, server, tool, reason, user, arguments):
        audit.record("blocked", user=user, server=server, tool=tool, reason=reason,
                     args_digest=audit.payload_digest(arguments))
        return {"server": server, "tool": tool, "status": "blocked", "reason": reason}


def _role_ceiling(claims: dict) -> int:
    from .config import POLICY
    return POLICY["roles"].get(claims.get("role", ""), {}).get("max_tool_tier", -1)


def _validate_args(tool: dict | None, args: dict) -> tuple[bool, str]:
    """Validate args against the tool's declared input schema with
    additionalProperties=false (W9.6). Missing/empty schema → allow (nothing to
    enforce). Never crash the pipeline on a malformed schema (fail-open to the
    other controls, which still gate the call)."""
    if not tool:
        return True, ""
    schema = tool.get("schema") or {}
    if not isinstance(schema.get("properties"), dict):
        return True, ""
    try:
        import jsonschema
    except ModuleNotFoundError:
        return True, ""
    try:
        jsonschema.validate(instance=args, schema={**schema, "additionalProperties": False})
        return True, ""
    except jsonschema.ValidationError as e:
        return False, str(e.message)[:150]        # bad args -> block
    except Exception:
        return True, ""                            # our own bad schema -> fail open (other controls gate)


def _strip_injected(tool: dict) -> dict:
    """Hide gateway-injected params (leading underscore, e.g. `_credential`) from the
    model-facing tool schema so the planner can never see or supply a credential."""
    schema = tool.get("schema") or {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return tool
    def _hidden(k):
        return k.startswith("_") or k == _INJECTED_PARAM
    clean_props = {k: v for k, v in props.items() if not _hidden(k)}
    clean_required = [r for r in schema.get("required", []) if not _hidden(r)]
    new_schema = {**schema, "properties": clean_props}
    if "required" in schema:
        new_schema["required"] = clean_required
    return {**tool, "schema": new_schema}


def _preview(server, tool, arguments, taint_hits) -> str:
    lines = [f"Action: {server}.{tool}", "Arguments:"]
    tainted_args = {t["arg"] for t in taint_hits}
    for k, v in arguments.items():
        mark = "  ⚠ TAINTED" if k in tainted_args else ""
        lines.append(f"  - {k} = {v!r}{mark}")
    if taint_hits:
        lines.append("")
        lines.append("⚠ One or more arguments derive from untrusted content "
                     "(a document or tool result). Verify this action was intended by you, "
                     "not injected. Sources: " + ", ".join(sorted({t["source"] for t in taint_hits})))
    return "\n".join(lines)
