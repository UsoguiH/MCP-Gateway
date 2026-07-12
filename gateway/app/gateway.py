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
import base64
import json
import time

from . import audit, authz, classification, dlp, selfinfo, unicode_guard
from .approvals import ApprovalStore
from .config import DATA_DIR, GATEWAY, clearance_rank
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
        # admin drain: refuse NEW calls to a server while in-flight work finishes
        # (softer than stop/kill). Persisted so a drain survives a restart.
        self._drain_file = DATA_DIR / "drained.json"
        try:
            self.drained: set[str] = set(json.loads(self._drain_file.read_text(encoding="utf-8")))
        except Exception:
            self.drained = set()

    # ---- admin drain / breaker controls ----
    def _save_drained(self):
        self._drain_file.write_text(json.dumps(sorted(self.drained)), encoding="utf-8")

    def drain(self, server: str):
        self.drained.add(server)
        self._save_drained()

    def undrain(self, server: str):
        self.drained.discard(server)
        self._save_drained()

    def reset_breaker(self, server: str):
        """Admin force-close after fixing the underlying cause."""
        self._breaker_reset(server)

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
        allowed = _role_servers(claims)
        out = []
        for t in self.mcp.all_tools():
            if allowed is not None and t["server"] not in allowed:
                continue
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

        # 0. maintenance mode: pause mediated work during a patch/migration without the
        # finality of a kill switch, and without locking admins out of the console.
        # Admins keep working so they can fix whatever the maintenance is for.
        maint = selfinfo.maintenance_status()
        if maint.get("enabled") and claims.get("role") != "admin":
            return self._blocked(server, tool,
                                 f"gateway in maintenance: {maint.get('message', '')}".strip(),
                                 user, arguments)

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

        # 3. server entitlement (role allowlist) — the client-facing reason is identical
        # to the unknown-tool case so a non-entitled caller cannot distinguish a hidden
        # server from one that does not exist; audit records what really happened.
        allowed = _role_servers(claims)
        if allowed is not None and server not in allowed:
            audit.record("blocked", user=user, server=server, tool=tool,
                         reason="server not entitled to role", role=claims.get("role", ""),
                         args_digest=audit.payload_digest(arguments))
            return {"server": server, "tool": tool, "status": "blocked",
                    "reason": "tool not in registry"}

        # 3a. registry
        entry = self.registry.get(server, tool)
        if not entry:
            return self._blocked(server, tool, "tool not in registry", user, arguments)

        # 3b. circuit breaker: a server that keeps failing is temporarily quarantined
        if self._breaker_open(server):
            return self._blocked(server, tool, "circuit open: server temporarily quarantined",
                                 user, arguments)

        # 3c. admin drain: new calls refused while the server is being drained
        if server in self.drained:
            return self._blocked(server, tool, "server drained by administrator", user, arguments)

        # 3d. API-key scope cap: a scoped key may never call above its tier ceiling,
        # regardless of the bound operator's role (a leaked read-only CI key cannot
        # even queue a destructive action for approval).
        cap = claims.get("tier_cap")
        if cap is not None and entry["tier"] > cap:
            return self._blocked(server, tool,
                                 f"API key scope '{claims.get('scope')}' caps risk tier at {cap}",
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
        """Run a call that has cleared HITL. Uses the *requester's* clearance for DLP,
        and stores the result so the requesting agent can fetch it back over MCP."""
        requester_claims = claims_by_user(approval["requester"])
        session = approval["requester"]
        result = await self._dispatch(
            requester_claims, session, approval["server"], approval["tool"],
            approval["arguments"], approval["tier"], approved_id=approval["id"],
        )
        self.approvals.set_result(approval["id"], result)
        return result

    async def _dispatch(self, claims, session, server, tool, arguments, tier, approved_id=None):
        # Vault: mint a short-lived, per-(server,user) credential and inject it into
        # the call. The secret is never in model context and never in the audit payload.
        cred = vault.issue(server, claims["sub"]) if vault.manages(server) else None
        call_args = dict(arguments)
        if cred:
            call_args[_INJECTED_PARAM] = cred["secret"]
        # A5: time every dispatch. Without this the gateway has no latency data at all —
        # every "avg"/"latency" column in the console was an em-dash, and slow-drip
        # exfiltration or a degrading backend had nothing to show up in.
        t0 = time.perf_counter()
        try:
            raw, blocks = await self.mcp.call(server, tool, call_args)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - t0) * 1000, 1)
            if cred:
                vault.revoke(cred["lease"])
            self._breaker_trip(server)          # circuit breaker: track failures
            audit.record("tool_error", user=claims["sub"], server=server, tool=tool,
                         error=str(exc)[:200], duration_ms=duration_ms)
            return {"server": server, "tool": tool, "status": "error",
                    "reason": f"tool call failed: {exc}", "tier": tier,
                    "duration_ms": duration_ms}
        duration_ms = round((time.perf_counter() - t0) * 1000, 1)
        self._breaker_reset(server)
        if cred:
            audit.record("credential_injected", user=claims["sub"], server=server, tool=tool,
                         lease=cred["lease"], secret_digest=audit.payload_digest(cred["secret"]))
            vault.revoke(cred["lease"])          # per-call lease, revoked immediately after use

        g = self._govern(claims, session, f"{server}.{tool}",
                         classification.tool_classification(self.registry.get(server, tool)), raw)
        audit.record(
            "tool_call", user=claims["sub"], server=server, tool=tool, tier=tier,
            approved_id=approved_id, truncated=g["truncated"], classification=g["classification"],
            result_digest=audit.payload_digest(g["masked"]),
            pii_detected=g["pii_detected"], pii_masked=g["pii_masked"],
            result_unicode_flags=g["result_unicode_flags"], duration_ms=duration_ms,
        )
        return {
            "server": server, "tool": tool, "status": "executed", "tier": tier,
            "result": g["masked"], "content_blocks": blocks, "truncated": g["truncated"],
            "classification": g["classification"], "pii_detected": g["pii_detected"],
            "pii_masked": g["pii_masked"], "result_unicode_flags": g["result_unicode_flags"],
            "approved_id": approved_id, "duration_ms": duration_ms,
        }

    def _govern(self, claims, session, source, data_class, raw):
        """Run untrusted content (a tool result OR a resource read) through the shared
        governance: size cap -> Unicode sanitize -> taint-record -> DLP-mask by clearance."""
        if len(raw.encode("utf-8")) > MAX_RESULT:
            raw, truncated = raw[:MAX_RESULT], True
        else:
            truncated = False
        try:
            parsed, is_json = json.loads(raw), True
        except json.JSONDecodeError:
            parsed, is_json = raw, False
        parsed, res_uflags = unicode_guard.sanitize_obj(parsed)
        self.taint.add_untrusted(session, json.dumps(parsed, ensure_ascii=False) if is_json else parsed,
                                 source=source)
        caller_cleared = classification.dominates(claims.get("clearance", "public"), data_class)
        det = dlp.scan(json.dumps(parsed, ensure_ascii=False) if is_json else parsed)
        masked, detections = parsed, []
        pii_masked = bool(det) and not caller_cleared
        if det and not caller_cleared:
            masked, detections = dlp.mask_obj(parsed)
        elif det:
            detections = det
        return {"masked": masked, "truncated": truncated, "classification": data_class,
                "pii_detected": [d["type"] for d in detections], "pii_masked": pii_masked,
                "result_unicode_flags": res_uflags}

    # ---- resources (MCP resources/list, resources/read) — governed like tool output ----
    def visible_resources(self, claims: dict) -> list[dict]:
        allowed = _role_servers(claims)
        return [{"uri": _wrap_uri(r["server"], r["uri"]), "name": r.get("name") or r["uri"],
                 "description": r.get("description", ""), "mimeType": r.get("mimeType") or "text/plain",
                 "_meta": {"gateway": {"server": r["server"]}}}
                for r in self.mcp.all_resources()
                if allowed is None or r["server"] in allowed]

    async def read_resource(self, claims: dict, wrapped_uri: str) -> dict:
        server, orig = _unwrap_uri(wrapped_uri)
        user = claims["sub"]
        if server is None:
            return {"status": "blocked", "reason": "invalid gateway resource uri"}
        allowed = _role_servers(claims)
        if server not in self.mcp.servers or (allowed is not None and server not in allowed):
            # entitlement block deliberately reads like a nonexistent server
            return {"status": "blocked", "reason": "unknown server"}
        blocked = kill_switch.blocked(user=user, server=server, tool="__resource__")
        if blocked:
            return {"status": "blocked", "reason": f"kill switch active: {blocked}"}
        if not rate_limiter.allow(user) or not server_limiter.allow(server):
            return {"status": "blocked", "reason": "rate limit exceeded"}
        if self._breaker_open(server):
            return {"status": "blocked", "reason": "circuit open: server temporarily quarantined"}
        if server in self.drained:
            return {"status": "blocked", "reason": "server drained by administrator"}
        t0 = time.perf_counter()
        try:
            raw, blobs = await self.mcp.read_resource(server, orig)
        except Exception as exc:
            self._breaker_trip(server)
            audit.record("resource_error", user=user, server=server,
                         uri_digest=audit.payload_digest(orig), error=str(exc)[:200],
                         duration_ms=round((time.perf_counter() - t0) * 1000, 1))
            return {"status": "error", "reason": f"resource read failed: {exc}"}
        duration_ms = round((time.perf_counter() - t0) * 1000, 1)
        self._breaker_reset(server)
        # resources carry no registry tier; govern at the fail-toward-protected default.
        g = self._govern(claims, user, f"{server}:resource", classification.tool_classification(None), raw)
        audit.record("resource_read", user=user, server=server, uri_digest=audit.payload_digest(orig),
                     classification=g["classification"], pii_detected=g["pii_detected"],
                     pii_masked=g["pii_masked"], truncated=g["truncated"],
                     result_unicode_flags=g["result_unicode_flags"], duration_ms=duration_ms)
        text = g["masked"] if isinstance(g["masked"], str) else json.dumps(g["masked"], ensure_ascii=False)
        return {"status": "executed", "server": server, "uri": wrapped_uri, "text": text,
                "blobs": blobs, "classification": g["classification"], "pii_masked": g["pii_masked"]}

    # ---- prompts (MCP prompts/list, prompts/get) — templates re-entering model context ----
    def visible_prompts(self, claims: dict) -> list[dict]:
        allowed = _role_servers(claims)
        return [{"name": f"{p['server']}__{p['name']}", "description": p.get("description", ""),
                 "arguments": p.get("arguments", []),
                 "_meta": {"gateway": {"server": p["server"], "prompt": p["name"]}}}
                for p in self.mcp.all_prompts()
                if allowed is None or p["server"] in allowed]

    async def get_prompt(self, claims: dict, server: str, name: str, arguments: dict) -> dict:
        user = claims["sub"]
        allowed = _role_servers(claims)
        if server not in self.mcp.servers or (allowed is not None and server not in allowed):
            # entitlement block deliberately reads like a nonexistent server
            return {"status": "blocked", "reason": "unknown server"}
        if kill_switch.blocked(user=user, server=server, tool="__prompt__"):
            return {"status": "blocked", "reason": "kill switch active"}
        if not rate_limiter.allow(user) or not server_limiter.allow(server):
            return {"status": "blocked", "reason": "rate limit exceeded"}
        try:
            got = await self.mcp.get_prompt(server, name, arguments)
        except Exception as exc:
            self._breaker_trip(server)
            audit.record("prompt_error", user=user, server=server, prompt=name, error=str(exc)[:200])
            return {"status": "error", "reason": f"prompt get failed: {exc}"}
        self._breaker_reset(server)
        # A prompt's text is injected into the model context -> sanitize + taint it.
        msgs = []
        for m in got.get("messages", []):
            c = m.get("content") or {}
            if isinstance(c, dict) and c.get("type") == "text":
                clean, _ = unicode_guard.sanitize(c.get("text", ""))
                self.taint.add_untrusted(user, clean, source=f"{server}:prompt:{name}")
                c = {**c, "text": clean}
            msgs.append({**m, "content": c})
        audit.record("prompt_get", user=user, server=server, prompt=name)
        return {"status": "executed", "description": got.get("description", ""), "messages": msgs}

    # ---- HITL round-trip: the requesting agent fetches an approved call's result ----
    def approval_result(self, claims: dict, aid: str) -> dict:
        a = self.approvals.get(aid)
        if not a or a["requester"] != claims["sub"]:
            return {"found": False, "reason": "no such approval for this operator"}
        return {"found": True, "status": a["status"], "result": self.approvals.get_result(aid)}

    def _blocked(self, server, tool, reason, user, arguments):
        audit.record("blocked", user=user, server=server, tool=tool, reason=reason,
                     args_digest=audit.payload_digest(arguments))
        return {"server": server, "tool": tool, "status": "blocked", "reason": reason}


def _role_ceiling(claims: dict) -> int:
    from .config import POLICY
    return POLICY["roles"].get(claims.get("role", ""), {}).get("max_tool_tier", -1)


def _role_servers(claims: dict) -> set[str] | None:
    """Server entitlement for the caller's role. None = all servers ("*" or the
    key omitted — legacy roles); an unknown role gets an empty set (deny all)."""
    from .config import POLICY
    role = POLICY["roles"].get(claims.get("role", ""))
    if role is None:
        return set()
    servers = role.get("servers", "*")
    if servers == "*":
        return None
    return set(servers or [])


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


def _wrap_uri(server: str, uri: str) -> str:
    """Namespace a downstream resource URI under one gateway so reads route back to
    the owning server unambiguously: mcpgw://<server>/<base64url(original uri)>."""
    enc = base64.urlsafe_b64encode(uri.encode("utf-8")).decode().rstrip("=")
    return f"mcpgw://{server}/{enc}"


def _unwrap_uri(wrapped: str) -> tuple[str | None, str | None]:
    prefix = "mcpgw://"
    if not isinstance(wrapped, str) or not wrapped.startswith(prefix):
        return None, None
    server, _, enc = wrapped[len(prefix):].partition("/")
    if not server or not enc:
        return None, None
    try:
        uri = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8")
    except Exception:
        return None, None
    return server, uri


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
