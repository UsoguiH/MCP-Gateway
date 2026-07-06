"""End-to-end HTTP tests against a running gateway on 127.0.0.1:8800.

Covers TPM+PIN certificate login (challenge/response with a PIN-sealed key),
two-factor tokens, cert binding, anti-hammering lockout + admin unlock, Tier-3
step-up, RBAC, DLP, injection taint -> HITL, two-person approval + SoD, kill
switch, identity revocation, origin guard, audit-chain integrity, and the
inbound MCP endpoint (initialize, tools/list RBAC, tools/call through the full
control pipeline — the gateway runs no model; the client drives tool calls).

Run the server first:  python -m uvicorn app.main:app --port 8800
Then:                   python -m pytest tests/test_e2e.py -q
"""
import base64
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import auth, pki

BASE = "http://127.0.0.1:8800"

# Demo/test credentials — match data/credentials.json (rotate for production).
DEMO_PW = {"sara": "L!mfd3TySJPa8a", "khalid": "M$5@bwMJ8nmAC8", "noura": "4G5drhmY4$S45d",
           "faisal": "R#XJc3gVUYFg$a", "admin": "fn27pwKxev%hKm"}


def session(username):
    """Real two-factor login: unlock the PIN-sealed key, sign the challenge."""
    cert = pki.ensure_user_cert(username)
    key = pki.load_user_key(username, pki.get_dev_pin(username))   # PIN unlocks key (factor 2)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    ch = httpx.post(f"{BASE}/api/login/challenge", json={"cert_pem": cert_pem})
    ch.raise_for_status()
    nonce = ch.json()["nonce"]
    sig = base64.b64encode(key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))).decode()
    r = httpx.post(f"{BASE}/api/login", json={"cert_pem": cert_pem, "nonce": nonce, "signature": sig})
    r.raise_for_status()
    body = r.json()
    return body["token"], body["thumbprint"]


def h(sess):
    tok, thumb = sess
    return {"Authorization": f"Bearer {tok}", "X-Client-Cert-Thumbprint": thumb}


# ---------- inbound MCP client helpers (replace the old /api/chat driver) ----------
def _mcp_headers(sess, sid=None):
    hdr = {**h(sess), "Accept": "application/json, text/event-stream"}
    if sid:
        hdr["Mcp-Session-Id"] = sid
    return hdr


def mcp_rpc(sess, method, params=None, sid=None, id_=1):
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    return httpx.post(f"{BASE}/mcp", headers=_mcp_headers(sess, sid), json=body, timeout=30)


def mcp_initialize(sess):
    r = mcp_rpc(sess, "initialize",
                {"protocolVersion": "2025-11-25", "capabilities": {},
                 "clientInfo": {"name": "e2e", "version": "1"}})
    r.raise_for_status()
    sid = r.headers.get("Mcp-Session-Id")
    httpx.post(f"{BASE}/mcp", headers=_mcp_headers(sess, sid),
               json={"jsonrpc": "2.0", "method": "notifications/initialized"})   # ack
    return sid


def mcp_tools_call(sess, sid, name, arguments):
    r = mcp_rpc(sess, "tools/call", {"name": name, "arguments": arguments}, sid=sid, id_=2)
    r.raise_for_status()
    return r.json()["result"]


def mcp_tools_list(sess, sid):
    r = mcp_rpc(sess, "tools/list", {}, sid=sid, id_=3)
    r.raise_for_status()
    return r.json()["result"]["tools"]


def _result_blob(res):
    if "structuredContent" in res:
        return res["structuredContent"]
    return "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")


def call1(sess, name, arguments):
    """Open a session, call one tool, return a step-like dict: the gateway's
    per-call decision (_meta.gateway) plus the tool result and isError flag."""
    sid = mcp_initialize(sess)
    res = mcp_tools_call(sess, sid, name, arguments)
    step = dict(res.get("_meta", {}).get("gateway", {}))
    step["result"] = _result_blob(res)
    step["isError"] = res.get("isError", False)
    return step


def test_health():
    assert httpx.get(f"{BASE}/api/health").json()["status"] == "ok"


def test_cert_login_and_bad_proof_rejected():
    assert session("sara")
    cert = pki.ensure_user_cert("sara")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    nonce = httpx.post(f"{BASE}/api/login/challenge", json={"cert_pem": cert_pem}).json()["nonce"]
    bad = base64.b64encode(b"not-a-valid-signature").decode()
    r = httpx.post(f"{BASE}/api/login", json={"cert_pem": cert_pem, "nonce": nonce, "signature": bad})
    assert r.status_code == 401


def test_two_layer_login_and_rejections():
    # Two layers: (1) username+password, then (2) TOTP with the layer-1 ticket.
    auth.enroll_totp("sara")

    # --- Layer 1 rejections: wrong password / unknown user never advance to MFA ---
    bad = httpx.post(f"{BASE}/api/auth/login",
                     json={"username": "sara", "password": "not-the-password-9!"})
    assert bad.status_code == 401 and "mfa_ticket" not in bad.json()
    assert httpx.post(f"{BASE}/api/auth/login",
                      json={"username": "ghost", "password": "whatever-1234!"}).status_code == 401

    # --- Layer 1 success -> ticket, NO session token yet ---
    l1 = httpx.post(f"{BASE}/api/auth/login",
                    json={"username": "sara", "password": DEMO_PW["sara"]})
    assert l1.status_code == 200 and l1.json()["mfa_required"] is True
    ticket = l1.json()["mfa_ticket"]
    assert "token" not in l1.json()                       # password alone does NOT sign you in

    # --- Layer 2: wrong code -> 401; can't reach the session without the real code ---
    assert httpx.post(f"{BASE}/api/auth/mfa",
                      json={"mfa_ticket": ticket, "otp": "000000"}).status_code == 401
    # a forged/garbage ticket -> 401 (layer 1 cannot be skipped)
    assert httpx.post(f"{BASE}/api/auth/mfa",
                      json={"mfa_ticket": "not-a-real-ticket", "otp": auth.totp_code("sara")}).status_code == 401

    # --- Layer 2 success -> bound session token ---
    good = httpx.post(f"{BASE}/api/auth/mfa",
                      json={"mfa_ticket": ticket, "otp": auth.totp_code("sara")})
    assert good.status_code == 200 and good.json()["user"]["sub"] == "sara"
    tok, thumb = good.json()["token"], good.json()["thumbprint"]
    assert httpx.get(f"{BASE}/api/me", headers={"Authorization": f"Bearer {tok}",
                                                "X-Client-Cert-Thumbprint": thumb}).status_code == 200


def test_token_is_two_factor_and_cert_bound():
    tok, thumb = session("khalid")
    me = httpx.get(f"{BASE}/api/me", headers={"Authorization": f"Bearer {tok}",
                                              "X-Client-Cert-Thumbprint": thumb})
    assert me.status_code == 200
    # token without / with wrong cert thumbprint is rejected (sender-constraint)
    assert httpx.get(f"{BASE}/api/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert httpx.get(f"{BASE}/api/me", headers={"Authorization": f"Bearer {tok}",
                                                "X-Client-Cert-Thumbprint": "wrong"}).status_code == 401


def test_origin_guard_blocks_foreign_origin():   # fix L1
    assert httpx.get(f"{BASE}/api/health", headers={"Origin": "http://evil.example"}).status_code == 403
    assert httpx.get(f"{BASE}/api/health", headers={"Origin": "http://localhost:8800"}).status_code == 200


def test_dev_endpoints_disabled_in_production():
    # the whole developer sign-in surface is off (dev_login_enabled: false)
    assert httpx.post(f"{BASE}/api/dev/login",
                      json={"username": "admin", "pin": "x", "otp": "y"}).status_code == 404
    assert httpx.get(f"{BASE}/api/dev/otp?username=admin").status_code == 404
    assert httpx.get(f"{BASE}/api/dev/userlist").status_code == 404
    assert httpx.get(f"{BASE}/api/dev/users").status_code == 404


def test_request_size_cap():                     # fix M3
    assert httpx.post(f"{BASE}/api/login/challenge",
                      json={"cert_pem": "A" * 2_000_000}).status_code == 413


def test_rbac_tool_visibility():
    sara, admin = session("sara"), session("admin")
    sara_tools = {t["name"] for t in httpx.get(f"{BASE}/api/tools", headers=h(sara)).json()["tools"]}
    admin_tools = {t["name"] for t in httpx.get(f"{BASE}/api/tools", headers=h(admin)).json()["tools"]}
    assert "delete_record" not in sara_tools and "delete_record" in admin_tools
    assert "search_documents" in sara_tools


# ---------- inbound MCP protocol ----------
def test_mcp_requires_auth():
    # no bearer token / cert -> 401 before any dispatch
    r = httpx.post(f"{BASE}/mcp", headers={"Accept": "application/json, text/event-stream"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r.status_code == 401


def test_mcp_initialize_returns_bound_session():
    r = mcp_rpc(session("sara"), "initialize",
                {"protocolVersion": "2025-11-25", "capabilities": {},
                 "clientInfo": {"name": "t", "version": "1"}})
    assert r.status_code == 200
    assert r.headers.get("Mcp-Session-Id")                      # CSPRNG session id (A10)
    assert r.json()["result"]["protocolVersion"] == "2025-11-25"


def test_mcp_get_is_method_not_allowed():
    assert httpx.get(f"{BASE}/mcp").status_code == 405           # no server-initiated SSE stream


def test_mcp_tools_call_requires_session():
    r = mcp_rpc(session("sara"), "tools/call",
                {"name": "docs__search_documents", "arguments": {"query": "x"}}, id_=5)
    assert r.status_code == 400                                  # missing Mcp-Session-Id


def test_mcp_tools_list_is_rbac_filtered():
    sara, admin = session("sara"), session("admin")
    sara_names = {t["name"] for t in mcp_tools_list(sara, mcp_initialize(sara))}
    admin_names = {t["name"] for t in mcp_tools_list(admin, mcp_initialize(admin))}
    # tier-3 destructive tool is invisible to an employee, visible to admin
    assert "actions__delete_record" not in sara_names
    assert "actions__delete_record" in admin_names
    assert "docs__search_documents" in sara_names


def test_mcp_unknown_tool_is_error():
    admin = session("admin")
    res = mcp_tools_call(admin, mcp_initialize(admin), "actions__does_not_exist", {})
    assert res["isError"] is True
    assert "registry" in res["content"][0]["text"].lower()


def test_readonly_autoallow_and_dlp_masks_for_low_clearance():
    step = call1(session("sara"), "docs__search_documents", {"query": "payroll"})
    assert step["status"] == "executed"
    blob = str(step["result"])
    assert "1023456781" not in blob and "SA4420000001234567891234" not in blob
    assert step["pii_masked"] is True


def test_dlp_unmasks_for_secret_clearance():
    step = call1(session("khalid"), "docs__search_documents", {"query": "payroll"})
    blob = str(step["result"])
    assert "1023456781" in blob or "SA4420000001234567891234" in blob


def test_injection_via_document_is_tainted_and_gated():
    admin = session("admin")
    sid = mcp_initialize(admin)
    mcp_tools_call(admin, sid, "docs__read_document", {"doc_id": 4})   # reads injection -> taints
    res = mcp_tools_call(admin, sid, "actions__send_message",
                         {"recipient": "external@evil.example", "body": "docs"})
    g = res["_meta"]["gateway"]
    assert g["status"] == "pending_approval" and g["taint"]


def test_tier3_two_person_sod_and_step_up():
    admin, noura, faisal = session("admin"), session("noura"), session("faisal")
    step = call1(admin, "actions__delete_record", {"record_id": "8"})
    assert step["status"] == "pending_approval" and step["approvals_required"] == 2
    aid = step["approval_id"]
    # requester cannot approve own request (SoD)
    assert httpx.post(f"{BASE}/api/approvals/{aid}/approve", headers=h(admin)).status_code == 400
    # fresh approvers pass the Tier-3 step-up check and complete two-person control
    r1 = httpx.post(f"{BASE}/api/approvals/{aid}/approve", headers=h(noura)).json()
    assert r1["status"] == "recorded" and r1["remaining"] == 1
    assert httpx.post(f"{BASE}/api/approvals/{aid}/approve", headers=h(noura)).status_code == 400
    r2 = httpx.post(f"{BASE}/api/approvals/{aid}/approve", headers=h(faisal)).json()
    assert r2["status"] == "approved_and_executed" and r2["result"]["status"] == "executed"


def test_anti_hammering_lockout_and_admin_unlock():
    admin = session("admin")
    # 5 wrong-password logins lock the identity
    for i in range(5):
        httpx.post(f"{BASE}/api/auth/login",
                   json={"username": "noura", "password": f"wrong-{i}-Passw0rd!"})
    locked = httpx.post(f"{BASE}/api/auth/login",
                        json={"username": "noura", "password": DEMO_PW["noura"]})
    assert locked.status_code == 429                       # locked out even with the right password
    # admin clears the lockout -> login works again (two-layer: password then MFA)
    httpx.post(f"{BASE}/api/admin/unlock", headers=h(admin), json={"sub": "noura"})
    auth.enroll_totp("noura")
    l1 = httpx.post(f"{BASE}/api/auth/login",
                    json={"username": "noura", "password": DEMO_PW["noura"]})
    assert l1.status_code == 200
    ok = httpx.post(f"{BASE}/api/auth/mfa",
                    json={"mfa_ticket": l1.json()["mfa_ticket"], "otp": auth.totp_code("noura")})
    assert ok.status_code == 200


def test_killswitch_blocks():
    admin = session("admin")
    httpx.post(f"{BASE}/api/admin/killswitch/engage", headers=h(admin),
               json={"scope": "tool:docs:search_documents"})
    assert call1(admin, "docs__search_documents", {"query": "security"})["status"] == "blocked"
    httpx.post(f"{BASE}/api/admin/killswitch/release", headers=h(admin),
               json={"scope": "tool:docs:search_documents"})
    assert call1(admin, "docs__search_documents", {"query": "security"})["status"] == "executed"


def test_identity_revocation_blocks_in_flight_token():
    sara = session("sara")
    assert httpx.get(f"{BASE}/api/me", headers=h(sara)).status_code == 200
    admin = session("admin")
    httpx.post(f"{BASE}/api/admin/revoke", headers=h(admin), json={"sub": "sara"})
    try:
        assert httpx.get(f"{BASE}/api/me", headers=h(sara)).status_code == 401
        cert = pki.ensure_user_cert("sara")
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        assert httpx.post(f"{BASE}/api/login/challenge", json={"cert_pem": pem}).status_code == 401
    finally:
        httpx.post(f"{BASE}/api/admin/unrevoke", headers=h(admin), json={"sub": "sara"})


def test_audit_chain_intact():
    r = httpx.get(f"{BASE}/api/admin/audit", headers=h(session("admin"))).json()
    assert r["chain_ok"] is True


def test_non_admin_cannot_admin():
    assert httpx.get(f"{BASE}/api/admin/audit", headers=h(session("sara"))).status_code == 403


def test_credential_injection():  # A3
    admin = session("admin")
    step = call1(admin, "actions__list_records", {})
    assert step["status"] == "executed"
    # the actions server received a gateway-injected credential (never from the model)
    assert step["result"]["authenticated"] is True
    # the audit shows the injection with a lease + digest, but NEVER the secret value
    records = httpx.get(f"{BASE}/api/admin/audit", headers=h(admin)).json()["records"]
    inj = [r for r in records if r["event"] == "credential_injected"]
    assert inj, "expected a credential_injected audit event"
    assert "lease" in inj[-1] and "secret_digest" in inj[-1] and "secret" not in inj[-1]


def test_metrics_endpoint():  # A9
    admin = session("admin")
    m = httpx.get(f"{BASE}/api/metrics", headers=h(admin))
    assert m.status_code == 200
    body = m.json()
    assert "event_counts" in body and body["event_counts"].get("login", 0) >= 1
    # non-admin is denied
    assert httpx.get(f"{BASE}/api/metrics", headers=h(session("sara"))).status_code == 403


def test_schema_validation_rejects_unexpected_arg():   # W9.6
    step = call1(session("admin"), "actions__list_records", {"bogus_field": "x"})
    assert step["status"] == "blocked" and "schema" in step["reason"].lower()


def test_result_carries_classification_label():        # W3.3
    step = call1(session("khalid"), "actions__list_records", {})
    assert step["classification"] in ("public", "restricted", "secret", "top_secret")


def test_per_tool_rate_limit():  # A5
    # khalid:actions:list_records has a per-tool budget (limit 10/min)
    khalid = session("khalid")
    sid = mcp_initialize(khalid)
    statuses = [mcp_tools_call(khalid, sid, "actions__list_records", {})["_meta"]["gateway"]["status"]
                for _ in range(11)]
    assert statuses.count("executed") <= 10
    assert any(s == "blocked" for s in statuses), "11th call should hit the per-tool limit"


# ---------- MCP resources + prompts (full protocol surface) ----------
def test_mcp_resources_list_and_read():
    admin = session("admin"); sid = mcp_initialize(admin)
    r = mcp_rpc(admin, "resources/list", {}, sid=sid, id_=30).json()["result"]
    names = {x["name"] for x in r["resources"]}
    assert "docs_index" in names                                # a real resource is exposed
    uri = next(x["uri"] for x in r["resources"] if x["name"] == "docs_index")
    assert uri.startswith("mcpgw://")                            # namespaced per server
    rd = mcp_rpc(admin, "resources/read", {"uri": uri}, sid=sid, id_=31).json()["result"]
    assert rd["contents"][0]["text"]                            # content came back


def test_mcp_resource_read_dlp_by_clearance():
    def payroll_uri(sess, sid, i):
        r = mcp_rpc(sess, "resources/list", {}, sid=sid, id_=i).json()["result"]
        return next(x["uri"] for x in r["resources"] if "payroll" in x["name"].lower())
    # sara (restricted) must NOT see the Saudi national id in the payroll resource
    sara = session("sara"); ss = mcp_initialize(sara)
    stext = mcp_rpc(sara, "resources/read", {"uri": payroll_uri(sara, ss, 32)}, sid=ss, id_=33).json()["result"]["contents"][0]["text"]
    assert "1023456781" not in stext
    # admin (top_secret) sees it in the clear — DLP is clearance-aware on resources
    admin = session("admin"); a = mcp_initialize(admin)
    atext = mcp_rpc(admin, "resources/read", {"uri": payroll_uri(admin, a, 34)}, sid=a, id_=35).json()["result"]["contents"][0]["text"]
    assert "1023456781" in atext


def test_mcp_prompts_list_and_get():
    admin = session("admin"); sid = mcp_initialize(admin)
    pl = mcp_rpc(admin, "prompts/list", {}, sid=sid, id_=36).json()["result"]
    assert "docs__summarize_document" in [p["name"] for p in pl["prompts"]]
    g = mcp_rpc(admin, "prompts/get", {"name": "docs__summarize_document", "arguments": {"doc_id": "2"}},
                sid=sid, id_=37).json()["result"]
    assert g["messages"] and g["messages"][0]["content"]["type"] == "text"


def test_mcp_hitl_round_trip_result_over_mcp():
    # a held Tier-2 call's result becomes fetchable over MCP once an approver releases it
    admin = session("admin"); sid = mcp_initialize(admin)
    res = mcp_tools_call(admin, sid, "actions__send_message", {"recipient": "x@ex.com", "body": "hi"})
    assert res["_meta"]["gateway"]["status"] == "pending_approval"
    aid = res["_meta"]["gateway"]["approval_id"]
    before = json.loads(mcp_rpc(admin, "resources/read", {"uri": f"gateway://approval/{aid}"},
                                sid=sid, id_=38).json()["result"]["contents"][0]["text"])
    assert before["status"] == "pending" and before["result"] is None
    httpx.post(f"{BASE}/api/approvals/{aid}/approve", headers=h(session("noura")))
    after = json.loads(mcp_rpc(admin, "resources/read", {"uri": f"gateway://approval/{aid}"},
                               sid=sid, id_=39).json()["result"]["contents"][0]["text"])
    assert after["status"] == "approved" and after["result"] is not None
