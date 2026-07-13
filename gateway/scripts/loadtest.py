"""Load-test harness (Phase 3, task 4). Drives the running gateway with N
CONCURRENT MCP SESSIONS — each session its own provisioned operator with its own
OAuth-shaped identity, its own rate-limit budget, and its own MCP session id —
and reports throughput + latency percentiles for the PEP overhead per mediated
tool call. The gateway runs no model, so what is measured is the control plane:
edge guard + auth + session + kill-switch + 3-key rate limit + registry +
Unicode + schema + taint + ABAC + dispatch + result governance + audit append.

Target (PROJECT-PLAN §12): p95 added latency ≤ 150 ms per mediated call at 300
concurrent sessions.

Modes:
  * --provision N  : create N temporary operators (loadtest-0001…) through the
                     admin API, run the test, then offboard them (unless --keep).
                     Needs one admin sign-in: --admin-user/--admin-password and
                     either --admin-otp (one current code) or --admin-totp-secret.
  * default        : single-operator smoke mode (the old behaviour) via the dev
                     cert login — dev stacks only.

Works through the mTLS proxy (--base https://localhost:8443 --client-cert
deploy/tls/client.crt --client-key deploy/tls/client.key --ca deploy/tls/ca.crt)
or straight at a dev gateway (--base http://127.0.0.1:8800).

Examples:
  python scripts/loadtest.py --provision 300 --duration 60 --pace 2.0 \
      --base https://localhost:8443 --ca deploy/tls/ca.crt \
      --client-cert deploy/tls/client.crt --client-key deploy/tls/client.key \
      --admin-user admin --admin-password ... --admin-otp 123456 \
      --tool files__list_shares
"""
import argparse
import base64
import concurrent.futures
import hashlib
import hmac as hmac_mod
import json
import statistics
import struct
import sys
import threading
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PREFIX = "loadtest-"          # purge_test_artifacts.py knows this prefix too


def _totp(b32secret: str, at: float | None = None) -> str:
    """RFC 6238 (SHA1/30s/6 digits) — matches app.auth's enrolment parameters."""
    pad = "=" * (-len(b32secret) % 8)
    key = base64.b32decode(b32secret.upper() + pad)
    counter = int((time.time() if at is None else at) // 30)
    mac = hmac_mod.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 10**6).zfill(6)


def _client(a) -> httpx.Client:
    # --ca verifies the server cert; --insecure skips that (the dev CA carries no
    # keyUsage extension, which strict OpenSSL refuses — org PKI fixes it in Phase 6).
    # The CLIENT cert is still presented either way: mTLS auth is unaffected.
    verify = False if (a.insecure or not a.base.startswith("https")) else (a.ca or True)
    cert = (a.client_cert, a.client_key) if a.client_cert else None
    return httpx.Client(base_url=a.base, verify=verify, cert=cert, timeout=30)


# ---------------------------------------------------------------------------
# admin session (provisioning)
# ---------------------------------------------------------------------------

def _admin_login(c: httpx.Client, a) -> dict:
    otp = a.admin_otp or (_totp(a.admin_totp_secret) if a.admin_totp_secret else "")
    r = c.post("/api/auth/login", json={"username": a.admin_user,
                                        "password": a.admin_password})
    r.raise_for_status()
    j = r.json()
    if j.get("mfa_required"):
        if not otp:
            sys.exit("admin MFA required: pass --admin-otp or --admin-totp-secret")
        r = c.post("/api/auth/mfa", json={"mfa_ticket": j["mfa_ticket"], "otp": otp})
        r.raise_for_status()
        j = r.json()
    return {"Authorization": "Bearer " + j["token"],
            "X-Client-Cert-Thumbprint": j["thumbprint"]}


def _provision(c: httpx.Client, admin: dict, n: int, role: str,
               clearance: str) -> list[dict]:
    """Create n operators; returns [{sub, password, totp_secret}]. Existing
    loadtest-* operators are reused-by-recreate (offboard first) so reruns are clean."""
    ops = []
    for i in range(1, n + 1):
        sub = f"{PREFIX}{i:04d}"
        c.post(f"/api/admin/operators/{sub}/offboard", headers=admin)  # 404 is fine
        r = c.post("/api/admin/operators", headers=admin,
                   json={"sub": sub, "name": f"Load Test {i}", "role": role,
                         "clearance": clearance})
        if r.status_code != 200:
            sys.exit(f"provisioning {sub} failed: {r.status_code} {r.text[:200]}")
        j = r.json()
        ops.append({"sub": sub, "password": j["temp_password"],
                    "totp_secret": j["totp_secret"]})
        if i % 50 == 0:
            print(f"  provisioned {i}/{n}")
    return ops


def _deprovision(c: httpx.Client, admin: dict, ops: list[dict]):
    for o in ops:
        c.post(f"/api/admin/operators/{o['sub']}/offboard", headers=admin)


def _raise_limits(c: httpx.Client, admin: dict, server: str, per_tool: int = 60):
    """The gateway's own budgets (per-server 60/min, per-(user,tool) 10/min) would
    throttle the harness long before 300 sessions. Raise them for the run through
    the same console API an admin would use, remembering what to put back."""
    prev = c.get("/api/admin/settings", headers=admin).json()["overrides"] \
        .get("rate_limits", {})
    c.post("/api/admin/settings", headers=admin, json={
        "section": "rate_limits",
        "patch": {"per_tool_per_minute": per_tool,
                  "per_server_overrides": {server: 100_000}}}).raise_for_status()

    def restore(cli: httpx.Client, adm: dict):
        patch = {"per_tool_per_minute": prev.get("per_tool_per_minute", 10),
                 "per_server_overrides": prev.get("per_server_overrides", {}) or
                 {server: 60}}
        cli.post("/api/admin/settings", headers=adm,
                 json={"section": "rate_limits", "patch": patch})
    return restore


# ---------------------------------------------------------------------------
# per-operator session: password(+rotate)+TOTP login -> bearer -> MCP initialize
# ---------------------------------------------------------------------------

def _post_retry(c: httpx.Client, path: str, *, json_body: dict, tries: int = 8):
    """POST, backing off on 429.

    The gateway throttles authentication per SOURCE IP (login_rate_per_minute) — and a
    load test signing 300 operators in from ONE machine looks exactly like credential
    stuffing, which is precisely what that control is for. Real users arrive from 300
    different workstations. So the HARNESS adapts (the defence stays on): it backs off
    and retries, and the login phase is deliberately not what we measure — the mediated
    tool call is."""
    delay = 1.0
    for _ in range(tries):
        r = c.post(path, json=json_body)
        if r.status_code != 429:
            return r
        time.sleep(delay)
        delay = min(delay * 1.6, 15)
    return r


def _operator_session(c: httpx.Client, op: dict) -> dict | None:
    """Sign one temp operator in (rotating the forced temp password), then open
    an MCP session. Returns the ready-to-call headers, or None on failure."""
    try:
        r = _post_retry(c, "/api/auth/login",
                        json_body={"username": op["sub"], "password": op["password"]})
        if r.status_code != 200:
            return None
        j = r.json()
        if j.get("mfa_required"):
            r = _post_retry(c, "/api/auth/mfa",
                            json_body={"mfa_ticket": j["mfa_ticket"],
                                       "otp": _totp(op["totp_secret"])})
            if r.status_code != 200:
                return None
            j = r.json()
        headers = {"Authorization": "Bearer " + j["token"],
                   "X-Client-Cert-Thumbprint": j["thumbprint"]}
        # temp passwords carry must_change: rotate once so /mcp is usable
        new_pw = op["password"] + "x9!Z"
        r = c.post("/api/auth/password", headers=headers,
                   json={"old_password": op["password"], "new_password": new_pw})
        if r.status_code == 200:
            op["password"] = new_pw
        r = c.post("/mcp", headers={**headers,
                                    "Accept": "application/json, text/event-stream",
                                    "Content-Type": "application/json"},
                   json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                    "clientInfo": {"name": "loadtest", "version": "3"}}})
        sid = r.headers.get("Mcp-Session-Id")
        if not sid:
            return None
        c.post("/mcp", headers={**headers, "Mcp-Session-Id": sid},
               json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        return {**headers, "Mcp-Session-Id": sid,
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json"}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

def _drive(a, make_client, sessions: list[dict]) -> dict:
    """Every session issues one call every `pace` seconds for `duration` seconds."""
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": a.tool, "arguments": {}}}
    lat, outcomes = [], {"executed": 0, "blocked": 0, "error": 0, "http_error": 0}
    lock = threading.Lock()
    stop_at = time.time() + a.duration

    def one_session(headers):
        with make_client() as c:
            while time.time() < stop_at:
                t0 = time.perf_counter()
                try:
                    r = c.post("/mcp", headers=headers, json=body)
                    dt = (time.perf_counter() - t0) * 1000
                    ok = r.status_code == 200
                    kind = "http_error"
                    if ok:
                        j = r.json()
                        meta = (j.get("result") or {}).get("_meta", {}).get("gateway", {})
                        status = meta.get("status", "executed")
                        kind = ("executed" if status == "executed"
                                else "blocked" if status in ("blocked", "denied")
                                else "error")
                except Exception:
                    dt = (time.perf_counter() - t0) * 1000
                    kind = "http_error"
                with lock:
                    outcomes[kind] += 1
                    if kind == "executed":
                        lat.append(dt)
                sleep = a.pace - (time.perf_counter() - t0)
                if sleep > 0:
                    time.sleep(sleep)

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sessions)) as ex:
        list(ex.map(one_session, sessions))
    wall = time.time() - t0
    return {"lat": sorted(lat), "outcomes": outcomes, "wall": wall}


def _pct(s, p):
    return s[min(len(s) - 1, int(len(s) * p / 100))] if s else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provision", type=int, default=0,
                    help="create this many temp operators and run one session each")
    ap.add_argument("--duration", type=int, default=60, help="seconds of sustained load")
    ap.add_argument("--pace", type=float, default=2.2,
                    help="seconds between calls per session (2.2 ≈ 27/min, just under "
                         "the 30/min per-user budget so the limiter is exercised, not slammed)")
    ap.add_argument("--tool", default="files__list_shares",
                    help="server__tool to call — must be ACTIVE in the registry and its "
                         "server entitled to --role (a cheap tier-0 read)")
    ap.add_argument("--role", default="employee",
                    help="role for the temp operators (must be entitled to the tool's server)")
    ap.add_argument("--clearance", default="restricted")
    ap.add_argument("--base", default="http://127.0.0.1:8800")
    ap.add_argument("--ca", default="")
    ap.add_argument("--insecure", action="store_true",
                    help="skip SERVER cert verification (dev CA); client cert still presented")
    ap.add_argument("--client-cert", default="")
    ap.add_argument("--client-key", default="")
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password", default="")
    ap.add_argument("--admin-otp", default="")
    ap.add_argument("--admin-totp-secret", default="")
    ap.add_argument("--keep", action="store_true", help="leave the temp operators in place")
    # legacy single-user smoke flags
    ap.add_argument("--users", type=int, default=10)
    ap.add_argument("--requests", type=int, default=200)
    a = ap.parse_args()

    make_client = lambda: _client(a)          # noqa: E731

    if not a.provision:
        return _legacy_smoke(a, make_client)

    with make_client() as c:
        admin = _admin_login(c, a)
        print(f"[1/4] provisioning {a.provision} {a.role} operators…")
        ops = _provision(c, admin, a.provision, a.role, a.clearance)
        restore_limits = _raise_limits(c, admin, a.tool.split("__")[0])

    print(f"[2/4] opening {len(ops)} MCP sessions (backing off the per-IP login "
          f"throttle as needed)...")
    sessions = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        def open_one(op):
            with make_client() as c:
                return _operator_session(c, op)
        sessions = [s for s in ex.map(open_one, ops) if s]
    print(f"      {len(sessions)}/{len(ops)} sessions established")
    if len(sessions) < len(ops):
        print(f"      !! {len(ops) - len(sessions)} session(s) failed to establish — "
              f"the numbers below cover only the {len(sessions)} that did")
    if not sessions:
        sys.exit("no sessions established - check credentials/certs/tool name/entitlement")

    print(f"[3/4] driving {len(sessions)} concurrent sessions for {a.duration}s "
          f"(1 call / {a.pace}s each -> ~{len(sessions)/a.pace:.0f} calls/s aggregate)...")
    res = _drive(a, make_client, sessions)

    lat, o = res["lat"], res["outcomes"]
    total = sum(o.values())
    print(f"\n[4/4] results - {total} calls in {res['wall']:.1f}s "
          f"({total/res['wall']:.1f} req/s aggregate)")
    print(f"  concurrent sessions: {len(sessions)}")
    print(f"  executed={o['executed']}  blocked(rate/policy)={o['blocked']}  "
          f"tool_error={o['error']}  http_error={o['http_error']}")
    if lat:
        print(f"  gateway-mediated latency (executed calls, ms): "
              f"p50={_pct(lat,50):.0f}  p95={_pct(lat,95):.0f}  "
              f"p99={_pct(lat,99):.0f}  max={lat[-1]:.0f}")
        print(f"  TARGET p95 <= 150 ms: {'PASS' if _pct(lat,95) <= 150 else 'FAIL'} "
              f"({_pct(lat,95):.0f} ms)")
    with make_client() as c:
        admin = _admin_login(c, a)
        restore_limits(c, admin)
        if not a.keep:
            print("  cleaning up temp operators…")
            _deprovision(c, admin, ops)
    return 0


def _legacy_smoke(a, make_client):
    """Original single-operator mode (dev cert login) — kept for quick checks."""
    from app import pki
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    with make_client() as c:
        cert = pki.ensure_user_cert("khalid")
        key = pki.load_user_key("khalid", pki.get_dev_pin("khalid"))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        nonce = c.post("/api/login/challenge", json={"cert_pem": pem}).json()["nonce"]
        sig = base64.b64encode(key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))).decode()
        j = c.post("/api/login", json={"cert_pem": pem, "nonce": nonce, "signature": sig}).json()
        headers = {"Authorization": "Bearer " + j["token"],
                   "X-Client-Cert-Thumbprint": j["thumbprint"],
                   "Accept": "application/json, text/event-stream",
                   "Content-Type": "application/json"}
        r = c.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "loadtest", "version": "1"}}})
        headers["Mcp-Session-Id"] = r.headers.get("Mcp-Session-Id")
        body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": a.tool, "arguments": {}}}
        lat = []

        def one(_):
            t0 = time.time()
            r = c.post("/mcp", headers=headers, json=body)
            lat.append((time.time() - t0) * 1000)
            return r.status_code == 200

        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.users) as ex:
            oks = list(ex.map(one, range(a.requests)))
        wall = time.time() - t0
        lat.sort()
        print(f"requests={a.requests} users={a.users} ok={sum(oks)}/{len(oks)}")
        print(f"throughput={a.requests / wall:.1f} req/s  wall={wall:.2f}s")
        print(f"latency ms: p50={statistics.median(lat):.0f} "
              f"p95={_pct(lat, 95):.0f} p99={_pct(lat, 99):.0f} max={lat[-1]:.0f}")


if __name__ == "__main__":
    main()
