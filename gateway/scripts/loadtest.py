"""Load-test harness (W9.4). Drives the running gateway concurrently and reports
throughput + latency percentiles. Against the mock LLM it measures the control-plane
overhead; re-run against vLLM (llm.provider: openai_compat) for the §5 sizing test.

Usage:  python scripts/loadtest.py [--users 20] [--requests 200] [--base URL]
"""
import argparse
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import pki  # noqa: E402


def _session(base, user):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import base64
    cert = pki.ensure_user_cert(user)
    key = pki.load_user_key(user, pki.get_dev_pin(user))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    nonce = httpx.post(f"{base}/api/login/challenge", json={"cert_pem": pem}).json()["nonce"]
    sig = base64.b64encode(key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))).decode()
    j = httpx.post(f"{base}/api/login", json={"cert_pem": pem, "nonce": nonce, "signature": sig}).json()
    return {"Authorization": "Bearer " + j["token"], "X-Client-Cert-Thumbprint": j["thumbprint"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=10)
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--base", default="http://127.0.0.1:8800")
    a = ap.parse_args()

    headers = _session(a.base, "khalid")
    lat = []

    def one(_):
        t0 = time.time()
        r = httpx.post(f"{a.base}/api/chat", headers=headers, json={"message": "list records"}, timeout=30)
        dt = (time.time() - t0) * 1000
        lat.append(dt)
        return r.status_code == 200

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.users) as ex:
        oks = list(ex.map(one, range(a.requests)))
    wall = time.time() - t0

    lat.sort()
    print(f"requests={a.requests} users={a.users} ok={sum(oks)}/{len(oks)}")
    print(f"throughput={a.requests / wall:.1f} req/s  wall={wall:.2f}s")
    print(f"latency ms: p50={statistics.median(lat):.0f} "
          f"p95={lat[int(len(lat)*0.95)-1]:.0f} p99={lat[int(len(lat)*0.99)-1]:.0f} max={lat[-1]:.0f}")


if __name__ == "__main__":
    main()
