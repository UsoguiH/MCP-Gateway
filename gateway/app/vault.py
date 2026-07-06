"""Credential vault — per-call dynamic secrets (spec §4.4, blueprint Layer 2).

The gateway holds distinct, least-privilege credentials per backend and injects a
short-lived, per-(server,user) credential into each tool call at dispatch time.
Secrets are NEVER placed in model context and NEVER written to the audit payload
(only a lease id + digest are recorded).

DEV: secrets are minted locally from a per-server base secret with an HMAC over
(server,user,lease). PRODUCTION SWAP POINT: replace `issue()` with OpenBao dynamic
database credentials (unique short-TTL user per request) fetched via `hvac`; keys
in HSM. The injection mechanism above the vault is unchanged.
"""
import hashlib
import hmac
import os
import threading
import time
import uuid

from .config import CONFIG


class Vault:
    def __init__(self):
        self.cfg = CONFIG.get("vault", {}) or {}
        # provider: dev (local HMAC) | openbao (dynamic DB creds via hvac).
        self.provider = os.environ.get("MCP_VAULT_PROVIDER",
                                       (CONFIG.get("vault_provider") or "dev"))
        from .config import secret
        self._base = secret("MCP_VAULT_KEY", "dev-vault-key-change-me").encode()
        self._leases: dict[str, dict] = {}     # lease_id -> {server,user,exp}
        self._lock = threading.Lock()

    def manages(self, server: str) -> bool:
        return server in self.cfg

    def issue(self, server: str, user: str) -> dict | None:
        """Mint a short-lived credential for (server, user). Returns {lease, secret, exp}."""
        spec = self.cfg.get(server)
        if not spec:
            return None
        if self.provider == "openbao":
            return self._issue_openbao(server, user, spec)
        ttl = int(spec.get("ttl_seconds", 300))
        lease = uuid.uuid4().hex[:16]
        exp = time.time() + ttl
        # dev secret: deterministic per lease, never persisted in cleartext
        secret = hmac.new(self._base, f"{server}:{user}:{lease}".encode(), hashlib.sha256).hexdigest()
        with self._lock:
            self._leases[lease] = {"server": server, "user": user, "exp": exp}
            self._gc()
        return {"lease": lease, "secret": secret, "exp": exp}

    def _issue_openbao(self, server: str, user: str, spec: dict) -> dict:
        """Production path: dynamic DB credentials from OpenBao's database engine.
        Requires `hvac` and a reachable OpenBao (env MCP_VAULT_ADDR / MCP_VAULT_TOKEN).
        The unique short-TTL DB user is the injected credential; lease id = OpenBao's."""
        try:
            import hvac
        except ModuleNotFoundError as e:
            raise RuntimeError("vault_provider=openbao requires the 'hvac' package") from e
        client = hvac.Client(url=os.environ["MCP_VAULT_ADDR"], token=os.environ["MCP_VAULT_TOKEN"])
        role = spec.get("openbao_role", server)
        resp = client.secrets.database.generate_credentials(name=role)
        data, lease = resp["data"], resp["lease_id"]
        with self._lock:
            self._leases[lease] = {"server": server, "user": user,
                                   "exp": time.time() + resp.get("lease_duration", 300)}
        # secret = the dynamic DB user:password (never in model context/audit)
        return {"lease": lease, "secret": f"{data['username']}:{data['password']}",
                "exp": time.time() + resp.get("lease_duration", 300)}

    def revoke(self, lease: str):
        with self._lock:
            self._leases.pop(lease, None)
        if self.provider == "openbao":
            try:
                import hvac
                hvac.Client(url=os.environ["MCP_VAULT_ADDR"],
                            token=os.environ["MCP_VAULT_TOKEN"]).sys.revoke_lease(lease)
            except Exception:
                pass   # lease also expires by TTL; best-effort immediate revoke

    def active_leases(self) -> list[dict]:
        now = time.time()
        with self._lock:
            self._gc()
            return [{"lease": k, "server": v["server"], "user": v["user"],
                     "expires_in": round(v["exp"] - now)} for k, v in self._leases.items()]

    def _gc(self):
        now = time.time()
        for k in [k for k, v in self._leases.items() if v["exp"] < now]:
            self._leases.pop(k, None)


vault = Vault()
