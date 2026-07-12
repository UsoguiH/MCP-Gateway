# Secure MCP Gateway — container image (air-gapped: build from a private base mirror)
FROM python:3.13-slim

# Non-root runtime (least privilege; blueprint Layer 5)
RUN useradd --create-home --uid 10001 gateway
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# browser-mcp (Playwright/Chromium). Chromium's own OS libraries + the browser binary.
# In an air-gapped build these come from the private base mirror, not the internet.
# Omit this block if the browser connector is not deployed — every connector degrades to
# a clean "not installed" error when its dependency is absent.
RUN playwright install --with-deps chromium

COPY app ./app
COPY servers ./servers
COPY ui ./ui
COPY scripts ./scripts
COPY config.yaml policy.yaml ./

# Runtime state (PKI, audit, registry). Mount a volume here in production; in an
# air-gapped deployment the PKI is provisioned from the HSM/CA, not generated.
RUN mkdir -p /app/data /app/pki && chown -R gateway:gateway /app
USER gateway

# Secrets are supplied at runtime, never baked in (blueprint Layer 2):
#   MCP_GATEWAY_KEK  — key-encryption key for CA/signing keys (prod: HSM)
#   MCP_AUDIT_KEY    — HMAC key for the audit chain
#   MCP_VAULT_KEY    — base secret for dynamic credentials (prod: OpenBao)
EXPOSE 8800
# Longer start-period: the markitdown and qdrant connectors warm their engines at boot
# (document parser / embedding model) so the FIRST request is not the one that pays for it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s \
  CMD python -c "import httpx,sys; sys.exit(0 if httpx.get('http://127.0.0.1:8800/api/health').json().get('status')=='ok' else 1)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8800"]
