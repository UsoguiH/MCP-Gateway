#!/usr/bin/env bash
# Generate a dev CA + server cert + one client cert for the mTLS terminator.
# PRODUCTION: the CA and server cert come from your internal PKI / step-ca; client
# certs are issued per workstation (TPM-resident key). This is dev/pilot only.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p tls
cd tls

SUBJ_CA="/C=SA/O=Government Entity/CN=MCP-Gateway-Dev-CA"
SUBJ_SRV="/C=SA/O=Government Entity/CN=gateway.internal"
SUBJ_CLI="/C=SA/O=Government Entity/CN=operator@gov"

# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 825 -subj "$SUBJ_CA" -out ca.crt

# Server cert (SAN = gateway.internal, localhost)
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "$SUBJ_SRV" -out server.csr
cat > server.ext <<EOF
subjectAltName=DNS:gateway.internal,DNS:localhost,IP:127.0.0.1
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile server.ext -out server.crt

# One client cert for testing mTLS
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "$SUBJ_CLI" -out client.csr
cat > client.ext <<EOF
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile client.ext -out client.crt

rm -f ./*.csr ./*.ext ./*.srl
echo "TLS material written to deploy/tls/ (ca.crt, server.crt/key, client.crt/key)."
echo "Client cert SHA-256 thumbprint (what the gateway binds tokens to):"
openssl x509 -in client.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
