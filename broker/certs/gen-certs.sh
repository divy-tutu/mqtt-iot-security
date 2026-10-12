#!/usr/bin/env bash
# Generate a self-contained TLS trust chain for the HARDENED broker (Phase 2).
#
# Produces, in this directory:
#   ca.key   ca.crt        - a throwaway Certificate Authority for the testbed
#   server.key server.crt  - the broker's TLS server certificate, signed by the CA
#
# The CA is the simplified, self-contained trust root described in the synopsis
# ("keys and certificates distributed via Docker Compose ... a production
# deployment would replace it with a proper certificate authority"). Devices and
# the browser trust ca.crt; the broker presents server.crt on 8883/9002.
#
# Re-runnable: deletes and regenerates everything. Certs are git-ignored.
set -euo pipefail
cd "$(dirname "$0")"

# Git Bash / MSYS rewrites arguments that look like Unix paths (e.g. the "/C=IN"
# in an openssl subject) into Windows paths. Disable that for this script.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

DAYS=3650
SUBJ_CA="/C=IN/O=MQTT-IoT-Security Testbed/CN=MQTT-IoT-Security Testbed CA"
SUBJ_SRV="/C=IN/O=MQTT-IoT-Security Testbed/CN=broker"

echo "[certs] generating CA ..."
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days "$DAYS" -key ca.key -out ca.crt -subj "$SUBJ_CA"

echo "[certs] generating broker server key + CSR ..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "$SUBJ_SRV"

# Subject Alternative Names: the broker is reached as "broker" inside the compose
# network, and as localhost / 127.0.0.1 from the host (openssl client, browser).
cat > server.ext <<'EOF'
subjectAltName = DNS:broker, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

echo "[certs] signing broker cert with CA ..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha256 -extfile server.ext

rm -f server.csr server.ext ca.srl
echo "[certs] done:"
ls -1 ca.crt server.crt server.key
