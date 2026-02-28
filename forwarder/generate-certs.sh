#!/bin/bash
# Generates a local CA + per-domain certificates for ClawGuard Forwarder.
#
# Usage: ./generate-certs.sh api.openai.com slack.com graph.microsoft.com
#
# After running:
#   - Trust the CA on the agent machine:
#     sudo cp certs/ca.crt /usr/local/share/ca-certificates/clawguard-ca.crt
#     sudo update-ca-certificates
#   - Or for macOS:
#     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt

set -e

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

# ─── Generate CA (if not exists) ──────────────────────────────

if [ ! -f "$CERTS_DIR/ca.key" ]; then
  echo "🔐 Generating ClawGuard local CA..."
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERTS_DIR/ca.key" \
    -out "$CERTS_DIR/ca.crt" \
    -days 3650 -nodes \
    -subj "/CN=ClawGuard Local CA/O=ClawGuard"
  echo "   ✓ CA created: $CERTS_DIR/ca.crt"
  echo ""
  echo "   ⚠️  IMPORTANT: Trust this CA on the agent machine:"
  echo "   Linux:  sudo cp $CERTS_DIR/ca.crt /usr/local/share/ca-certificates/clawguard-ca.crt && sudo update-ca-certificates"
  echo "   macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERTS_DIR/ca.crt"
  echo ""
fi

# ─── Generate fallback cert ──────────────────────────────────

if [ ! -f "$CERTS_DIR/fallback.key" ]; then
  echo "🔐 Generating fallback certificate..."
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS_DIR/fallback.key" \
    -out "$CERTS_DIR/fallback.csr" \
    -subj "/CN=clawguard-forwarder"
  openssl x509 -req -in "$CERTS_DIR/fallback.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial -out "$CERTS_DIR/fallback.crt" \
    -days 3650
  rm "$CERTS_DIR/fallback.csr"
  echo "   ✓ Fallback cert created"
fi

# ─── Generate per-domain certs ────────────────────────────────

if [ $# -eq 0 ]; then
  echo "Usage: $0 <domain1> [domain2] [domain3] ..."
  echo "Example: $0 api.openai.com slack.com"
  exit 0
fi

for DOMAIN in "$@"; do
  echo "🔐 Generating certificate for: $DOMAIN"

  # Create config with SAN
  cat > "$CERTS_DIR/$DOMAIN.cnf" << EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = $DOMAIN

[v3_req]
subjectAltName = DNS:$DOMAIN
EOF

  openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS_DIR/$DOMAIN.key" \
    -out "$CERTS_DIR/$DOMAIN.csr" \
    -config "$CERTS_DIR/$DOMAIN.cnf"

  openssl x509 -req -in "$CERTS_DIR/$DOMAIN.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial -out "$CERTS_DIR/$DOMAIN.crt" \
    -days 3650 \
    -extfile "$CERTS_DIR/$DOMAIN.cnf" -extensions v3_req

  rm "$CERTS_DIR/$DOMAIN.csr" "$CERTS_DIR/$DOMAIN.cnf"
  echo "   ✓ $DOMAIN cert created"
done

echo ""
echo "✅ Done! Certs are in $CERTS_DIR/"
echo ""
echo "Next steps:"
echo "  1. Trust the CA:     (see commands above)"
echo "  2. Edit /etc/hosts:  echo '127.0.0.1 $*' | sudo tee -a /etc/hosts"
echo "  3. Edit forwarder.json with your ClawGuard address"
echo "  4. Run:              sudo node forwarder.js"
