#!/bin/sh
set -eu

umask 077

RUNTIME_DIR=/run/clawguard-ftp
DATA_DIR=/data
CERT_FILE=${CLAWGUARD_FTP_CERT_FILE:-/data/tls.crt}
KEY_FILE=${CLAWGUARD_FTP_KEY_FILE:-/data/tls.key}
TLS_HOSTNAME=${CLAWGUARD_FTP_TLS_HOSTNAME:-localhost}
TLS_NAME_FILE=/data/tls.hostname

case "$TLS_HOSTNAME" in
  ''|*[!A-Za-z0-9._-]*) echo 'fatal: invalid CLAWGUARD_FTP_TLS_HOSTNAME' >&2; exit 1 ;;
esac

mkdir -p "$RUNTIME_DIR" "$DATA_DIR" /tmp
chown ftp-gateway:ftp-gateway "$RUNTIME_DIR" "$DATA_DIR" /tmp
chmod 0700 "$RUNTIME_DIR" "$DATA_DIR"

for TLS_PATH in "$CERT_FILE" "$KEY_FILE" "$TLS_NAME_FILE"; do
  if [ -L "$TLS_PATH" ] || { [ -e "$TLS_PATH" ] && [ ! -f "$TLS_PATH" ]; }; then
    echo "fatal: unsafe FTP TLS file: $TLS_PATH" >&2
    exit 1
  fi
done

CURRENT_TLS_HOSTNAME=
if [ -f "$TLS_NAME_FILE" ]; then
  CURRENT_TLS_HOSTNAME=$(sed -n '1p' "$TLS_NAME_FILE")
fi

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ] || [ "$CURRENT_TLS_HOSTNAME" != "$TLS_HOSTNAME" ]; then
  if node -e "process.exit(require('node:net').isIP(process.argv[1]) ? 0 : 1)" "$TLS_HOSTNAME"; then
    TLS_SAN="IP:$TLS_HOSTNAME,IP:127.0.0.1"
  else
    TLS_SAN="DNS:$TLS_HOSTNAME,IP:127.0.0.1"
  fi
  TEMP_KEY=$(mktemp "$DATA_DIR/.tls-key.XXXXXX")
  TEMP_CERT=$(mktemp "$DATA_DIR/.tls-cert.XXXXXX")
  trap 'rm -f "$TEMP_KEY" "$TEMP_CERT"' EXIT HUP INT TERM
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj "/CN=$TLS_HOSTNAME" \
    -addext "subjectAltName=$TLS_SAN" \
    -keyout "$TEMP_KEY" -out "$TEMP_CERT" >/dev/null 2>&1
  mv "$TEMP_KEY" "$KEY_FILE"
  mv "$TEMP_CERT" "$CERT_FILE"
  printf '%s\n' "$TLS_HOSTNAME" > "$TLS_NAME_FILE"
  trap - EXIT HUP INT TERM
fi
chown ftp-gateway:ftp-gateway "$CERT_FILE" "$KEY_FILE" "$TLS_NAME_FILE"
chmod 0600 "$KEY_FILE"
chmod 0644 "$CERT_FILE"
chmod 0600 "$TLS_NAME_FILE"

exec su-exec ftp-gateway:ftp-gateway node /app/supervisor.js
