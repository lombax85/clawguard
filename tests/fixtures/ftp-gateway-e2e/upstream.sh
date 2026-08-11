#!/bin/sh
set -eu

mkdir -p /srv /data/upstream-tls
if [ ! -f /data/upstream-tls/tls.crt ] || [ ! -f /data/upstream-tls/tls.key ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=upstream' -addext 'subjectAltName=DNS:upstream' \
    -keyout /data/upstream-tls/tls.key -out /data/upstream-tls/tls.crt >/dev/null 2>&1
fi

rclone serve ftp /srv \
  --addr=:2121 \
  --passive-port=31000-31009 \
  --user=upstream-test-user \
  --pass=upstream-test-password \
  --log-level=NOTICE &

exec rclone serve ftp /srv \
  --addr=:2990 \
  --passive-port=32000-32009 \
  --user=upstream-test-user \
  --pass=upstream-test-password \
  --cert=/data/upstream-tls/tls.crt \
  --key=/data/upstream-tls/tls.key \
  --log-level=NOTICE
