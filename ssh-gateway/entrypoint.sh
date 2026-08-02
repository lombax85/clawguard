#!/bin/sh
set -eu

umask 077

AUTHORIZED_KEYS_SOURCE=${CLAWGUARD_AUTHORIZED_KEYS_FILE:-/config/authorized_keys}
AUTHORIZED_KEYS_TARGET=/home/gateway/.ssh/authorized_keys
HOST_KEY=/data/ssh_host_ed25519_key

if [ ! -f "$AUTHORIZED_KEYS_SOURCE" ]; then
  echo "fatal: authorized keys file not found: $AUTHORIZED_KEYS_SOURCE" >&2
  exit 1
fi

if [ ! -s "$AUTHORIZED_KEYS_SOURCE" ]; then
  echo "fatal: authorized keys file is empty: $AUTHORIZED_KEYS_SOURCE" >&2
  exit 1
fi

install -o gateway -g gateway -m 0600 "$AUTHORIZED_KEYS_SOURCE" "$AUTHORIZED_KEYS_TARGET"

mkdir -p /data /run/sshd
chmod 0700 /data

if [ ! -f "$HOST_KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'clawguard-ssh-gateway' -f "$HOST_KEY"
fi
chmod 0600 "$HOST_KEY"

echo "ClawGuard SSH gateway host key: $(ssh-keygen -lf "$HOST_KEY.pub" -E sha256 | awk '{print $2}')" >&2

/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
