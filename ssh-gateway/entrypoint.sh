#!/bin/sh
set -eu

umask 077

AUTHORIZED_KEYS_SOURCE=${CLAWGUARD_AUTHORIZED_KEYS_FILE:-/config/authorized_keys}
AUTHORIZED_KEYS_TARGET=/home/gateway/.ssh/authorized_keys
HOST_KEY=/data/ssh_host_ed25519_key

if [ -f "$AUTHORIZED_KEYS_SOURCE" ] && [ -s "$AUTHORIZED_KEYS_SOURCE" ]; then
  install -o gateway -g gateway -m 0600 "$AUTHORIZED_KEYS_SOURCE" "$AUTHORIZED_KEYS_TARGET"
else
  # A fresh clone must be able to start the complete Compose stack. An empty
  # target is fail-closed: sshd runs, but no inbound public key can authenticate
  # until the operator installs one and recreates this container.
  echo "warning: no inbound SSH public keys at $AUTHORIZED_KEYS_SOURCE; gateway will deny all SSH logins" >&2
  install -o gateway -g gateway -m 0600 /dev/null "$AUTHORIZED_KEYS_TARGET"
fi

mkdir -p /data /run/sshd
chmod 0700 /data

if [ ! -f "$HOST_KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'clawguard-ssh-gateway' -f "$HOST_KEY"
fi
chmod 0600 "$HOST_KEY"

echo "ClawGuard SSH gateway host key: $(ssh-keygen -lf "$HOST_KEY.pub" -E sha256 | awk '{print $2}')" >&2

/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
