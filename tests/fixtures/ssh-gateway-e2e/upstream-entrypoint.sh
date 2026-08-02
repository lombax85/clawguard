#!/bin/sh
set -eu

umask 077

AUTHORIZED_KEYS_SOURCE=/e2e-config/authorized_keys
HOST_KEY_SOURCE=/e2e-config/ssh_host_ed25519_key
AUTHORIZED_KEYS_TARGET=/home/deploy/.ssh/authorized_keys
HOST_KEY_TARGET=/run/e2e-upstream-host-key

[ -s "$AUTHORIZED_KEYS_SOURCE" ] || {
  echo 'fatal: E2E upstream authorized_keys is missing or empty' >&2
  exit 1
}
[ -s "$HOST_KEY_SOURCE" ] || {
  echo 'fatal: E2E upstream host key is missing or empty' >&2
  exit 1
}

install -o deploy -g deploy -m 0600 "$AUTHORIZED_KEYS_SOURCE" "$AUTHORIZED_KEYS_TARGET"
install -o root -g root -m 0600 "$HOST_KEY_SOURCE" "$HOST_KEY_TARGET"

/usr/sbin/sshd -t -f /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
