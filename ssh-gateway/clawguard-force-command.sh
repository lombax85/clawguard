#!/bin/sh
set -eu
set -f

umask 077

BROKER_SOCKET=${CLAWGUARD_SSH_BROKER_SOCKET:-/run/clawguard-ssh/broker.sock}
BROKER_TIMEOUT_SECONDS=${CLAWGUARD_SSH_BROKER_TIMEOUT_SECONDS:-135}
ORIGINAL_COMMAND=${SSH_ORIGINAL_COMMAND:-}
RUNTIME_DIR=${TMPDIR:-/tmp}

fail() {
  echo "ClawGuard SSH gateway: $1" >&2
  exit 126
}

case "$BROKER_TIMEOUT_SECONDS" in
  ''|*[!0-9]*) fail 'invalid broker timeout' ;;
esac
[ "${#BROKER_TIMEOUT_SECONDS}" -le 3 ] \
  && [ "$BROKER_TIMEOUT_SECONDS" -ge 1 ] \
  && [ "$BROKER_TIMEOUT_SECONDS" -le 600 ] \
  || fail 'broker timeout must be between 1 and 600 seconds'

if [ -z "$ORIGINAL_COMMAND" ]; then
  fail 'missing service alias; use: ssh -t gateway@host -- SERVICE'
fi

SERVICE=${ORIGINAL_COMMAND%% *}
case "$SERVICE" in
  ''|*[!A-Za-z0-9_-]*) fail 'invalid service alias' ;;
esac

REMAINDER=${ORIGINAL_COMMAND#"$SERVICE"}
REMAINDER=${REMAINDER# }

ACTION=shell
REMOTE_COMMAND=
if [ -n "$REMAINDER" ]; then
  case "$REMAINDER" in
    --\ *)
      ACTION=exec
      REMOTE_COMMAND=${REMAINDER#-- }
      [ -n "$REMOTE_COMMAND" ] || fail 'empty remote command'
      ;;
    *) fail 'expected -- before the remote command' ;;
  esac
fi

CLIENT_IP=unknown
if [ -n "${SSH_CONNECTION:-}" ]; then
  CLIENT_IP=${SSH_CONNECTION%% *}
fi

REQUEST_FILE=$(mktemp "$RUNTIME_DIR/clawguard-ssh-request.XXXXXX")
RESPONSE_FILE=$(mktemp "$RUNTIME_DIR/clawguard-ssh-response.XXXXXX")
KNOWN_HOSTS_FILE=$(mktemp "$RUNTIME_DIR/clawguard-known-hosts.XXXXXX")
LEASE_ID=

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM

  if [ -n "$LEASE_ID" ] && [ -S "$BROKER_SOCKET" ]; then
    completion=$(jq -cn --argjson exitStatus "$status" '{exitStatus:$exitStatus}')
    curl --silent --show-error --max-time 5 \
      --unix-socket "$BROKER_SOCKET" \
      --header 'content-type: application/json' \
      --request POST \
      --data "$completion" \
      "http://localhost/session/$LEASE_ID/complete" >/dev/null 2>&1 || true
  fi

  rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$KNOWN_HOSTS_FILE"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

jq -cn \
  --arg service "$SERVICE" \
  --arg clientIp "$CLIENT_IP" \
  --arg action "$ACTION" \
  '{service:$service,clientIp:$clientIp,action:$action}' >"$REQUEST_FILE"

if [ ! -S "$BROKER_SOCKET" ]; then
  fail 'broker unavailable'
fi

HTTP_STATUS=$(curl --silent --show-error \
  --max-time "$BROKER_TIMEOUT_SECONDS" \
  --unix-socket "$BROKER_SOCKET" \
  --output "$RESPONSE_FILE" \
  --write-out '%{http_code}' \
  --header 'content-type: application/json' \
  --request POST \
  --data-binary "@$REQUEST_FILE" \
  'http://localhost/session') || fail 'broker request failed'

if [ "$HTTP_STATUS" != 201 ]; then
  ERROR_MESSAGE=$(jq -r '.error // "access denied"' "$RESPONSE_FILE" 2>/dev/null || echo 'access denied')
  fail "$ERROR_MESSAGE"
fi

LEASE_ID=$(jq -er '.leaseId | select(test("^[A-Za-z0-9_-]+$"))' "$RESPONSE_FILE") || fail 'invalid broker lease id'
AGENT_SOCKET=$(jq -er '.agentSocket | select(startswith("/run/clawguard-ssh/"))' "$RESPONSE_FILE") || fail 'invalid broker agent socket'
MAX_SESSION_SECONDS=$(jq -er '.maxSessionSeconds | select(type == "number" and floor == . and . >= 1 and . <= 86400)' "$RESPONSE_FILE") || fail 'invalid maximum session duration'
TARGET_HOST=$(jq -er '.target.host | select(length <= 64 and (test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$") or test("^[0-9A-Fa-f:]+$")))' "$RESPONSE_FILE") || fail 'invalid target host'
TARGET_PORT=$(jq -er '.target.port | select(type == "number" and . >= 1 and . <= 65535)' "$RESPONSE_FILE") || fail 'invalid target port'
TARGET_USER=$(jq -er '.target.username | select(test("^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$"))' "$RESPONSE_FILE") || fail 'invalid target username'
HOST_KEY_ALIAS=$(jq -er '.target.hostKeyAlias | select(test("^[A-Za-z0-9._-]+$"))' "$RESPONSE_FILE") || fail 'invalid host-key alias'
KNOWN_HOSTS_LINE=$(jq -er '.target.knownHostsLine | select(length > 0 and contains("\n") | not)' "$RESPONSE_FILE") || fail 'invalid pinned host key'

[ -S "$AGENT_SOCKET" ] || fail 'credential lease socket unavailable'
printf '%s\n' "$KNOWN_HOSTS_LINE" >"$KNOWN_HOSTS_FILE"
chmod 0600 "$KNOWN_HOSTS_FILE"

# The broker keeps the response provisional until the wrapper has durably
# parsed every security-sensitive field and confirmed the agent socket. This
# short acknowledgement prevents an interrupted handoff from holding a full
# session-capacity slot until maxSessionSeconds.
ACTIVATION_STATUS=$(curl --silent --show-error \
  --max-time 5 \
  --unix-socket "$BROKER_SOCKET" \
  --output /dev/null \
  --write-out '%{http_code}' \
  --header 'content-type: application/json' \
  --request POST \
  --data '{}' \
  "http://localhost/session/$LEASE_ID/activate") || fail 'broker activation acknowledgement failed'
[ "$ACTIVATION_STATUS" = 200 ] || fail 'broker activation acknowledgement rejected'

set -- \
  -F /dev/null \
  -o BatchMode=yes \
  -o CanonicalizeHostname=no \
  -o CheckHostIP=no \
  -o ClearAllForwardings=yes \
  -o ConnectionAttempts=1 \
  -o ConnectTimeout=20 \
  -o ControlMaster=no \
  -o EnableEscapeCommandline=no \
  -o EscapeChar=none \
  -o ExitOnForwardFailure=yes \
  -o ForwardAgent=no \
  -o GlobalKnownHostsFile=/dev/null \
  -o "HostKeyAlias=$HOST_KEY_ALIAS" \
  -o IdentitiesOnly=no \
  -o IdentityFile=none \
  -o "IdentityAgent=$AGENT_SOCKET" \
  -o KbdInteractiveAuthentication=no \
  -o KnownHostsCommand=none \
  -o NumberOfPasswordPrompts=0 \
  -o PasswordAuthentication=no \
  -o PermitLocalCommand=no \
  -o PreferredAuthentications=publickey \
  -o ProxyCommand=none \
  -o ProxyJump=none \
  -o PubkeyAuthentication=yes \
  -o StrictHostKeyChecking=yes \
  -o UpdateHostKeys=no \
  -o "UserKnownHostsFile=$KNOWN_HOSTS_FILE" \
  -o VerifyHostKeyDNS=no \
  -p "$TARGET_PORT" \
  -l "$TARGET_USER"

if [ "$ACTION" = shell ]; then
  timeout -s TERM "$MAX_SESSION_SECONDS" ssh -tt "$@" "$TARGET_HOST"
else
  timeout -s TERM "$MAX_SESSION_SECONDS" ssh -T "$@" "$TARGET_HOST" "$REMOTE_COMMAND"
fi
