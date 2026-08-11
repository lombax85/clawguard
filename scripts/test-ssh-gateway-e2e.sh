#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/ssh-gateway-e2e"

log() {
  printf '[ssh-gateway-e2e] %s\n' "$*"
}

fail() {
  printf '[ssh-gateway-e2e] FAIL: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf '[ssh-gateway-e2e] SKIP: %s\n' "$*"
  exit 0
}

command -v docker >/dev/null 2>&1 || skip 'Docker CLI is unavailable'
docker info >/dev/null 2>&1 || skip 'Docker daemon is unavailable'
command -v ssh >/dev/null 2>&1 || skip 'stock OpenSSH client is unavailable'
command -v ssh-keygen >/dev/null 2>&1 || skip 'ssh-keygen is unavailable'

RUN_TOKEN="$$-${RANDOM:-0}"
RUN_ID="cg-ssh-e2e-$RUN_TOKEN"
NETWORK_NAME="$RUN_ID-net"
RUNTIME_VOLUME="$RUN_ID-runtime"
UPSTREAM_CONTAINER="$RUN_ID-upstream"
BROKER_CONTAINER="$RUN_ID-broker"
TTL_BROKER_CONTAINER="$RUN_ID-broker-ttl"
MISMATCH_BROKER_CONTAINER="$RUN_ID-broker-mismatch"
GATEWAY_CONTAINER="$RUN_ID-gateway"
RESOURCE_LABEL="com.clawguard.ssh-e2e.run=$RUN_ID"

BROKER_IMAGE=clawguard-ssh-e2e-broker:local
GATEWAY_IMAGE=clawguard-ssh-e2e-sidecar:local
UPSTREAM_IMAGE=clawguard-ssh-e2e-upstream:local

TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/clawguard-ssh-e2e.XXXXXX")
CONTAINERS=()
NETWORK_CREATED=0
VOLUME_CREATED=0

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e

  for container in "${CONTAINERS[@]-}"; do
    [ -n "$container" ] || continue
    if [ "$(docker inspect -f '{{ index .Config.Labels "com.clawguard.ssh-e2e.run" }}' \
      "$container" 2>/dev/null || true)" = "$RUN_ID" ]; then
      docker rm -f "$container" >/dev/null 2>&1 || true
    fi
  done
  if [ "$NETWORK_CREATED" -eq 1 ]; then
    if [ "$(docker network inspect -f '{{ index .Labels "com.clawguard.ssh-e2e.run" }}' \
      "$NETWORK_NAME" 2>/dev/null || true)" = "$RUN_ID" ]; then
      docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
    fi
  fi
  if [ "$VOLUME_CREATED" -eq 1 ]; then
    if [ "$(docker volume inspect -f '{{ index .Labels "com.clawguard.ssh-e2e.run" }}' \
      "$RUNTIME_VOLUME" 2>/dev/null || true)" = "$RUN_ID" ]; then
      docker volume rm "$RUNTIME_VOLUME" >/dev/null 2>&1 || true
    fi
  fi

  case "$TEMP_ROOT" in
    "${TMPDIR:-/tmp}"/clawguard-ssh-e2e.*)
      rm -rf -- "$TEMP_ROOT"
      ;;
    *)
      printf '[ssh-gateway-e2e] refusing unsafe temporary cleanup path: %s\n' "$TEMP_ROOT" >&2
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

build_image() {
  local label=$1
  shift
  local build_log="$TEMP_ROOT/build-$label.log"
  log "building $label image (Docker layer cache is reusable)"
  if ! docker build "$@" >"$build_log" 2>&1; then
    tail -n 120 "$build_log" >&2 || true
    fail "$label image build failed"
  fi
}

wait_for_log() {
  local container=$1
  local pattern=$2
  local deadline=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != true ]; then
      docker logs "$container" >&2 2>&1 || true
      fail "$container exited before becoming ready"
    fi
    if docker logs "$container" 2>&1 | grep -Fq "$pattern"; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container" >&2 2>&1 || true
  fail "timed out waiting for $container"
}

wait_for_file() {
  local file=$1
  local container=$2
  local deadline=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ -s "$file" ]; then
      return 0
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != true ]; then
      docker logs "$container" >&2 2>&1 || true
      fail "$container exited before creating $(basename "$file")"
    fi
    sleep 1
  done
  docker logs "$container" >&2 2>&1 || true
  fail "timed out waiting for $(basename "$file") from $container"
}

wait_for_event_count() {
  local pattern=$1
  local minimum=$2
  local deadline=$((SECONDS + 15))
  local count
  while [ "$SECONDS" -lt "$deadline" ]; do
    count=$(grep -F -c "$pattern" "$TEMP_ROOT/results/events.ndjson" 2>/dev/null || true)
    if [ "${count:-0}" -ge "$minimum" ]; then
      return 0
    fi
    sleep 1
  done
  fail "timed out waiting for broker audit event: $pattern"
}

assert_no_agent_lease_dirs() {
  local broker=$1
  docker exec "$broker" node -e '
    const fs = require("node:fs");
    const leases = fs.readdirSync("/run/clawguard-ssh").filter((name) => name.startsWith("a-"));
    if (leases.length) {
      console.error(`active lease directories remain: ${leases.join(",")}`);
      process.exit(1);
    }
  ' || fail "agent lease was not removed in $broker"
}

start_broker() {
  local container=$1
  local known_host_public_key=$2
  local lease_ttl_seconds=${3:-30}
  local max_concurrent_leases=${4:-4}
  rm -f -- "$TEMP_ROOT/results/broker.ready"
  CONTAINERS+=("$container")
  docker run -d \
    --name "$container" \
    --network "$NETWORK_NAME" \
    --label "$RESOURCE_LABEL" \
    --env "E2E_LEASE_TTL_SECONDS=$lease_ttl_seconds" \
    --env "E2E_MAX_CONCURRENT_LEASES=$max_concurrent_leases" \
    --mount "type=volume,src=$RUNTIME_VOLUME,dst=/run/clawguard-ssh" \
    --mount "type=bind,src=$TEMP_ROOT/upstream_identity,dst=/e2e-secrets/upstream_identity,readonly" \
    --mount "type=bind,src=$known_host_public_key,dst=/e2e-config/upstream_host.pub,readonly" \
    --mount "type=bind,src=$TEMP_ROOT/results,dst=/e2e-results" \
    --mount "type=bind,src=$FIXTURE_DIR/broker.js,dst=/e2e/broker.js,readonly" \
    "$BROKER_IMAGE" node /e2e/broker.js >/dev/null
  wait_for_file "$TEMP_ROOT/results/broker.ready" "$container"
}

cd "$REPO_ROOT"
node --check "$FIXTURE_DIR/broker.js" >/dev/null
sh -n "$FIXTURE_DIR/upstream-entrypoint.sh"
sh -n "$REPO_ROOT/ssh-gateway/entrypoint.sh"
sh -n "$REPO_ROOT/ssh-gateway/clawguard-force-command.sh"

build_image broker -t "$BROKER_IMAGE" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"
build_image sidecar -t "$GATEWAY_IMAGE" "$REPO_ROOT/ssh-gateway"
build_image upstream -t "$UPSTREAM_IMAGE" -f "$FIXTURE_DIR/Dockerfile.upstream" "$FIXTURE_DIR"

mkdir -p "$TEMP_ROOT/upstream-config" "$TEMP_ROOT/gateway-data" "$TEMP_ROOT/results"
chmod 0700 "$TEMP_ROOT" "$TEMP_ROOT/upstream-config" "$TEMP_ROOT/gateway-data" "$TEMP_ROOT/results"

log 'generating ephemeral and distinct inbound, upstream, and host keys'
ssh-keygen -q -t ed25519 -N '' -C 'clawguard-e2e-inbound' \
  -f "$TEMP_ROOT/inbound_identity"
ssh-keygen -q -t ed25519 -N '' -C 'clawguard-e2e-upstream-auth' \
  -f "$TEMP_ROOT/upstream_identity"
ssh-keygen -q -t ed25519 -N '' -C 'clawguard-e2e-upstream-host' \
  -f "$TEMP_ROOT/upstream-config/ssh_host_ed25519_key"
ssh-keygen -q -t ed25519 -N '' -C 'clawguard-e2e-mismatch-host' \
  -f "$TEMP_ROOT/mismatch_host_identity"
ssh-keygen -q -t ed25519 -N '' -C 'clawguard-e2e-gateway-host' \
  -f "$TEMP_ROOT/gateway-data/ssh_host_ed25519_key"

cp "$TEMP_ROOT/upstream_identity.pub" "$TEMP_ROOT/upstream-config/authorized_keys"
cp "$TEMP_ROOT/inbound_identity.pub" "$TEMP_ROOT/inbound_authorized_keys"
chmod 0600 \
  "$TEMP_ROOT/upstream-config/authorized_keys" \
  "$TEMP_ROOT/inbound_authorized_keys" \
  "$TEMP_ROOT/inbound_identity" \
  "$TEMP_ROOT/upstream_identity" \
  "$TEMP_ROOT/upstream-config/ssh_host_ed25519_key" \
  "$TEMP_ROOT/gateway-data/ssh_host_ed25519_key"

NETWORK_CREATED=1
docker network create --label "$RESOURCE_LABEL" "$NETWORK_NAME" >/dev/null
VOLUME_CREATED=1
docker volume create --label "$RESOURCE_LABEL" "$RUNTIME_VOLUME" >/dev/null

log 'starting stock upstream sshd'
CONTAINERS+=("$UPSTREAM_CONTAINER")
docker run -d \
  --name "$UPSTREAM_CONTAINER" \
  --network "$NETWORK_NAME" \
  --network-alias upstream \
  --label "$RESOURCE_LABEL" \
  --mount "type=bind,src=$TEMP_ROOT/upstream-config,dst=/e2e-config,readonly" \
  "$UPSTREAM_IMAGE" >/dev/null
wait_for_log "$UPSTREAM_CONTAINER" 'Server listening on 0.0.0.0 port 2222'

log 'starting real ClawGuard broker with fake approval=true and in-memory key injection'
start_broker "$BROKER_CONTAINER" "$TEMP_ROOT/upstream-config/ssh_host_ed25519_key.pub"

log 'starting stock OpenSSH gateway sidecar'
CONTAINERS+=("$GATEWAY_CONTAINER")
docker run -d \
  --name "$GATEWAY_CONTAINER" \
  --network "$NETWORK_NAME" \
  --label "$RESOURCE_LABEL" \
  --publish 127.0.0.1::2222 \
  --mount "type=volume,src=$RUNTIME_VOLUME,dst=/run/clawguard-ssh" \
  --mount "type=bind,src=$TEMP_ROOT/gateway-data,dst=/data" \
  --mount "type=bind,src=$TEMP_ROOT/inbound_authorized_keys,dst=/config/authorized_keys,readonly" \
  "$GATEWAY_IMAGE" >/dev/null
wait_for_log "$GATEWAY_CONTAINER" 'Server listening on 0.0.0.0 port 2222'

GATEWAY_PORT=$(docker port "$GATEWAY_CONTAINER" 2222/tcp | awk -F: 'NR == 1 { print $NF }')
case "$GATEWAY_PORT" in
  ''|*[!0-9]*) fail 'could not discover the published gateway port' ;;
esac

GATEWAY_PUBLIC_KEY=$(awk 'NR == 1 { print $1 " " $2 }' \
  "$TEMP_ROOT/gateway-data/ssh_host_ed25519_key.pub")
printf '[127.0.0.1]:%s %s\n' "$GATEWAY_PORT" "$GATEWAY_PUBLIC_KEY" \
  >"$TEMP_ROOT/gateway_known_hosts"
chmod 0600 "$TEMP_ROOT/gateway_known_hosts"

SSH_COMMON=(
  -F /dev/null
  -i "$TEMP_ROOT/inbound_identity"
  -o BatchMode=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=10
  -o GlobalKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o KbdInteractiveAuthentication=no
  -o LogLevel=ERROR
  -o PasswordAuthentication=no
  -o PreferredAuthentications=publickey
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$TEMP_ROOT/gateway_known_hosts"
  -p "$GATEWAY_PORT"
)

log 'executing a harmless command through both stock OpenSSH legs'
SUCCESS_OUTPUT=$(ssh "${SSH_COMMON[@]}" gateway@127.0.0.1 -- \
  production -- printf clawguard-e2e-ok 2>"$TEMP_ROOT/success.stderr") \
  || {
    docker logs "$BROKER_CONTAINER" >&2 2>&1 || true
    docker logs "$GATEWAY_CONTAINER" >&2 2>&1 || true
    docker logs "$UPSTREAM_CONTAINER" >&2 2>&1 || true
    sed -n '1,120p' "$TEMP_ROOT/success.stderr" >&2 || true
    fail 'gateway command failed'
  }
[ "$SUCCESS_OUTPUT" = 'clawguard-e2e-ok' ] \
  || fail "unexpected upstream command output: $SUCCESS_OUTPUT"
wait_for_event_count '"outcome":"completed"' 1
assert_no_agent_lease_dirs "$BROKER_CONTAINER"
log 'PASS: command output, broker completion, and immediate lease cleanup verified'

COMPLETED_BEFORE_SHELL=$(grep -F -c '"outcome":"completed"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null || true)
log 'opening the declared interactive shell/TTY flow and exiting cleanly'
set +e
printf 'printf clawguard-e2e-shell-ok\nexit\n' \
  | ssh "${SSH_COMMON[@]}" -tt gateway@127.0.0.1 -- production \
    >"$TEMP_ROOT/shell.stdout" 2>"$TEMP_ROOT/shell.stderr"
SHELL_STATUS=${PIPESTATUS[1]}
set -e
[ "$SHELL_STATUS" -eq 0 ] \
  || {
    sed -n '1,160p' "$TEMP_ROOT/shell.stderr" >&2 || true
    fail 'interactive shell/TTY flow failed'
  }
grep -Fq 'clawguard-e2e-shell-ok' "$TEMP_ROOT/shell.stdout" \
  || fail 'interactive upstream shell did not return its marker'
wait_for_event_count '"outcome":"completed"' "$((COMPLETED_BEFORE_SHELL + 1))"
grep -Fq '"action":"shell"' "$TEMP_ROOT/results/events.ndjson" \
  || fail 'broker audit did not record the shell action'
assert_no_agent_lease_dirs "$BROKER_CONTAINER"
log 'PASS: interactive shell/TTY flow completed and released its lease'

COMPLETED_BEFORE_ESCAPE=$(grep -F -c '"outcome":"completed"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null || true)
SIDECAR_ESCAPE_MARKER="/tmp/clawguard-e2e-escape-$RUN_TOKEN"
docker exec "$GATEWAY_CONTAINER" test ! -e "$SIDECAR_ESCAPE_MARKER" \
  || fail 'sidecar escape-test marker unexpectedly exists before the test'
log 'proving the inner OpenSSH client cannot execute a ~! local-shell escape in the sidecar'
set +e
printf '~!touch %s\ntrue\nexit\n' "$SIDECAR_ESCAPE_MARKER" \
  | ssh "${SSH_COMMON[@]}" -o EscapeChar=none -tt gateway@127.0.0.1 -- production \
    >"$TEMP_ROOT/escape.stdout" 2>"$TEMP_ROOT/escape.stderr"
ESCAPE_STATUS=${PIPESTATUS[1]}
set -e
[ "$ESCAPE_STATUS" -eq 0 ] \
  || {
    sed -n '1,160p' "$TEMP_ROOT/escape.stderr" >&2 || true
    fail 'interactive escape hardening probe did not exit cleanly'
  }
docker exec "$GATEWAY_CONTAINER" test ! -e "$SIDECAR_ESCAPE_MARKER" \
  || fail 'inner OpenSSH ~! escape created a local file in the sidecar'
wait_for_event_count '"outcome":"completed"' "$((COMPLETED_BEFORE_ESCAPE + 1))"
assert_no_agent_lease_dirs "$BROKER_CONTAINER"
log 'PASS: inner OpenSSH local-shell escape is disabled'

EVENTS_BEFORE_UNSUPPORTED=$(wc -l <"$TEMP_ROOT/results/events.ndjson" | tr -d ' ')
set +e
ssh "${SSH_COMMON[@]}" gateway@127.0.0.1 -- \
  production printf must-not-run >"$TEMP_ROOT/unsupported.stdout" \
  2>"$TEMP_ROOT/unsupported.stderr"
UNSUPPORTED_STATUS=$?
set -e
[ "$UNSUPPORTED_STATUS" -ne 0 ] || fail 'unsupported wrapper syntax unexpectedly succeeded'
grep -Fq 'expected -- before the remote command' "$TEMP_ROOT/unsupported.stderr" \
  || fail 'unsupported wrapper syntax did not fail at the expected parser guard'
sleep 1
EVENTS_AFTER_UNSUPPORTED=$(wc -l <"$TEMP_ROOT/results/events.ndjson" | tr -d ' ')
[ "$EVENTS_BEFORE_UNSUPPORTED" = "$EVENTS_AFTER_UNSUPPORTED" ] \
  || fail 'unsupported wrapper syntax reached the broker'
log 'PASS: unsupported command syntax fails before approval or key lease creation'

set +e
ssh "${SSH_COMMON[@]}" -o ExitOnForwardFailure=yes \
  -R 0:127.0.0.1:22 gateway@127.0.0.1 -- \
  production -- printf forwarding-must-not-run \
  >"$TEMP_ROOT/forwarding.stdout" 2>"$TEMP_ROOT/forwarding.stderr"
FORWARDING_STATUS=$?
set -e
[ "$FORWARDING_STATUS" -ne 0 ] || fail 'inbound remote forwarding unexpectedly succeeded'
if grep -Fq 'forwarding-must-not-run' "$TEMP_ROOT/forwarding.stdout"; then
  fail 'remote command ran despite the rejected forwarding request'
fi
log 'PASS: inbound sshd rejects remote forwarding'

COMPLETED_BEFORE_TTL=$(grep -F -c '"outcome":"completed"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null || true)
EXPIRED_FINALS_BEFORE_TTL=$(grep -F '"type":"final"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null \
  | grep -F -c '"outcome":"lease_expired"' || true)
log 'testing that agent TTL removes capability without falsifying the live SSH session lifecycle'
docker stop -t 10 "$BROKER_CONTAINER" >/dev/null
start_broker "$TTL_BROKER_CONTAINER" \
  "$TEMP_ROOT/upstream-config/ssh_host_ed25519_key.pub" 2 1

ssh "${SSH_COMMON[@]}" gateway@127.0.0.1 -- \
  production -- 'sleep 5; printf clawguard-e2e-after-ttl' \
  >"$TEMP_ROOT/ttl.stdout" 2>"$TEMP_ROOT/ttl.stderr" &
TTL_SSH_PID=$!
sleep 3
kill -0 "$TTL_SSH_PID" 2>/dev/null \
  || {
    wait "$TTL_SSH_PID" || true
    sed -n '1,160p' "$TEMP_ROOT/ttl.stderr" >&2 || true
    fail 'SSH command did not remain active beyond the agent lease TTL'
  }
assert_no_agent_lease_dirs "$TTL_BROKER_CONTAINER"

set +e
ssh "${SSH_COMMON[@]}" gateway@127.0.0.1 -- \
  production -- printf ttl-capacity-must-not-run \
  >"$TEMP_ROOT/ttl-capacity.stdout" 2>"$TEMP_ROOT/ttl-capacity.stderr"
TTL_CAPACITY_STATUS=$?
set -e
[ "$TTL_CAPACITY_STATUS" -ne 0 ] \
  || fail 'session capacity was released while the first SSH session was still alive'
if grep -Fq 'ttl-capacity-must-not-run' "$TEMP_ROOT/ttl-capacity.stdout"; then
  fail 'a second upstream command ran after live-session capacity was incorrectly released'
fi
grep -Fq 'SSH gateway is at session capacity' "$TEMP_ROOT/ttl-capacity.stderr" \
  || fail 'second session did not fail at the expected live-session capacity guard'

set +e
wait "$TTL_SSH_PID"
TTL_SSH_STATUS=$?
set -e
[ "$TTL_SSH_STATUS" -eq 0 ] \
  || {
    sed -n '1,160p' "$TEMP_ROOT/ttl.stderr" >&2 || true
    fail 'authenticated SSH command failed after agent lease expiry'
  }
[ "$(cat "$TEMP_ROOT/ttl.stdout")" = 'clawguard-e2e-after-ttl' ] \
  || fail 'authenticated SSH command did not finish after agent lease expiry'
wait_for_event_count '"outcome":"completed"' "$((COMPLETED_BEFORE_TTL + 1))"
EXPIRED_FINALS_AFTER_TTL=$(grep -F '"type":"final"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null \
  | grep -F -c '"outcome":"lease_expired"' || true)
[ "$EXPIRED_FINALS_AFTER_TTL" -eq "$EXPIRED_FINALS_BEFORE_TTL" ] \
  || fail 'broker prematurely finalized a live SSH session as lease_expired'
assert_no_agent_lease_dirs "$TTL_BROKER_CONTAINER"
log 'PASS: agent capability expired, live capacity stayed reserved, and final completion was audited'

NONZERO_FINALS_BEFORE=$(grep -F -c '"outcome":"remote_exit_nonzero"' \
  "$TEMP_ROOT/results/events.ndjson" 2>/dev/null || true)
log 'restarting only the broker with an intentionally wrong upstream host key'
docker stop -t 10 "$TTL_BROKER_CONTAINER" >/dev/null
start_broker "$MISMATCH_BROKER_CONTAINER" "$TEMP_ROOT/mismatch_host_identity.pub"

set +e
ssh "${SSH_COMMON[@]}" gateway@127.0.0.1 -- \
  production -- printf host-key-mismatch-must-not-run \
  >"$TEMP_ROOT/mismatch.stdout" 2>"$TEMP_ROOT/mismatch.stderr"
MISMATCH_STATUS=$?
set -e
[ "$MISMATCH_STATUS" -ne 0 ] || fail 'wrong pinned upstream host key unexpectedly succeeded'
if grep -Fq 'host-key-mismatch-must-not-run' "$TEMP_ROOT/mismatch.stdout"; then
  fail 'upstream command ran despite host-key mismatch'
fi
grep -Eiq 'host key verification failed|remote host identification has changed' \
  "$TEMP_ROOT/mismatch.stderr" \
  || {
    sed -n '1,120p' "$TEMP_ROOT/mismatch.stderr" >&2 || true
    fail 'host-key mismatch did not produce the expected OpenSSH failure'
  }
wait_for_event_count '"outcome":"remote_exit_nonzero"' "$((NONZERO_FINALS_BEFORE + 1))"
assert_no_agent_lease_dirs "$MISMATCH_BROKER_CONTAINER"
log 'PASS: pinned upstream host-key mismatch fails closed and releases the lease'

if grep -Fq 'BEGIN OPENSSH PRIVATE KEY' "$TEMP_ROOT/results/events.ndjson"; then
  fail 'private-key material leaked into broker audit events'
fi

log 'PASS: full self-contained OpenSSH gateway E2E smoke test completed'
