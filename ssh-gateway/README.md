# OpenSSH gateway sidecar (experimental)

This directory contains the Linux/OpenSSH sidecar for ClawGuard's experimental
SSH access gateway. It deliberately does not implement SSH in Node.js:

- inbound authentication and channel handling use stock `sshd`;
- a root-owned global `ForceCommand` wrapper requests ClawGuard approval;
- outbound transport and host verification use stock `ssh`;
- ClawGuard alone resolves the upstream key and exposes a short-lived
  per-session `ssh-agent` socket after approval.

## Trust and credential boundaries

The inbound client key and the upstream key are different credentials.

- `./data/ssh-gateway/authorized_keys` contains **public keys only** and grants
  access to the restricted `gateway` account in this sidecar.
- The upstream private key belongs in ClawGuard's secret configuration/backend,
  under the `ssh-agent-key` plugin. It is fed to `ssh-add` through stdin and is
  never mounted into this sidecar or returned to the client.
- `/run/clawguard-ssh` is a private named volume shared by only the ClawGuard
  and sidecar containers. It carries a Unix broker socket and ephemeral agent
  sockets, not a private-key file.
- `/data` is a separate named volume that persists the sidecar's inbound
  Ed25519 host key across recreation.

The `gateway` session account is fixed at UID/GID `10001`. The `sshd` master
starts as root, as normal for OpenSSH, then drops privileges for the session.
ClawGuard keeps ownership of the runtime directories and sockets and grants the
sidecar access only through group `10001`; the sidecar cannot list or replace
other lease paths. The numeric gateway UID remains fixed at `10001` as well.
The experimental ClawGuard container itself must run as root: it creates each
agent as UID/GID `10001`, then root loads the key (which OpenSSH explicitly
permits) and retains cleanup control over the non-listable parent directory.

Anyone with root or Docker control on the trusted host can use an active agent
socket. Keep Docker and the host outside the untrusted agent's control.

## Configure

### 1. Inbound public keys

Create the host-side public-key file:

```bash
mkdir -p ./data/ssh-gateway
cp ~/.ssh/id_ed25519.pub ./data/ssh-gateway/authorized_keys
chmod 600 ./data/ssh-gateway/authorized_keys
```

The file may contain more than one OpenSSH public-key line. It must not contain
an upstream private key. Compose mounts the containing directory read-only and
the entrypoint copies the file into the unprivileged account's home with strict
ownership and mode. If the file is absent or empty, the complete stack still
starts but the sidecar installs an empty key list and denies every inbound
login. Recreate `clawguard-ssh` after adding or changing the file.

### 2. Broker and service

Set `sshBroker.enabled: true` in `clawguard.yaml`; the remaining values below
match the image and Compose defaults:

```yaml
sshBroker:
  enabled: true
  runtimeDir: /run/clawguard-ssh
  socketPath: /run/clawguard-ssh/broker.sock
  gatewayUid: 10001
  gatewayGid: 10001
  approvalTimeoutMs: 90000
  credentialTimeoutMs: 30000
  leaseTtlSeconds: 120
  maxSessionSeconds: 3600
  sshAgentPath: /usr/bin/ssh-agent
  sshAddPath: /usr/bin/ssh-add
  maxConcurrentLeases: 10
```

Add a YAML-only SSH service. Resolve `privateKey` from a protected secret
backend; this example uses the existing Vault reference syntax:

```yaml
services:
  production-ssh:
    protocol: ssh
    upstream: ssh://ssh.example.com:22
    auth:
      type: plugin
      pluginPath: ssh-agent-key
      pluginConfig:
        username: deploy
        privateKey: "vault:secret/data/ssh/production#privateKey"
    policy:
      default: require_approval
    ssh:
      # Syntactically complete example only: replace it with the verified key.
      knownHostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
      allowPrivateTarget: false

security:
  allowedUpstreams:
    - ssh.example.com
```

`upstream` must be exactly `ssh://host:port`: no username, path, query or
fragment. The upstream username comes only from the credential plugin. A
private, loopback or link-local target requires `allowPrivateTarget: true`;
leave it `false` for public targets.

Service aliases are intentionally restricted to 1-64 letters, digits,
hyphens or underscores because the same alias crosses YAML, broker JSON and
the forced-command parser.

`knownHostKey` must be the upstream server's complete, single-line OpenSSH host
public key (`key-type base64`), not just its fingerprint. Obtain the key from
the server administrator or configuration management and verify its fingerprint
through an independent trusted channel. ClawGuard does not use
trust-on-first-use, and a mismatch terminates the connection.

Telegram must be configured and paired. Unlike development HTTP behavior, SSH
never auto-approves when Telegram is absent: no approver, bot error, denial or
timeout all fail closed, and cached HTTP approvals are not reused.

If you customize `sshBroker.socketPath`, set the sidecar environment variable
`CLAWGUARD_SSH_BROKER_SOCKET` to the same path and mount its parent at the same
location in both containers. Keep
`CLAWGUARD_SSH_BROKER_TIMEOUT_SECONDS` greater than the configured approval
and credential-retrieval timeouts plus setup margin; the Compose default is
135 seconds versus 90 + 30 seconds in the broker defaults.

## Start and enroll the client

The SSH and FTP sidecars are part of the normal Compose lifecycle, so plain
`up` and `down` always manage the complete stack. Start it with:

```bash
docker compose up -d --build
docker compose logs clawguard-ssh
```

The published gateway ports bind to loopback by default. To accept clients on
a LAN interface without editing the versioned Compose file, set
`CLAWGUARD_GATEWAY_BIND_IP` to that interface's IP in the ignored `.env`.

The sidecar generates an Ed25519 **inbound gateway** host key on first start and
prints its SHA-256 fingerprint. The key persists in the
`clawguard-ssh-host-keys` volume. Verify this fingerprint before accepting the
gateway host key on a client.

Do not remove the host-key volume casually: doing so changes the gateway's
identity and should trigger a client warning. An intentional rotation requires
independent verification and an explicit client `known_hosts` update.

## Client usage

The first forced-command argument is always the configured ClawGuard service
alias.

Interactive shell (TTY required):

```bash
ssh -t gateway@CLAWGUARD_HOST -p 2222 -- production-ssh
```

Single command (the second `--` separates the service from the upstream
command):

```bash
ssh gateway@CLAWGUARD_HOST -p 2222 -- production-ssh -- uname -a
```

After inbound public-key authentication, the wrapper submits only the service
alias, inbound client IP and action type (`shell` or `exec`) to the broker. The
client cannot choose an upstream host, port, username, known-hosts line or agent
socket. On approval, the broker returns the fixed target metadata and one
ephemeral agent-socket path. After validating that response and the socket, the
wrapper acknowledges activation before starting stock `ssh`. An unacknowledged
handoff expires promptly and releases both the agent and its capacity slot, so
a lost wrapper response cannot strand a session until its maximum duration.
Wrapper exit reports only the exit status and requests lease cleanup; the TTL
and ClawGuard shutdown cleanup are additional backstops.

`leaseTtlSeconds` limits how long the private key can sign authentication
requests; expiring it does not terminate a connection that OpenSSH has already
authenticated. `maxSessionSeconds` is the absolute session limit enforced by
the wrapper. The broker keeps the capacity slot until completion and applies a
short cleanup grace, so a lost completion callback cannot saturate the gateway
forever. For backward-compatible naming, `maxConcurrentLeases` currently caps
pending approvals and live SSH sessions as well as active agent leases.

## Hardening and unsupported features

The bundled `sshd_config` enforces public-key-only authentication, the global
forced command, one session channel, bounded timeouts, and disables root login,
user environment/rc files, agent forwarding, TCP/Unix-socket forwarding, X11,
tunnels and gateway ports. The outbound client also disables all local escape
characters and is wrapped in the broker-provided absolute session timeout.

This MVP supports only an interactive shell and one exec command. It does not
support:

- SCP or SFTP;
- `ProxyJump` or using this endpoint as a generic `ProxyCommand` transport;
- local, remote, dynamic or Unix-socket forwarding;
- inbound agent forwarding, X11 or multiple channels.

The sidecar necessarily sees plaintext terminal traffic while relaying it, but
ClawGuard's SSH audit stores metadata only and does not store terminal streams
or full remote commands.

### Residual lease risk

The upstream private key never reaches the client, but the agent socket is a
short-lived signing capability. A sidecar compromised during an approved lease
could use that socket against another reachable server that accepts the same
key. Use narrowly scoped upstream accounts/keys, keep `leaseTtlSeconds` short,
restrict sidecar egress to configured targets, and isolate the Docker host.
Destination constraints (`ssh-add -h`) are a production-hardening backlog item
for this experimental feature.

## Troubleshooting

- **Warning that `authorized_keys` is missing or empty** — this is a safe
  fail-closed state. Add public keys at
  `./data/ssh-gateway/authorized_keys`, then run
  `docker compose up -d --force-recreate clawguard-ssh`.
- **`Permission denied (publickey)`** — the inbound client public key is not in
  that file, or the client selected a different private key. This happens
  before ClawGuard approval.
- **`broker unavailable`** — confirm `sshBroker.enabled: true`, both containers
  are running, and both mount `clawguard-ssh-runtime` at
  `/run/clawguard-ssh`.
- **Approval denied or timed out** — inspect Telegram pairing/bot health and
  make a new attempt only after resolving it; the denied session receives no
  lease.
- **Host-key verification failed** — do not bypass the check. Confirm whether
  the upstream host key was intentionally rotated, verify it independently,
  then update `knownHostKey`.
- **SCP/SFTP/forwarding fails** — those paths are intentionally unsupported in
  this experimental gateway.
