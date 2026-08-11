# Experimental FTP/FTPS access gateway

ClawGuard does not implement FTP. The opt-in Linux sidecar runs a deliberately
minimal build of rclone's FTP client/server for each approved lease; ClawGuard
retains responsibility for target policy, Telegram approval, credential
retrieval, lifecycle, and audit.

```text
FTP client -> per-lease rclone server -> pinned SOCKS relay
           -> per-lease rclone FTP backend -> configured upstream FTP server
                         ^
                         |
              ClawGuard approval + credentials
```

The client receives a random, ephemeral gateway username/password. It never
receives the configured upstream username/password. One isolated rclone process
and one control/passive port slice exist for the bounded lease, then ClawGuard
and the sidecar terminate them.

## Supported modes

- `protocol: ftp`: plain FTP inbound and plain FTP upstream.
- `protocol: ftps`: explicit FTPS (`AUTH TLS`) inbound. The configured upstream
  may use explicit or implicit FTPS through `ftp.tlsMode`.
- Every Telegram approval selects either **Read only** or **Read/write** for
  that lease. Read-only blocks uploads, deletes, renames and directory changes
  in the per-lease rclone server.
- Passive data connections are supported and must originate from the same IP
  as the authenticated control connection. Active FTP commands are rejected.
- SFTP is not FTP and is not handled here; the SSH experiment intentionally
  disables SFTP.

## Configuration

```yaml
services:
  production-files:
    protocol: ftps
    upstream: ftps://ftp.example.com:21
    auth:
      type: plugin
      pluginPath: ftp-password
      pluginConfig:
        username: deploy
        password: "vault:secret/data/ftp/production#password"
    policy:
      default: require_approval
    ftp:
      allowPrivateTarget: false
      tlsMode: explicit
      root: uploads
      noCheckCertificate: false

security:
  allowedUpstreams:
    - ftp.example.com

admin:
  enabled: true
  https:
    enabled: true
    port: 9443
    hostnames:
      - clawguard.example.com

ftpGateway:
  enabled: true
  socketPath: /run/clawguard-ftp/gateway.sock
  publicHost: clawguard.example.com
  allowInsecureHttpApi: false
  approvalTimeoutMs: 90000
  credentialTimeoutMs: 30000
  gatewayTimeoutMs: 10000
  sessionTtlSeconds: 3600
  maxConcurrentSessions: 1
  controlPortStart: 21210
  controlPortEnd: 21210
  passivePortStart: 30000
  passivePortsPerSession: 10
```

The target must be an exact `ftp://host:port` or `ftps://host:port` URL without
credentials, path, query, or fragment. `root` is a normalized relative path.
For implicit upstream FTPS, normally use port 990 and `tlsMode: implicit`.
Private/LAN targets require the explicit `allowPrivateTarget: true` opt-in.

The built-in `ftp-password` credential plugin accepts only `username` and
`password`. A custom FTP credential plugin may return only those same fields;
it cannot override the host, port, root, or TLS mode. Secret references inside
`pluginConfig` are resolved by ClawGuard before plugin initialization.

## Start the sidecar

The Compose defaults bind SSH and FTP/FTPS to host loopback, advertise
`127.0.0.1` for passive FTP, and expose one lease with ten passive ports. This
is suitable when the client runs on the same host:

```bash
docker compose up -d --build
```

For a remote client, deliberately replace the `127.0.0.1` host bindings, set
`CLAWGUARD_FTP_PUBLIC_IP` to the address advertised for passive connections,
and set `CLAWGUARD_FTP_TLS_HOSTNAME` to the inbound certificate name. Published
control and passive ranges must map one-to-one to the same container ports.
Expanding concurrency requires matching changes to the Compose port mappings,
sidecar environment, and `ftpGateway` values.

For the common case where bind, passive and certificate addresses are the same
LAN IP, set only this value in the ignored `.env`:

```dotenv
CLAWGUARD_GATEWAY_BIND_IP=192.168.1.50
```

Compose derives the SSH/FTP bindings, passive FTP address and FTPS certificate
identity from it. Set the ignored `clawguard.yaml` value to
`ftpGateway.publicHost: "${CLAWGUARD_GATEWAY_BIND_IP}"`; Compose passes that
variable through to ClawGuard. `CLAWGUARD_FTP_PUBLIC_IP` and
`CLAWGUARD_FTP_TLS_HOSTNAME` can still override the derived values separately.

The sidecar creates a persistent self-signed inbound FTPS certificate in its
TLS volume and regenerates it when `CLAWGUARD_FTP_TLS_HOSTNAME` changes. For a
production deployment, replace or trust that certificate through your normal
PKI process.

## Mint and use a lease

Every lease requires a fresh Telegram decision; HTTP policy auto-approval and
cached approval windows are deliberately ignored. Prefer the optional HTTPS
listener because the response contains the ephemeral gateway password:

Agents that have installed the standalone forwarder directory should prefer
`forwarder/clawguard-ftp.js` for directory listings. It reads the already
provisioned agent key internally, passes the ephemeral FTP password to curl on
standard input instead of its process arguments, and revokes the lease after
the operation:

```bash
CLAWGUARD_USER="alice via OpenClaw" \
CLAWGUARD_REASON="List release directory" \
  ~/clawguard-forwarder/clawguard-ftp.js \
  list production-files /releases --insecure
```

Configure `ftpApi` in `forwarder.json` when it cannot be derived from the
configured ClawGuard host. The lower-level flow follows for clients that need
to consume a lease directly.

```bash
curl -sk -X POST "https://CLAWGUARD_HOST:9443/__ftp/session" \
  -H "X-ClawGuard-Key: YOUR_AGENT_KEY" \
  -H "Content-Type: application/json" \
  -H "X-ClawGuard-User: test-agent" \
  -H "X-ClawGuard-Reason: upload release artifact" \
  --data '{"service":"production-files"}'
```

The response has this shape and is sent with `Cache-Control: no-store`:

```json
{
  "id": "lease-id",
  "protocol": "ftps",
  "host": "clawguard.example.com",
  "port": 21210,
  "username": "cg-ephemeral",
  "password": "ephemeral-password",
  "tlsMode": "explicit",
  "accessMode": "read_only",
  "expiresAt": "2026-08-11T12:00:00.000Z"
}
```

`accessMode` is the operator's Telegram decision. A client receiving
`read_only` must not attempt a mutation. If write access becomes necessary,
revoke the lease and request a new one so the operator can make a fresh,
explicit read/write decision.

Use explicit FTPS with an FTP URL plus TLS requirement:

```bash
curl --ssl-reqd --cacert ./clawguard-ftp.crt \
  --user 'LEASE_USERNAME:LEASE_PASSWORD' \
  --upload-file ./artifact.zip \
  'ftp://clawguard.example.com:21210/artifact.zip'
```

For an isolated test with the generated self-signed certificate, replace
`--cacert` with `-k`. Plain FTP uses the same command without `--ssl-reqd`, but
it exposes the ephemeral login and file contents to the network and should not
be used across untrusted links.

Revoke early with:

```bash
curl -sk -X DELETE "https://CLAWGUARD_HOST:9443/__ftp/session/LEASE_ID" \
  -H "X-ClawGuard-Key: YOUR_AGENT_KEY"
```

The API exists on port 9090 only when `allowInsecureHttpApi: true`; use that
opt-in only on localhost or behind a separately protected transport. With the
safe default, enabling FTP also requires `admin.https.enabled: true`. FTP lease
audit metadata is available from `GET /__audit/ftp` on the main listener. The
audit response deliberately omits lease IDs: only the client that received the
credential-bearing lease response gets the capability needed to revoke it.

## Security boundaries

- FTP targets are allowlisted, resolved at lease creation, and every outbound
  control/data connection is pinned to that validated IP set. A plugin or FTP
  server cannot redirect the sidecar to a different host.
- The private Unix control socket is shared only by ClawGuard and the sidecar.
- Pending approvals and active leases share one capacity bound. Approval,
  credential retrieval, sidecar startup, and total lease lifetime all have
  explicit deadlines.
- Credential and SOCKS debug logging is disabled because rclone debug output
  can include configuration material.
- The FTP command parser has a bounded line size and the sidecar caps concurrent
  unauthenticated control connections. Oversized commands are rejected and do
  not create unbounded goroutines or buffers.
- Active-mode commands (`PORT`, `EPRT`, and `LPRT`) are absent from the command
  registry, preventing an approved client from making the trusted sidecar dial
  an arbitrary destination.
- A passive listener discards connections whose normalized source IP differs
  from the authenticated control connection, preventing a second network peer
  from racing the legitimate data connection.
- `ftp.noCheckCertificate: true` affects only upstream FTPS and is an explicit
  insecure opt-in. It does not change inbound certificate validation.
- Passive FTP necessarily opens a port range. Restrict ingress to the clients
  that need it and restrict sidecar egress to configured FTP servers where the
  deployment platform permits it.

The image pins rclone v1.74.2 and `goftp.io/server/v2` v2.0.2 from Go module
source. It builds only the FTP/local backends, FTP server, and
password-obscuring command. Auditable local patches select RFC 4217 explicit
FTPS, reject authentication before `AUTH TLS`, remove active-mode commands,
bind passive peers to the control peer, and bound parser/concurrency resources;
the image build runs the dependency-level regression tests before compiling
rclone. ClawGuard itself still contains no FTP parser.

## Verification

The unit suite covers configuration, target validation, plugin isolation,
approval, timeout/memory cleanup, API authentication, lifecycle, and HTTP
protocol isolation. Docker is required for the real data-path test:

```bash
npm run test:ftp-e2e
```

That test uploads and downloads through both plain FTP and explicit FTPS,
including passive data channels, verifies active mode is rejected, exercises a
read-only lease (download succeeds while upload fails), verifies the FTPS
listener rejects credentials before `AUTH TLS`, and verifies the upstream
password is absent from the lease response. The image build separately runs
the exact patched dependency tests for passive-peer binding, connection and
line limits, and the safe command registry.
