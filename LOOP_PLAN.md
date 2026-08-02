# Experimental OpenSSH Gateway Loop Plan

## Goal

Build and verify, on `experimental-ssh-gateway`, an opt-in SSH access gateway where:

- OpenSSH implements the inbound and outbound SSH protocol; ClawGuard does not emulate `sshd`;
- the client never receives or stores an upstream SSH private key;
- ClawGuard resolves upstream credentials through a protocol-specific plugin and grants them to a short-lived, per-session `ssh-agent` lease without writing them to disk;
- every outbound SSH session is fail-closed behind one explicit Telegram approval and produces a metadata-only audit trail;
- existing HTTP services, plugins and approval behavior remain backward compatible.

## Loop-state mapping

- This file is the durable plan required by the custom loop.
- `LOOP_TODO.md` is the live execution checklist.
- The repository's existing `CHANGELOG.MD` is reused as the append-only iteration log; a duplicate `CHANGELOG.md` is intentionally not created.
- `.custom-loop.lock` marks an active iteration and is intentionally gitignored.

## Architecture

```text
OpenSSH client
  -> hardened sshd sidecar (public-key authentication)
  -> ForceCommand wrapper (fixed gateway account)
  -> ClawGuard SSH broker (one-time Telegram approval)
  -> per-session ssh-agent socket managed by ClawGuard
  -> stock OpenSSH client
  -> fixed, host-key-pinned upstream sshd
```

### OpenSSH sidecar

- A dedicated Linux container runs stock `sshd` and `ssh`.
- One fixed, unprivileged gateway account authenticates with an inbound key that grants access only to the gateway, never to an upstream target.
- The requested ClawGuard service is the first token of `SSH_ORIGINAL_COMMAND`; a small root-owned `ForceCommand` wrapper validates the alias and calls the broker. Initial UX:
  - interactive: `ssh -t gateway@clawguard -- production`;
  - command: `ssh gateway@clawguard -- production -- uname -a`.
- The broker, not the client or wrapper configuration, supplies the fixed host, port, upstream username and pinned known-host key.
- `sshd` is hardened with public-key-only authentication, `DisableForwarding yes`, `MaxSessions 1`, no root login, no user rc/environment, no X11/agent/TCP/Unix forwarding, bounded authentication/session timeouts and a forced command.
- SFTP/SCP subsystem compatibility, ProxyJump, port forwarding and multiple channels are outside the MVP.

### Approval hook decision

- PAM `account` + `pam_exec` is a valid OpenSSH authorization hook, but an external PAM helper cannot safely export the resulting session/lease id into the later forced-command process. Correlating by PID, TTY, username or client IP would introduce races and weak one-time semantics.
- The MVP therefore performs approval in the root-owned `ForceCommand` wrapper. It runs only after OpenSSH public-key authentication, owns the complete approval/lease/upstream/cleanup lifecycle and cannot be bypassed because forwarding and alternative session paths are disabled.
- PAM integration remains a later option if a native module or explicit, cryptographically bound handoff token is introduced.

### ClawGuard broker

- Add a disabled-by-default HTTP-over-Unix-socket broker beneath the same shared runtime volume used for agent sockets. Filesystem ownership/mode is the authentication boundary; no TCP listener or bearer token is added.
- Only statically configured `protocol: ssh` services are accepted. SSH services are YAML-only in the MVP and cannot be added, edited, deleted or shadowed through admin SQLite overrides.
- A session request contains only service alias, inbound client address and requested action (`shell` or `exec`). Client-supplied target/user/port/socket paths are never accepted.
- Approval is requested after inbound OpenSSH authentication, when the forced wrapper starts, and is strictly one-time:
  - no Telegram or unpaired/unhealthy Telegram means deny;
  - no HTTP development auto-approval fallback;
  - no lookup, persistence or reuse of normal method/path approval TTLs;
  - the Telegram UI offers only `Approve this session` and `Deny`.
- On approval the broker creates the agent lease and returns only lease id, socket path, fixed target metadata, an absolute session limit and a public `known_hosts` line.
- Credential-plugin retrieval has its own deadline and receives an `AbortSignal`; shutdown cannot be held open by a plugin that ignores cancellation, and any late Buffer result is scrubbed.
- Release is explicit on wrapper exit and enforced again by key-lease TTL, absolute session watchdog and process shutdown cleanup. Key expiry removes signing capability without falsifying the lifecycle of an already authenticated OpenSSH channel.

### Credential plugin and agent lease

- Keep the HTTP `IAuthPlugin` unchanged. Add a separate SSH credential-plugin contract that can return only an upstream username and private key; it cannot override target, port or host verification and should honor broker cancellation.
- The built-in plugin obtains key material from recursively resolved `pluginConfig` values, so existing Vault/static secret providers remain the source of truth.
- ClawGuard starts a fresh standard `ssh-agent` per approved session, loads the key through `ssh-add -` stdin, and exposes only its Unix socket through a shared runtime volume.
- The key is never returned by an HTTP response, written to a file, logged, included in audit data or exposed through the admin API.
- MVP supports unencrypted in-memory OpenSSH private keys resolved from a protected secret backend. Encrypted-key/passphrase automation is deferred.
- Lease directories are random, bounded beneath a non-listable broker-owned runtime root, permission-restricted for the fixed sidecar UID/GID, killed on release/TTL/shutdown and scrubbed after use. The experimental broker must run as root so the sidecar UID never owns that parent boundary.

### Target and host verification

- SSH services use a fixed `ssh://host:port` upstream and require a complete OpenSSH public host-key value, not TOFU.
- ClawGuard constructs an exact service-scoped `HostKeyAlias key-type base64` known-hosts line; the wrapper connects to the already validated IP with `StrictHostKeyChecking=yes` and isolated global/user known-host files.
- The service alias, target hostname, port, username and host key are validated at startup.
- Private targets require an SSH-specific explicit opt-in without weakening HTTP SSRF settings.
- The sidecar must eventually be egress-restricted to configured targets; for the experimental MVP the short-lived per-session agent limits credential exposure, but a compromised sidecar during an approved lease remains a documented residual risk.

### Audit and redaction

- Add a dedicated `ssh_sessions` table containing session id, timestamps/duration, service, client IP, upstream host/port/user, action, approval result, lease expiry, outcome and exit status.
- Do not store private/public client keys, private keys, passphrases, terminal streams or full remote commands.
- The wrapper may report only action type and final exit status; ClawGuard does not trust it to authorize or choose a target.

## Delivery milestones

1. Persist the OpenSSH pivot and remove uncommitted `ssh2` transport work.
2. Add protocol-aware config/security validation and the isolated SSH credential-plugin loader with tests.
3. Add one-time fail-closed approval, SSH audit storage and the agent-lease manager with real-tool and negative tests.
4. Add the authenticated broker API and hardened OpenSSH sidecar/wrapper.
5. Add container and end-to-end tests for approval, denial, lease cleanup and host-key mismatch.
6. Document configuration/client usage, run full regression/security gap analysis and commit each coherent iteration.

## Acceptance criteria

- Existing HTTP YAML and all existing tests continue to work unchanged.
- SSH and the broker are disabled by default and fail startup on incomplete or unsafe configuration.
- The sidecar uses stock OpenSSH for both SSH legs; the Node application contains no SSH server or PTY/channel bridge.
- An OpenSSH client can open an interactive shell and execute a command through a configured service after explicit approval.
- The upstream private key is resolved only inside ClawGuard, passed to `ssh-add` through stdin, retained only in a short-lived agent process and never reaches the inbound client or filesystem.
- Missing/invalid inbound authentication, unknown service, no approver, denial, malformed broker request, failed credential setup, host-key mismatch and the absolute session limit all fail closed.
- Forwarding, extra sessions, arbitrary target selection and unsupported subsystems are rejected.
- Every session attempt has a metadata-only audit record and every agent process/socket is reclaimed.
- README, example YAML and sidecar documentation clearly state the experimental limits and residual risks.

## Stop condition

The loop is complete only when the MVP acceptance criteria pass, documentation is current, the todo has no MVP-critical item, the working tree is clean and a final independent security gap analysis finds no unresolved critical/high issue. Real deployment, firewall changes and modification of upstream SSH servers remain out of scope unless separately authorized.
