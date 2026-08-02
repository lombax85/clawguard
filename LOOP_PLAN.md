# Experimental SSH Gateway Loop Plan

## Goal

Build and verify, on `experimental-ssh-gateway`, an opt-in SSH access gateway where:

- the client never receives or stores an upstream SSH private key;
- ClawGuard terminates inbound SSH and creates a separate authenticated upstream SSH connection;
- upstream credentials are supplied by an SSH auth plugin and may be resolved through the existing secret-provider layer;
- every SSH connection is fail-closed behind an explicit approval and produces a metadata-only audit trail;
- existing HTTP services and HTTP auth plugins remain backward compatible.

## Loop-state mapping

- This file is the durable plan required by the custom loop.
- `LOOP_TODO.md` is the live execution checklist.
- The repository's existing `CHANGELOG.MD` is reused as the append-only iteration log; a duplicate `CHANGELOG.md` is intentionally not created.
- `.custom-loop.lock` marks an active iteration and is intentionally gitignored.

## Architectural direction

### Protocol and configuration

- Add `service.protocol` with `http` as the backward-compatible default and `ssh` as the opt-in value.
- Add a disabled-by-default `sshGateway` listener with conservative bind, timeout, connection-cap, host-key and authorized-client-key settings.
- Represent SSH targets as fixed `ssh://host:port` upstream URLs. The inbound SSH username selects the ClawGuard service; it never overrides the configured upstream username.
- Continue using `auth.type: plugin` and `auth.pluginPath`, but load protocol-specific plugins through a separate `ISshAuthPlugin` contract and registry. Do not widen `IAuthPlugin` with SSH-only optional methods.
- Keep SSH services YAML-only in the MVP, even when `admin.strictMode` is disabled. Admin overrides are applied after normal secret resolution and dynamic plugin reload is not implemented, so accepting SSH edits there could persist resolved key material or create a service whose plugin is not loaded.

### Credential boundary

- The built-in `ssh-private-key` plugin owns the resolved upstream username, private key and optional passphrase in ClawGuard process memory.
- No upstream private key, passphrase or derived secret is returned to the inbound client, logged, persisted by the plugin, or exposed through the admin API.
- The gateway's own inbound host key is generated once under `data/ssh/` with mode `0600` when no configured key exists.
- Inbound clients authenticate with an allowlisted public key loaded from a configured authorized-keys file. This client key grants access only to ClawGuard and is not accepted by upstream hosts; compromise still remains subject to human approval. Its fingerprint, never the key material, identifies the caller in audit.

### Approval and session scope

- SSH must fail closed if no interactive approver is configured/paired; it must not inherit HTTP's development-time auto-approval fallback.
- Authenticate the inbound client before emitting an approval request.
- Request approval only when the authenticated client asks for its single allowed `shell` or `exec` channel, for a concrete tuple: service, fixed upstream user, fixed host/port, action and session identifier.
- The MVP approval is single-session and is not restored or reused from the normal method-wide approval cache.

### SSH capabilities

MVP supports:

- one inbound connection selecting one configured SSH service;
- at most one session/channel per inbound connection;
- interactive shell with PTY and window-resize propagation;
- non-interactive `exec`, with stdout, stderr, exit code and signal propagation;
- idle, connection and maximum-session timeouts;
- graceful shutdown of inbound and upstream connections.

MVP explicitly rejects:

- SFTP and arbitrary subsystems;
- direct, reverse and Unix-socket forwarding;
- SSH agent and X11 forwarding;
- arbitrary environment-variable injection;
- client-selected upstream usernames, hosts or ports;
- password, keyboard-interactive, hostbased and `none` inbound authentication.

### Host verification and network policy

- An upstream SHA-256 host-key fingerprint is mandatory. A missing verifier or mismatch is fatal; TOFU and auto-accept are forbidden.
- `ssh:` is accepted only for services declared with `protocol: ssh`; HTTP runtime URL validation remains limited to HTTP(S).
- Private SSH targets require an explicit SSH-specific opt-in and still use fixed configured targets. This must not weaken HTTP SSRF policy.
- The SSH plugin may provide credentials only; it may not override host, port or target URL.
- DNS validation covers IPv4 and IPv6 and fails closed on resolution errors; the current IPv4-only, fail-open runtime helper is not reused for SSH.

### Audit and redaction

- Add a dedicated SSH-session audit record containing session id, timestamps/duration, service, client IP, upstream host/port/user, approval result, channel type and terminal outcome.
- Do not record private keys, passphrases, raw terminal streams, command stdin/stdout/stderr or arbitrary environment values.
- Do not log full `exec` commands by default because command arguments may contain secrets.

## Delivery milestones

1. Persist loop state and security decisions on the experimental branch.
2. Add protocol-aware types, configuration validation, SSH security helpers and the separate SSH plugin loader with unit tests.
3. Add fail-closed one-time approval support and dedicated SSH audit storage/tests.
4. Implement the SSH listener, inbound authentication, upstream connection and restricted shell/exec bridging.
5. Add integration tests using in-process SSH servers, including denial and host-key mismatch paths.
6. Document configuration, client use, experimental limitations and safe rollout; run full regression and final gap analysis.

## Acceptance criteria

- Existing HTTP configuration loads unchanged and all existing tests pass.
- SSH is disabled by default and cannot start with incomplete or unsafe configuration.
- A supported OpenSSH client can run an interactive shell and `ssh service@gateway command` through ClawGuard.
- The upstream private key exists only in resolved ClawGuard/plugin memory and is never sent to the inbound client or written by the SSH plugin.
- Invalid inbound identity, unknown service, absent/denied approval, unpinned or mismatched host key, and disallowed SSH channel types all fail closed.
- Every attempted SSH session produces a useful metadata-only audit record.
- Unit/integration tests cover the success path and the security-negative paths.
- README and example YAML make the experimental boundary and operational setup unambiguous.

## Stop condition

The loop is complete only when the acceptance criteria pass, the backlog contains no MVP-critical item, documentation is updated, the working tree is clean, and the final independent gap analysis finds no missing security-critical behavior. External deployment and changes to real SSH servers are out of scope unless separately authorized.
