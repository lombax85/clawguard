# Experimental OpenSSH Gateway Todo

## Done

- [x] Create `experimental-ssh-gateway` from current `main`.
- [x] Establish the shared goal and durable custom-loop state.
- [x] Confirm that a conventional ProxyJump cannot inject an upstream key held by ClawGuard.
- [x] Reject the custom SSH-server direction before committing feature code.
- [x] Select `OpenSSH sidecar + ForceCommand + ClawGuard approval/agent lease`.
- [x] Remove the uncommitted `ssh2` dependency and transport-plugin prototype.
- [x] Choose a Unix-socket broker and direct ForceCommand approval lifecycle; defer PAM until it can hand off a cryptographically bound session id.

## Current iteration

- [x] Reconcile the pivot with independent sidecar, credential-lease and approval reviews.
- [x] Commit the updated loop architecture (`3a1d3f9`).
- [x] Add protocol-aware config/types and SSH-only validation tests.
- [x] Add the isolated SSH credential-plugin interface/loader and built-in agent-key plugin.
- [x] Keep SSH services YAML-only and prevent admin serialization/override of resolved key data.

## Next

- [x] Add one-time fail-closed SSH approval UI/API without cached HTTP fallback.
- [x] Add dedicated SSH session audit schema/query helpers.
- [x] Implement and test the per-session `ssh-agent` lease manager.
- [x] Implement the authenticated internal SSH broker router.
- [x] Build the hardened OpenSSH sidecar, entrypoint and ForceCommand wrapper.
- [x] Add unit, container and end-to-end tests.
- [x] Document experimental configuration and client workflow.
- [x] Run full regression, dependency audit and final security gap analysis.
- [x] Bound and abort credential-plugin retrieval; preserve approval state during shutdown races.

## Backlog

- [ ] Per-client identities and service allowlists.
- [ ] Short-lived SSH certificate plugin for targets that trust a ClawGuard CA.
- [ ] Network-policy generation restricting sidecar egress per target.
- [ ] Destination-constrained agent keys (`ssh-add -h`) after verifying target OpenSSH compatibility.
- [ ] SFTP/SCP support as explicit, separately approved capabilities.
- [ ] Service aliases as dedicated dynamic Unix users for `ssh service@gateway` UX.
- [ ] Admin dashboard visualization for SSH sessions.
- [ ] Record Telegram approver identity and inbound-key fingerprint in SSH audit metadata.
- [ ] Either parameterize the packaged sidecar UID/GID or enforce its fixed `10001` identity in configuration.
- [ ] Metrics and concurrency quotas.

## Risks/blockers

- The sidecar can use an approved agent socket for any host accepting the same key until the short TTL expires; service-specific keys, short leases and egress policy reduce but do not eliminate this experimental residual risk.
- Shared Unix-socket ownership must be consistent across container UID/GID mappings.
- The experimental broker intentionally requires root so the gateway UID cannot enumerate or replace the broker-owned runtime parent.
- The broker wrapper must never evaluate `SSH_ORIGINAL_COMMAND` locally or accept client-supplied SSH options/targets.
- CI/container environments must provide `ssh-agent`, `ssh-add`, `ssh`, `sshd`, `curl` and `jq` for their respective tests.
- Approval waits must stay within OpenSSH connection/session timeouts.
