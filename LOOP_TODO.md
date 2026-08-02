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

- [ ] Reconcile the pivot with independent sidecar, credential-lease and approval reviews.
- [ ] Commit the updated loop architecture.
- [ ] Add protocol-aware config/types and SSH-only validation tests.
- [ ] Add the isolated SSH credential-plugin interface/loader and built-in agent-key plugin.
- [ ] Keep SSH services YAML-only and prevent admin serialization/override of resolved key data.

## Next

- [ ] Add one-time fail-closed SSH approval UI/API without cached HTTP fallback.
- [ ] Add dedicated SSH session audit schema/query helpers.
- [ ] Implement and test the per-session `ssh-agent` lease manager.
- [ ] Implement the authenticated internal SSH broker router.
- [ ] Build the hardened OpenSSH sidecar, entrypoint and ForceCommand wrapper.
- [ ] Add unit, container and end-to-end tests.
- [ ] Document experimental configuration and client workflow.
- [ ] Run full regression, dependency audit and final security gap analysis.

## Backlog

- [ ] Per-client identities and service allowlists.
- [ ] Short-lived SSH certificate plugin for targets that trust a ClawGuard CA.
- [ ] Network-policy generation restricting sidecar egress per target.
- [ ] SFTP/SCP support as explicit, separately approved capabilities.
- [ ] Service aliases as dedicated dynamic Unix users for `ssh service@gateway` UX.
- [ ] Admin dashboard visualization for SSH sessions.
- [ ] Metrics and concurrency quotas.

## Risks/blockers

- The sidecar can use an approved agent socket for any host accepting the same key until the short TTL expires; service-specific keys, short leases and egress policy reduce but do not eliminate this experimental residual risk.
- Shared Unix-socket ownership must be consistent across container UID/GID mappings.
- The broker wrapper must never evaluate `SSH_ORIGINAL_COMMAND` locally or accept client-supplied SSH options/targets.
- CI/container environments must provide `ssh-agent`, `ssh-add`, `ssh`, `sshd`, `curl` and `jq` for their respective tests.
- Approval waits must stay within OpenSSH connection/session timeouts.
