# Experimental SSH Gateway Todo

## Done

- [x] Create `experimental-ssh-gateway` from current `main`.
- [x] Establish shared goal and activate the custom loop.
- [x] Confirm that the existing auth plugin contract is HTTP request-specific.
- [x] Select a terminate-and-reoriginate SSH gateway architecture so upstream keys remain inside ClawGuard.
- [x] Define fail-closed MVP capability boundaries and credential-handling rules.

## Current iteration

- [ ] Reconcile the plan with independent architecture, repository-fit and threat-model reviews.
- [ ] Commit the initial loop state.
- [ ] Add protocol-aware configuration/types and validation tests.
- [ ] Add a separate SSH auth plugin interface/loader and built-in private-key plugin tests.
- [ ] Make SSH services YAML-only and prevent admin serialization/exposure of resolved SSH credential config.

## Next

- [ ] Add one-time, fail-closed SSH approval flow without cached HTTP fallback.
- [ ] Add dedicated SSH session audit schema and query helpers.
- [ ] Implement SSH host-key management and inbound public-key verification.
- [ ] Implement upstream pinned-host connection handling.
- [ ] Implement restricted shell and exec channel bridging.
- [ ] Add in-process end-to-end SSH tests.
- [ ] Document experimental configuration and client workflow.
- [ ] Run full build/test regression and a final gap analysis.

## Backlog

- [ ] Admin dashboard visualization for SSH sessions.
- [ ] Optional command-policy engine with carefully redacted command previews.
- [ ] Multiple inbound client identities with per-identity service policy.
- [ ] SFTP support as a separately approved capability.
- [ ] Port forwarding as separately scoped services rather than a blanket SSH capability.
- [ ] Metrics and concurrent-session quotas.

## Risks/blockers

- The `ssh2` dependency must be added and audited; installation may require network approval.
- Private-network SSH access needs an explicit policy separate from HTTP SSRF settings.
- Holding approval while an OpenSSH client waits must be tested against client and library timeouts.
- PTY, signal and half-close propagation are easy to get subtly wrong and require integration coverage.
- Inbound client authorization must not be confused with upstream credentials: only the latter are centrally held, while the former proves which client may ask ClawGuard for access.
