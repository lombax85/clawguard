# ClawGuard Approval/Admin Hardening TODO

## Done

- Created branch `feat/clawguard-approval-admin-hardening`.
- Captured loop goal, constraints, and acceptance criteria.
- Hardened Telegram polling restart: cancel-first stop, restart health tracking, repeated polling error recovery, and admin/status diagnostics.
- Added `admin.strictMode` defaulting to YAML-only service/token config.
- Added guarded admin API behavior for strict/editable service overrides.
- Added dashboard service add/edit/rotate/delete token flow when strict mode is disabled.
- Reworked approvals dashboard into collapsible service groups with service-level revoke controls.
- Documented multi-token usage as separate service names, e.g. `coolify-logotel` and `coolify-lombax`.
- Added admin strict-mode tests.
- Ran `npm test`: 68/68 passing after rebuilding local `better-sqlite3` for the current Node ABI.

## Current Iteration

- Final diff review, commit, and push the branch.

## Next

- Manual smoke test on Fabio's ClawGuard instance after branch deployment.

## Backlog

- Add end-to-end Telegram polling test with a fake polling adapter if regressions continue.
- Consider a webhook-based Telegram mode as an alternative to long polling for always-on server deployments.

## Risks / Blockers

- Real Telegram callback stalls require live Telegram/network conditions to reproduce; this iteration can harden the known fragile polling lifecycle and expose diagnostics, but final proof needs deployment.
- Web token editing must remain opt-in because admin overrides can shadow YAML.
