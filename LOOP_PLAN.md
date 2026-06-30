# ClawGuard Approval/Admin Hardening Loop

## Goal

Implement the next ClawGuard iteration requested by Fabio on 2026-06-23:

- fix recurring Telegram approval callback stalls permanently;
- make multi-token behavior explicit and document the supported pattern;
- add a strict/admin-editable mode for service and token management;
- reorganize the approvals dashboard by service with collapsible sections.

## Scope

Work only in `~/claude-projects/clawguard` on branch `feat/clawguard-approval-admin-hardening`.

## Constraints

- Do not introduce checkout duplicates.
- Do not store or print real tokens.
- Preserve fail-closed behavior for approvals.
- Keep YAML as the default source of truth unless admin edit mode is explicitly enabled.
- Use `CHANGELOG.MD` as the project changelog. This repository already uses that file, so no duplicate `CHANGELOG.md` will be created.

## Architecture Notes

- Telegram approval callbacks are delivered through `node-telegram-bot-api` long polling; button clicks require polling to be alive even when `sendMessage` still works.
- Service definitions are loaded from YAML and may be overridden by SQLite `services_override`.
- Current multi-token support is service-name based: separate services such as `coolify-logotel` and `coolify-lombax` can use separate credentials.
- Admin UI is a single static `public/index.html` served by Express.

## Acceptance Criteria

- Telegram polling restarts use cancellation or bounded timeouts, expose health diagnostics, and do not silently ignore repeated unhealthy polling states.
- Admin strict mode defaults to YAML-only. When disabled, the dashboard can add, edit, rotate, and remove service credentials via existing service override persistence.
- Services API reports whether web edits are allowed and masks secrets consistently.
- Approvals UI groups active approvals and recent history by service with collapse/expand controls.
- Build and test pass.
- Changes are committed and pushed to the feature branch.
