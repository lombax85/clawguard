# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Outbound webhook side channel**: fire-and-forget notification to a user-defined URL whenever an approval is requested, and (optionally) when it's resolved. Generic by design — any external alerting or automation system that can ingest a JSON POST is supported. Does not participate in the approval decision; Telegram is still the decider. Configure via `notifications.webhook` in `clawguard.yaml` (URL, method, headers, timeout, `cancelOnResolve`).
  - **Escalation delay** (`escalateAfterSeconds`, default 0): when set, the `approval_required` event is deferred by N seconds and only fires if the request is still pending. If the user approves/denies within the window, neither `approval_required` nor `approval_resolved` is sent. Useful to keep the webhook (and any urgent alerts it triggers) reserved for cases where Telegram was missed.
- **Admin HTTPS listener**: optional second listener (`admin.https.enabled`, default port 9443) that serves the dashboard over TLS using a leaf cert auto-issued by the existing MITM CA. Cert SAN includes `localhost` + `127.0.0.1` plus any user-configured hostnames/IPs. Files persisted under `data/ca/admin.{crt,key,json}`; cert is regenerated when the SAN list changes.

### Removed
- **Web Push notification channel**: removed in favor of the more flexible outbound-webhook channel. Browser-side Web Push had too many platform caveats on Safari/macOS (no action buttons, push only delivered while the browser process is running, secure-context requirements). The webhook channel keeps the same goal — wake the human via a second path — but delegates delivery to whatever notification system the operator already trusts.
- **Path-scoped approvals**: new Telegram buttons `15m-path`, `24h-path`, `forever-path` grant approval only for the exact request path (including querystring). Non-matching paths on the same service+method still trigger a fresh approval request. Persisted across restarts via new `approvals.path` column.
- **`1month` approval duration** (30 days) added to the standard TTL set.
- **`/showlog on|off` Telegram command**: when enabled, the paired chat receives info-only notifications for every auto-approved call (policy-based or via existing approval), with the reason surfaced. State persisted per chat (`telegram_paired_users.showlog`).
- Admin dashboard: active approvals table now shows the scope (method-wide vs path-scoped) and the path; revoke action honors the specific scope. Recent approval history shows the method and path.
- **Vault secrets provider**: credentials can now be fetched from HashiCorp Vault at startup, with support for both `token` and `kubernetes` auth methods. Secrets are resolved per-service via `secrets.provider: vault` configuration.
- **Static secrets provider**: explicit `secrets.provider: static` for inline credentials (existing behavior, now formalized).
- **Secrets provider abstraction** (`src/secrets/provider.ts`): pluggable interface for credential backends, making it easy to add new providers.
- **E2E tests for Vault integration**: full Kubernetes E2E tests covering both Vault token auth and Vault Kubernetes auth, with dedicated Skaffold manifests.
- **Auth plugin system**: extensible plugin architecture for complex authentication flows (e.g. OAuth2). Plugins are loaded before the server starts (fail-closed). Includes path traversal protection, SSRF re-validation, and audit logging.
- **OAuth2 Authorization Code plugin** (`oauth2-authcode`): built-in plugin supporting token persistence, automatic refresh, PKCE, and custom token types.
- **`clawguard auth` CLI**: interactive command to perform OAuth2 Authorization Code Flow — opens browser, handles redirect, exchanges code for tokens, and saves them for the plugin.
- **`auth.type: body_json`**: new auth type that injects credentials into JSON request bodies (useful for APIs like Bluesky/AT Protocol).
- **Transparent proxy mode**: L7 transparent proxy for Kubernetes sidecar deployments using iptables redirection. HTTPS interception via SNI-based dynamic certificate forging with cert-manager CAs.
- **Dummy token validation**: `dummyToken` field for services — validates the agent sends the expected placeholder before injecting the real credential.
- **Git HTTPS clone/pull/push support**: ClawGuard now handles the HTTP 407 authentication retry flow required by git clients, which send credentials only after receiving a `407 Proxy Authentication Required` challenge.
- `auth.type: url` for services that require credentials embedded in the URL (`https://user:pass@host`) instead of an Authorization header — needed for Bitbucket git operations.
- `auth.type: basic` for services that accept standard HTTP Basic Authentication (`Authorization: Basic <base64>`).
- Debug logging for auth injection (`🔑 Auth injected` / `⚠️ Auth NOT injected`) to help troubleshoot credential issues.
- Discovery policy control for unknown hosts in HTTPS proxy mode: `proxy.discoveryPolicy` with values `block` (default) and `silent_allow` (explicit opt-in).
- Runtime SSRF validation in discovery MITM forwarding path (allowlist/protocol validation + DNS private-IP check).
- Discovery `silent_allow` requests now generate audit entries (status + path/method/client IP) like other proxy paths.
- Discovery host tracking now uses memory cap with eviction to prevent unbounded growth under hostile traffic.
- Tests for discovery host tracking cap/eviction and same-host aggregation (`tests/mitm-proxy.test.js`).
- README section explaining functional differences between Mode C (`HTTPS_PROXY`) and `/etc/hosts` + forwarder setup.
- Hardening guidance for proxy mode (agent key strength, network/IP restrictions, private IP blocking, conservative discovery defaults).
- Admin deny response now includes `clientIp` + hint when access is blocked by `admin.allowedIPs`, to speed up network/debug setup.

### Changed
- **Telegram approval buttons reorganized**: removed `8h`, moved `Forever` out of the method-wide row (use `forever-path` for path-only approvals). New layout: row 1 `Once / 15m / 1h`, row 2 `24h / 1w / 1month`, row 3 `15m-path / 24h-path / forever-path`, row 4 `Deny`.
- **Approval lookup order**: exact path match first, then method-wide approval, before requesting a new approval.
- **Telegram notifications are now optional**: when unconfigured, approvals are auto-approved instead of failing.
- **CI/CD restructured**: E2E workflows consolidated using a reusable composite action (`.github/actions/e2e-setup/`), duplicate workflow removed, GitHub Actions upgraded to v5 (Node.js 24).
- CI workflow renamed to "CI: Unit Tests" for clarity; all workflows support manual trigger via `workflow_dispatch`.
- MITM proxy now keeps the TCP connection open after sending 407, waits for client retry with `Proxy-Authorization`, and validates credentials from the retry request before establishing the TLS tunnel.
- Unknown/unconfigured hosts are now default-deny in discovery flows unless `proxy.discoveryPolicy: silent_allow` is explicitly set.

## [0.2.1] - 2026-03-05

### Added
- Minimal CI pipeline via GitHub Actions (`.github/workflows/ci.yml`) to run build + tests on push to `main` and on pull requests.
- Baseline automated tests for `security.ts` helpers (`tests/security.test.js`).

### Changed
- Approval scope is now more granular: approvals are separated by **service + HTTP method** (not only by service).
- README roadmap updated to reflect the new per-method approval behavior.
- Restored Docker bridge IP note in README for admin dashboard `allowedIPs` when running in Docker.

## [0.2.0] - 2026-02-28

### Added
- Initial public release of ClawGuard.
- Telegram approval flow with time-limited approvals.
- Audit trail and admin dashboard.
- Forwarder mode for hardcoded SDK URLs.
- Security checks (allowlist, SSRF blocking, runtime URL validation).
