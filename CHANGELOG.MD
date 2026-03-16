# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
