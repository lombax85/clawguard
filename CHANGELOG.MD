# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Discovery policy control for unknown hosts in HTTPS proxy mode: `proxy.discoveryPolicy` with values `block` (default) and `silent_allow` (explicit opt-in).
- Runtime SSRF validation in discovery MITM forwarding path (allowlist/protocol validation + DNS private-IP check).
- Discovery `silent_allow` requests now generate audit entries (status + path/method/client IP) like other proxy paths.
- Discovery host tracking now uses memory cap with eviction to prevent unbounded growth under hostile traffic.
- Tests for discovery host tracking cap/eviction and same-host aggregation (`tests/mitm-proxy.test.js`).
- README section explaining functional differences between Mode C (`HTTPS_PROXY`) and `/etc/hosts` + forwarder setup.
- Hardening guidance for proxy mode (agent key strength, network/IP restrictions, private IP blocking, conservative discovery defaults).
- Roadmap note for planned policy scope selector: `method` only, or `service + method + path prefix`, or `service + method + exact path`.

### Changed
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
