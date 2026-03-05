# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Roadmap note for planned policy scope selector: `method` only, or `service + method + path prefix`, or `service + method + exact path`.

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
