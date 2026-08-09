# Changelog

All notable changes will be documented here. The project follows Semantic Versioning after `1.0.0`; pre-1.0 releases may refine APIs while preserving documented security behavior where possible.

## 0.1.1 - 2026-08-09

- Removed all legacy MD5 and MD5-hash paths from the Vonage adapter.
- Pinned GitHub Actions to immutable commits and updated their major releases.
- Added Cloudflare Pages security headers, including a strict Content Security Policy.
- Updated release status, website metadata, and security regression coverage.

## 0.1.0 - 2026-08-09

- Added Twilio, Telnyx, Vonage, Plivo V3, and Generic HMAC validators.
- Added timestamp and payload policies.
- Added an atomic replay-store contract and bounded in-memory development store.
- Added phone, OTP, mixed-code, Arabic-code, and email redaction.
- Added Express-compatible middleware and raw-body capture helper.
- Added a localhost-only defensive CLI.
- Added a static code generator, provider guides, security policy, examples, tests, and release automation.
