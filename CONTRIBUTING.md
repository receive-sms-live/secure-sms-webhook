# Contributing

Thank you for improving Secure SMS Webhook.

## Before a pull request

1. Open an issue for significant API or provider-protocol changes.
2. Never commit real Auth Tokens, signing secrets, public inbox messages, phone numbers, or production webhook payloads.
3. Use synthetic fixtures and document the first-party provider reference behind every signing rule.
4. Add positive, negative, malformed-input, and byte-level canonicalization tests.
5. Run `npm run check`.

## Design rules

- Fail closed when a required signature component is missing.
- Keep provider-specific canonicalization in its adapter.
- Do not normalize the URL or raw body before signature verification.
- Treat unknown provider fields as warnings unless the caller explicitly chooses stricter application validation.
- Keep the tester restricted to explicit, authorized local/staging use.
- Redact logs after verification; never mutate the bytes being authenticated.
- Preserve the no-runtime-dependency goal unless a dependency has a clear security justification.

## Commits and releases

Use focused commits and include a test for each security fix. Maintainers publish releases through the protected release workflow and npm Trusted Publishing. Do not include generated package archives in pull requests.
