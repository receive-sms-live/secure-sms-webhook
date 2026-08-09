# Security model

## Security goals

Secure SMS Webhook helps an application reject unsigned, incorrectly signed, stale, malformed, or replayed webhook requests before business logic processes them. It also provides log-safe copies of common SMS payloads.

## Required processing order

1. Enforce an HTTP byte limit before body parsing.
2. Preserve the exact public URL and raw request bytes.
3. Verify the provider signature and signed timestamp, when available.
4. Parse and validate the SMS payload.
5. Atomically claim an event ID, nonce, or request fingerprint.
6. Execute business logic.
7. Log only a redacted copy.

Changing URL encoding, whitespace, query parameters, form values, or JSON serialization before verification can invalidate an authentic signature.

## Trust boundaries

- A valid signature authenticates the request according to the provider's signing contract. It does not make message content trustworthy.
- Phone numbers are identifiers supplied by a messaging network, not proof of a human identity.
- Payload validation is application input validation, not HTML sanitization for every downstream context.
- In-memory replay protection is not sufficient for clusters, serverless concurrency, restarts, or multi-region deployments.
- Logging redaction is best effort. Do not log secrets, raw signatures, authentication tokens, or unredacted request bodies.

## Replay protection

The `ReplayStore.claim` operation must be atomic. A Redis implementation should use a single `SET key value NX PX ttl` operation or an equivalent atomic primitive. A check followed by a separate write is race-prone.

Provider event IDs are preferred. When an ID is unavailable, the package hashes the raw body and signature. Choose a TTL that covers the provider's retry window without allowing unbounded state.

## Reverse proxies

Signature schemes frequently cover the public URL. Framework-derived URLs may be wrong behind a load balancer or tunnel. Configure `publicUrl` explicitly or reconstruct it only from trusted proxy headers. Never accept an arbitrary untrusted `Host` or forwarded header as signing input.

## Failure behavior

Signature and payload failures should stop processing. Replay behavior is application-specific: a `409` is useful in a test endpoint, while production integrations may intentionally return `2xx` for duplicates to stop provider retries. The duplicate must never repeat the business side effect.
