# Provider notes

Provider algorithms and configuration can change. Review the linked first-party documentation before production deployment.

## Twilio

Twilio signs inbound requests in `X-Twilio-Signature`. Form-encoded validation uses the exact URL plus every form parameter. JSON validation uses the exact raw body and the URL's `bodySHA256` parameter. Do not hard-code an allowlist before signature verification because Twilio may add parameters.

- Use the primary Auth Token required by the account configuration.
- Preserve URL-encoded query parameters.
- Configure the external HTTPS URL when TLS terminates at a proxy.
- Use `MessageSid` for idempotency.

Official reference: <https://www.twilio.com/docs/usage/webhooks/webhooks-security>

## Telnyx

Telnyx uses Ed25519. It signs `timestamp|json_payload` and sends the Base64 signature and Unix timestamp in headers. The package accepts a Base64 raw 32-byte Ed25519 public key, SPKI DER Base64, or PEM public key.

The default timestamp tolerance is five minutes. Event IDs should still be stored to make side effects idempotent.

Official reference: <https://developers.telnyx.com/docs/messaging/messages/receiving-webhooks>

## Vonage SMS

Signed inbound SMS webhooks must be enabled for the account. Configure HMAC-SHA256 or stronger. Legacy MD5 modes are intentionally unsupported.

Official reference: <https://developer.vonage.com/en/getting-started/concepts/signing-messages>

## Plivo V3

Plivo V3 uses HMAC-SHA256 over its canonical final URL, sorted POST parameters, separator characters defined by the V3 scheme, and a unique nonce. It can send comma-separated signatures during Auth Token rotation; the validator accepts the request when any supplied signature matches the configured token.

Official reference: <https://www.plivo.com/docs/voice/concepts/signature-validation>

## Generic HMAC

Generic mode is a byte-level contract. Document all of the following for both sender and receiver:

- hashing algorithm;
- signature encoding and prefix;
- exact signed bytes;
- timestamp header and separator;
- maximum age and future clock skew;
- event ID and replay-store TTL;
- secret rotation strategy.

Prefer HMAC-SHA256. Never invent a custom hash such as `hash(secret + body)`.
