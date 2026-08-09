# Secure SMS Webhook Validator

[![CI](https://github.com/receive-sms-live/secure-sms-webhook/actions/workflows/test.yml/badge.svg)](https://github.com/receive-sms-live/secure-sms-webhook/actions/workflows/test.yml)
[![Security policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Security-first webhook validation for applications that receive SMS events from Twilio, Telnyx, Vonage, Plivo, or a custom HMAC provider. The package combines signature verification, timestamp checks, replay protection, payload validation, PII redaction, Express middleware, and a defensive localhost tester.

> Status: `0.1.0` release candidate. Validate the exact provider configuration and test in staging before production use.

## Why

An SMS provider sends an HTTP request when a number receives a message. Without signature verification, an attacker can submit a forged request with a fake sender or message. A valid signature proves authenticity and integrity, but provider retry behavior, replay attacks, unsafe payload assumptions, and sensitive logs still need deliberate controls.

## Install

```bash
npm install secure-sms-webhook
```

Node.js 20 or newer is required. The package is ESM and has no runtime dependencies.

## Express + Twilio

Capture the raw body before parsing and configure the public URL exactly as Twilio sees it:

```js
import express from 'express';
import {
  captureRawBody,
  createExpressMiddleware,
  MemoryReplayStore,
} from 'secure-sms-webhook';

const app = express();
const replayStore = new MemoryReplayStore(); // Development/single-process only.

app.use(express.urlencoded({
  extended: false,
  limit: '64kb',
  verify: captureRawBody,
}));

app.post('/webhooks/sms', createExpressMiddleware({
  provider: 'twilio',
  publicUrl: 'https://example.com/webhooks/sms',
  authToken: () => process.env.TWILIO_AUTH_TOKEN,
  replayStore,
  replayTtlMs: 10 * 60 * 1000,
}), (req, res) => {
  // Process req.secureSmsWebhook.normalizedPayload.
  res.sendStatus(204);
});
```

For multiple application instances, replace `MemoryReplayStore` with an atomic shared store such as Redis. The custom store contract is `claim(key, ttlMs, now)`, which must return `true` only for the first claim.

## Direct verification

```js
import { verifyTwilioWebhook } from 'secure-sms-webhook';

const result = verifyTwilioWebhook({
  url: 'https://example.com/webhooks/sms',
  params: req.body,
  signature: req.headers['x-twilio-signature'],
  authToken: process.env.TWILIO_AUTH_TOKEN,
});

if (!result.valid) return res.status(403).send('Invalid webhook');
```

### Generic HMAC

```js
import { verifyHmacWebhook } from 'secure-sms-webhook';

const result = verifyHmacWebhook({
  rawBody,
  signature: req.headers['x-webhook-signature'],
  secret: process.env.WEBHOOK_SECRET,
  algorithm: 'sha256',
  encoding: 'hex',
});
```

Use `timestamp` and `timestampSeparator` when your signing contract includes a timestamp. Both producer and consumer must use the same byte-level canonicalization.

## Provider behavior

| Provider | Verification | Freshness/replay signal |
| --- | --- | --- |
| Twilio | HMAC-SHA1 over the exact URL and form parameters; JSON also checks `bodySHA256` | Use `MessageSid` with a replay store |
| Telnyx | Ed25519 over `timestamp\|raw JSON` | Signed timestamp, default maximum age 5 minutes, plus event ID |
| Vonage SMS | Configurable signature; HMAC-SHA256 recommended | Signed timestamp and message ID |
| Plivo V3 | HMAC-SHA256 over URL, sorted parameters, and nonce | Unique nonce plus message UUID |
| Generic HMAC | SHA-256 by default; configurable encoding/prefix | Configurable timestamp and event ID |

Vonage's legacy MD5 modes are rejected by default. If migration compatibility is unavoidable, pass `allowLegacyMd5: true` explicitly and document the risk.

## Payload validation and logging

```js
import { normalizeSmsPayload, redactWebhook, validateSmsPayload } from 'secure-sms-webhook';

const normalized = normalizeSmsPayload('twilio', req.body);
const check = validateSmsPayload(normalized, { maxBodyLength: 5000 });

console.log(redactWebhook(req.body, {
  phoneNumbers: true,
  otp: true,
  email: true,
}));
```

Unknown provider fields are warnings, not failures, because providers may add fields. Redaction is for logs only and must happen **after** signature verification.

## Defensive CLI

The tester only accepts explicit localhost/loopback URLs. Use a dedicated staging endpoint because valid signed tests can produce application side effects.

```bash
export SECURE_SMS_WEBHOOK_TEST_SECRET='your-local-test-secret'
npx secure-sms-webhook test \
  --url http://127.0.0.1:3000/webhooks/sms \
  --provider generic-hmac \
  --acknowledge-staging
```

The CLI checks missing and invalid signatures without a credential. Valid-signature, payload, replay, and size tests require the provider's test credential environment variable. A duplicate HTTP `2xx` is reported as inconclusive because a secure endpoint may acknowledge a retry while suppressing duplicate side effects.

See [CLI safety and interpretation](docs/cli.md).

## Documentation

- [Security model](docs/security-model.md)
- [Provider notes](docs/providers.md)
- [Defensive CLI](docs/cli.md)
- [Testing the SMS flow](docs/testing-sms-flow.md)
- [Express example](examples/express/server.js)
- [Next.js example](examples/nextjs/route.js)
- [Cloudflare Worker example](examples/cloudflare-worker/worker.js)

## Security posture

- No network calls or install scripts in the library.
- Constant-time comparison for shared-secret signatures.
- Raw-body and exact-URL validation where required.
- Atomic replay-store interface.
- CodeQL, dependency review, Dependabot, tests, and release provenance workflow.
- Responsible disclosure process in [SECURITY.md](SECURITY.md).

This project reduces common implementation mistakes; it is not a security certification. Review provider documentation, proxy URL handling, key rotation, storage availability, and application side effects for your environment.

## Maintainer disclosure and SMS testing resource

Secure SMS Webhook is maintained by the team behind [Receive SMS Live — United States](https://receive-smss.live/sms/us).

That public inbox resource may be used only for non-sensitive outbound SMS delivery checks. Public inbox messages are visible to other people. Never use public numbers for passwords, OTPs, banking, private accounts, or confidential data. It does not replace testing an inbound webhook on a provider number you control.

## License

[MIT](LICENSE)
