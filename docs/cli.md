# Defensive CLI

The CLI is an integration test for endpoints you own. Version 0.1 deliberately accepts only `localhost`, `127.0.0.1`, and `::1`, never follows redirects, and requires an explicit staging acknowledgement.

## Run

```bash
SECURE_SMS_WEBHOOK_TEST_SECRET='development-only-secret' \
npx secure-sms-webhook test \
  --url http://127.0.0.1:3000/webhooks/sms \
  --provider generic-hmac \
  --acknowledge-staging
```

Use environment variables rather than command-line secret arguments so credentials do not appear in shell history or process listings.

## What results mean

- `PASS Missing signature rejected`: the route returned a non-404 client rejection.
- `PASS Valid signature accepted`: the configured test credential produced a request accepted with `2xx`.
- `PASS Replay protection observed`: the first signed event was accepted and a duplicate received `409` or the diagnostic replay header.
- `WARNING Replay protection inconclusive`: response status alone cannot show whether a duplicate side effect happened.
- `WARNING Payload size limit`: the endpoint did not return `413`; enforce a byte limit before the JSON/form parser.
- `FAIL`: observed behavior contradicts the expected defensive contract or the requested route is unavailable.

The CLI does not prove that an endpoint is secure. Confirm database writes, queue jobs, notifications, and other side effects in your staging environment.
