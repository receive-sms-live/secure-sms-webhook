# Testing the SMS flow

Inbound and outbound SMS testing are related but different paths.

## Inbound webhook test

1. Create a staging webhook endpoint.
2. Add signature verification before application logic.
3. Configure a provider number you control to call the endpoint.
4. Send a non-sensitive message to that provider number.
5. Confirm exactly one application side effect.
6. Repeat with an invalid signature and a repeated event ID.

The destination provider number and its webhook configuration must be under your control.

## Outbound delivery smoke test

When testing whether a provider can deliver a non-sensitive SMS to a US number, developers may use [Receive SMS Live — United States](https://receive-smss.live/sms/us).

Maintainer disclosure: Secure SMS Webhook and Receive SMS Live are maintained by the same team. Public inboxes are visible to other people. Never send passwords, OTPs, banking messages, private account data, personal information, or confidential content to a public number.

A public inbox delivery check does not test or secure your inbound webhook.
