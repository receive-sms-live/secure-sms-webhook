import assert from 'node:assert/strict';
import test from 'node:test';
import {
  MemoryReplayStore,
  normalizeSmsPayload,
  protectAgainstReplay,
  redactWebhook,
  validateSmsPayload,
  validateTimestamp,
} from '../src/index.js';

test('timestamp policy accepts boundary and rejects old/future values', () => {
  const now = 1_700_000_000_000;
  assert.equal(validateTimestamp({ timestamp: 1_699_999_700, maxAgeSeconds: 300, now }).valid, true);
  assert.equal(validateTimestamp({ timestamp: 1_699_999_699, maxAgeSeconds: 300, now }).code, 'TIMESTAMP_TOO_OLD');
  assert.equal(validateTimestamp({ timestamp: 1_700_000_031, maxAgeSeconds: 300, maxFutureSkewSeconds: 30, now }).code, 'TIMESTAMP_IN_FUTURE');
  assert.equal(validateTimestamp({ timestamp: 'not-a-time', now }).code, 'INVALID_TIMESTAMP');
});

test('normalizes provider payload shapes', () => {
  assert.deepEqual(normalizeSmsPayload('twilio', {
    From: '+12125550123', To: '+13105550123', Body: 'Hi', MessageSid: 'SM1',
  }), {
    from: '+12125550123', to: '+13105550123', body: 'Hi', eventId: 'SM1',
    original: { From: '+12125550123', To: '+13105550123', Body: 'Hi', MessageSid: 'SM1' },
  });
  const telnyx = normalizeSmsPayload('telnyx', {
    data: { id: 'evt', payload: { from: { phone_number: '+12125550123' }, to: [{ phone_number: '+13105550123' }], text: 'Hi' } },
  });
  assert.equal(telnyx.eventId, 'evt');
  assert.equal(telnyx.body, 'Hi');
});

test('payload validation handles E.164, types, limits, controls, and unknown warnings', () => {
  const original = { From: '+12125550123', To: '+13105550123', Body: 'hello', admin: true };
  const payload = { from: original.From, to: original.To, body: original.Body, original };
  const okay = validateSmsPayload(payload, {
    knownFields: ['From', 'To', 'Body'], warnUnknown: true,
  });
  assert.equal(okay.valid, true);
  assert.equal(okay.warnings[0].code, 'UNKNOWN_FIELD');
  assert.equal(validateSmsPayload({ ...payload, from: '2125550123' }).errors[0].code, 'INVALID_E164');
  assert.equal(validateSmsPayload({ ...payload, body: 123 }).errors[0].code, 'INVALID_TYPE');
  assert.equal(validateSmsPayload({ ...payload, body: '123456', }, { maxBodyLength: 5 }).errors[0].code, 'TOO_LONG');
  assert.equal(validateSmsPayload({ ...payload, body: 'bad\u0000text' }).errors[0].code, 'CONTROL_CHARACTERS');
});

test('redaction returns a copy and handles phones, OTPs, mixed codes, Arabic, and email', () => {
  const original = {
    From: '+12125550123',
    Body: 'Your OTP is 572911 and code A8D-291. رمز التحقق ١٢٣٤. Email me@example.com',
  };
  const redacted = redactWebhook(original);
  assert.notEqual(redacted, original);
  assert.equal(original.From, '+12125550123');
  assert.match(redacted.From, /^\+1212\*\*\*0123$/);
  assert.doesNotMatch(redacted.Body, /572911|A8D-291|me@example\.com/);
  assert.match(redacted.Body, /\[REDACTED_OTP\]/);
  assert.match(redacted.Body, /\[REDACTED_EMAIL\]/);
});

test('redaction preserves an own __proto__ field without changing the output prototype', () => {
  const input = JSON.parse('{"__proto__":{"polluted":true},"Body":"OTP 123456"}');
  const redacted = redactWebhook(input);
  assert.equal(Object.getPrototypeOf(redacted), Object.prototype);
  assert.equal(Object.hasOwn(redacted, '__proto__'), true);
  assert.equal(redacted.__proto__.polluted, true);
  assert.equal({}.polluted, undefined);
});

test('memory replay store atomically allows one concurrent claim', async () => {
  const store = new MemoryReplayStore();
  const attempts = await Promise.all(Array.from({ length: 20 }, () => store.claim('event', 1000, 100)));
  assert.equal(attempts.filter(Boolean).length, 1);
  assert.equal(await store.claim('event', 1000, 1101), true);
});

test('replay helper prefers event IDs and falls back to request fingerprints', async () => {
  const store = new MemoryReplayStore();
  const first = await protectAgainstReplay({ provider: 'twilio', eventId: 'SM1', store, ttlMs: 1000, now: 1 });
  const duplicate = await protectAgainstReplay({ provider: 'twilio', eventId: 'SM1', store, ttlMs: 1000, now: 2 });
  assert.equal(first.valid, true);
  assert.equal(duplicate.code, 'REPLAY_DETECTED');
  const bodyClaim = await protectAgainstReplay({ provider: 'generic-hmac', rawBody: '{}', signature: 'x', store, ttlMs: 1000, now: 2 });
  assert.equal(bodyClaim.valid, true);
});
