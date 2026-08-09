import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import {
  createHmacSignature,
  createPlivoSignature,
  createTelnyxTestSignature,
  createTwilioSignature,
  createVonageSignature,
  verifyHmacWebhook,
  verifyPlivoWebhook,
  verifyTelnyxWebhook,
  verifyTwilioWebhook,
  verifyVonageWebhook,
} from '../src/index.js';

test('Generic HMAC matches a fixed SHA-256 vector', () => {
  const rawBody = '{"hello":"world"}';
  const signature = createHmacSignature({ rawBody, secret: 'test_secret' });
  assert.equal(signature, 'b7b1e7e190c7aace9efb076f2394f2408bf389ed0398c526b97101ab2c84fed3');
  assert.equal(verifyHmacWebhook({ rawBody, signature, secret: 'test_secret' }).valid, true);
  assert.equal(verifyHmacWebhook({ rawBody: `${rawBody} `, signature, secret: 'test_secret' }).code, 'INVALID_SIGNATURE');
});

test('Generic HMAC supports prefix, Base64, and timestamp contracts', () => {
  const options = {
    rawBody: 'message',
    secret: 'secret',
    timestamp: 1_700_000_000,
    timestampSeparator: '.',
    encoding: 'base64',
    prefix: 'sha256=',
  };
  const signature = createHmacSignature(options);
  assert.match(signature, /^sha256=/);
  assert.equal(verifyHmacWebhook({ ...options, signature, now: 1_700_000_000_000 }).valid, true);
  assert.equal(verifyHmacWebhook({ ...options, signature: 'wrong', now: 1_700_000_000_000 }).code, 'MALFORMED_SIGNATURE');
});

test('Generic HMAC enforces a configured timestamp header and freshness', () => {
  const base = { rawBody: '{}', secret: 'secret', requireTimestamp: true };
  const bodyOnlySignature = createHmacSignature({ rawBody: '{}', secret: 'secret' });
  assert.equal(verifyHmacWebhook({ ...base, signature: bodyOnlySignature }).code, 'MISSING_TIMESTAMP');
  const timestamp = 1_700_000_000;
  const signature = createHmacSignature({ ...base, timestamp });
  assert.equal(verifyHmacWebhook({ ...base, timestamp, signature, now: (timestamp + 301) * 1000 }).code, 'TIMESTAMP_TOO_OLD');
});

test('Twilio form validator matches a provider reference vector', () => {
  const options = {
    authToken: '12345',
    url: 'https://mycompany.com/myapp.php?foo=1&bar=2',
    params: {
      CallSid: 'CA1234567890ABCDE',
      Caller: '+12349013030',
      Digits: '1234',
      From: '+12349013030',
      To: '+18005551212',
    },
  };
  const signature = createTwilioSignature(options);
  assert.equal(signature, '0/KCTR6DLpKmkAf8muzZqo1nDgQ=');
  assert.equal(verifyTwilioWebhook({ ...options, signature }).valid, true);
  assert.equal(verifyTwilioWebhook({ ...options, url: `${options.url}/`, signature }).code, 'INVALID_SIGNATURE');
});

test('Twilio JSON validator checks bodySHA256 before the request signature', () => {
  const rawBody = '{"CallSid":"CA1234567890ABCDE","Caller":"+12349013030"}';
  const url = 'https://example.com/myapp?bodySHA256=5ccde7145dfb8f56479710896586cb9d5911809d83afbe34627818790db0aec9';
  const signature = createTwilioSignature({ url, authToken: '12345' });
  const valid = verifyTwilioWebhook({
    url, rawBody, signature, authToken: '12345', contentType: 'application/json',
  });
  assert.equal(valid.valid, true);
  const changed = verifyTwilioWebhook({
    url, rawBody: `${rawBody} `, signature, authToken: '12345', contentType: 'application/json',
  });
  assert.equal(changed.code, 'BODY_HASH_MISMATCH');
});

test('Telnyx verifies Ed25519 using both raw Base64 and PEM public keys', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawBody = '{"data":{"id":"event-1"}}';
  const timestamp = 1_700_000_000;
  const signature = createTelnyxTestSignature({ rawBody, timestamp, privateKey });
  const jwk = publicKey.export({ format: 'jwk' });
  const now = timestamp * 1000;
  assert.equal(verifyTelnyxWebhook({
    rawBody, timestamp, signature, publicKey: Buffer.from(jwk.x, 'base64url').toString('base64'), now,
  }).valid, true);
  assert.equal(verifyTelnyxWebhook({
    rawBody, timestamp, signature, publicKey: publicKey.export({ format: 'pem', type: 'spki' }), now,
  }).valid, true);
  assert.equal(verifyTelnyxWebhook({
    rawBody: `${rawBody}\n`, timestamp, signature, publicKey: publicKey.export({ format: 'pem', type: 'spki' }), now,
  }).code, 'INVALID_SIGNATURE');
});

test('Telnyx rejects stale and future timestamps before signature acceptance', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawBody = '{}';
  const timestamp = 1_700_000_000;
  const signature = createTelnyxTestSignature({ rawBody, timestamp, privateKey });
  const base = { rawBody, timestamp, signature, publicKey: publicKey.export({ format: 'pem', type: 'spki' }) };
  assert.equal(verifyTelnyxWebhook({ ...base, now: (timestamp + 301) * 1000 }).code, 'TIMESTAMP_TOO_OLD');
  assert.equal(verifyTelnyxWebhook({ ...base, now: (timestamp - 31) * 1000 }).code, 'TIMESTAMP_IN_FUTURE');
});

test('Vonage HMAC-SHA256 matches canonical parameter vector', () => {
  const params = {
    msisdn: '+12125550123',
    text: 'A&B=C',
    timestamp: '1700000000',
    to: '+13105550123',
  };
  const signature = createVonageSignature({ params, secret: 'vonage_secret', algorithm: 'sha256' });
  assert.equal(signature, 'a74e1d28b6e70ad2940104d4d2a152bb22b97f5fa4f3b499e86865609753ec1c');
  assert.equal(verifyVonageWebhook({
    params: { ...params, sig: signature }, secret: 'vonage_secret', algorithm: 'sha256', now: 1_700_000_000_000,
  }).valid, true);
});

test('Vonage rejects legacy MD5 unless explicitly allowed', () => {
  const params = { timestamp: '1700000000', text: 'hello' };
  const signature = createVonageSignature({ params, secret: 'secret', algorithm: 'md5hash' });
  assert.equal(verifyVonageWebhook({ params, signature, secret: 'secret', algorithm: 'md5hash', maxAgeSeconds: false }).code, 'INSECURE_ALGORITHM');
  assert.equal(verifyVonageWebhook({ params, signature, secret: 'secret', algorithm: 'md5hash', allowLegacyMd5: true, maxAgeSeconds: false }).valid, true);
});

test('Plivo V3 matches a fixed HMAC-SHA256 vector and token rotation list', () => {
  const options = {
    url: 'https://example.com/abcd?foo=bar',
    params: { CallUUID: '4vbcpem8', Digits: '1234', From: '+15551111111', To: '+15555555555' },
    nonce: 'kjsdhfsd87sd7yisud2',
    authToken: 'plivo_secret',
  };
  const signature = createPlivoSignature(options);
  assert.equal(signature, 'y8MikLBFi9mqAVk5Ah7AeOUYo7MEGP6zWWIn5avVGGQ=');
  assert.equal(verifyPlivoWebhook({ ...options, signature: `${Buffer.alloc(32).toString('base64')},${signature}` }).valid, true);
  assert.equal(verifyPlivoWebhook({ ...options, nonce: 'different', signature }).code, 'INVALID_SIGNATURE');
});

test('all validators fail closed on missing signatures', () => {
  assert.equal(verifyHmacWebhook({ rawBody: '', secret: 'x' }).code, 'MISSING_SIGNATURE');
  assert.equal(verifyTwilioWebhook({ url: 'https://example.com', authToken: 'x' }).code, 'MISSING_SIGNATURE');
  assert.equal(verifyTelnyxWebhook({ rawBody: '', publicKey: 'x', timestamp: 1 }).code, 'MISSING_SIGNATURE');
  assert.equal(verifyVonageWebhook({ params: {}, secret: 'x' }).code, 'MISSING_SIGNATURE');
  assert.equal(verifyPlivoWebhook({ url: 'https://example.com', nonce: 'x', authToken: 'x' }).code, 'MISSING_SIGNATURE');
});
