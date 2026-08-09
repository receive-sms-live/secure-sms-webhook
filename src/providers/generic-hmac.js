import {
  asBuffer,
  configurationFailure,
  constantTimeEqual,
  decodeSignature,
  encodeSignature,
  hmacBytes,
  invalid,
  requireNonEmptyString,
  valid,
} from '../internal.js';
import { validateTimestamp } from '../policies/timestamp.js';

export function createHmacSignature(options) {
  const {
    rawBody,
    secret,
    algorithm = 'sha256',
    encoding = 'hex',
    prefix = '',
    timestamp,
    timestampSeparator = '.',
  } = options || {};
  requireNonEmptyString(secret, 'secret');
  const body = asBuffer(rawBody, 'rawBody');
  const signed = timestamp === undefined || timestamp === null
    ? body
    : Buffer.concat([
        Buffer.from(String(timestamp)),
        Buffer.from(timestampSeparator),
        body,
      ]);
  return `${prefix}${encodeSignature(hmacBytes(algorithm, secret, signed), encoding)}`;
}

export function verifyHmacWebhook(options) {
  const provider = 'generic-hmac';
  try {
    const {
      signature,
      encoding = 'hex',
      prefix = '',
      timestamp,
      requireTimestamp = false,
      maxAgeSeconds = 300,
      maxFutureSkewSeconds = 30,
      now,
    } = options || {};
    if (!signature) return invalid(provider, 'MISSING_SIGNATURE', 'Webhook signature is missing.');
    if (requireTimestamp && (timestamp === undefined || timestamp === null || timestamp === '')) {
      return invalid(provider, 'MISSING_TIMESTAMP', 'Configured webhook timestamp is missing.');
    }
    if (timestamp !== undefined && timestamp !== null && maxAgeSeconds !== false) {
      const time = validateTimestamp({ timestamp, maxAgeSeconds, maxFutureSkewSeconds, now });
      if (!time.valid) return { ...time, provider };
    }
    const received = decodeSignature(signature, encoding, prefix);
    if (!received) return invalid(provider, 'MALFORMED_SIGNATURE', 'Webhook signature encoding is invalid.');

    const expectedText = createHmacSignature({ ...options, prefix: '' });
    const expected = decodeSignature(expectedText, encoding);
    if (!constantTimeEqual(received, expected)) {
      return invalid(provider, 'INVALID_SIGNATURE', 'Webhook signature does not match.');
    }
    return valid(provider, {
      algorithm: options?.algorithm || 'sha256',
      ...(timestamp === undefined ? {} : { timestamp: Number(timestamp) }),
    });
  } catch (error) {
    return configurationFailure(provider, error);
  }
}
