import {
  canonicalPairs,
  configurationFailure,
  constantTimeEqual,
  decodeSignature,
  hmacBytes,
  invalid,
  requireNonEmptyString,
  valid,
} from '../internal.js';
import { validateTimestamp } from '../policies/timestamp.js';

const VONAGE_ALGORITHMS = new Map([
  ['sha1', 'sha1'],
  ['sha256', 'sha256'],
  ['sha512', 'sha512'],
]);

function canonicalVonageParams(params) {
  return canonicalPairs(params, {
    exclude: ['sig'],
    prefix: '&',
    separator: '&',
    assignment: '=',
    sanitizeValue: (value) => String(value).replace(/[&=]/g, '_'),
  });
}

export function createVonageSignature({ params, secret, algorithm = 'sha256' }) {
  requireNonEmptyString(secret, 'secret');
  const normalized = String(algorithm).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!VONAGE_ALGORITHMS.has(normalized)) {
    throw new TypeError(`Unsupported Vonage algorithm: ${algorithm}`);
  }
  const data = canonicalVonageParams(params);
  return hmacBytes(normalized, secret, data).toString('hex');
}

export function verifyVonageWebhook(options) {
  const provider = 'vonage';
  try {
    const {
      params,
      signature = params?.sig,
      secret,
      algorithm = 'sha256',
      maxAgeSeconds = 300,
      maxFutureSkewSeconds = 30,
      now,
    } = options || {};
    if (!signature) return invalid(provider, 'MISSING_SIGNATURE', 'Vonage sig parameter is missing.');
    const normalized = String(algorithm).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (params?.timestamp === undefined) {
      return invalid(provider, 'MISSING_TIMESTAMP', 'Vonage timestamp parameter is missing.');
    }
    if (maxAgeSeconds !== false) {
      const time = validateTimestamp({
        timestamp: params.timestamp,
        maxAgeSeconds,
        maxFutureSkewSeconds,
        now,
      });
      if (!time.valid) return { ...time, provider };
    }
    const expected = decodeSignature(createVonageSignature({ params, secret, algorithm }), 'hex');
    const received = decodeSignature(signature, 'hex');
    if (!received) return invalid(provider, 'MALFORMED_SIGNATURE', 'Vonage signature is not valid hexadecimal.');
    if (!constantTimeEqual(received, expected)) {
      return invalid(provider, 'INVALID_SIGNATURE', 'Vonage signature does not match.');
    }
    return valid(provider, { algorithm: normalized, timestamp: Number(params.timestamp) });
  } catch (error) {
    return configurationFailure(provider, error);
  }
}
