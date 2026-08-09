import { sign, verify } from 'node:crypto';
import {
  asBuffer,
  configurationFailure,
  decodeSignature,
  ed25519PublicKey,
  invalid,
  valid,
} from '../internal.js';
import { validateTimestamp } from '../policies/timestamp.js';

export function createTelnyxTestSignature({ rawBody, timestamp, privateKey }) {
  const payload = Buffer.concat([
    Buffer.from(String(timestamp)),
    Buffer.from('|'),
    asBuffer(rawBody, 'rawBody'),
  ]);
  return sign(null, payload, privateKey).toString('base64');
}

export function verifyTelnyxWebhook(options) {
  const provider = 'telnyx';
  try {
    const {
      rawBody,
      signature,
      timestamp,
      publicKey,
      maxAgeSeconds = 300,
      maxFutureSkewSeconds = 30,
      now,
    } = options || {};
    if (!signature) return invalid(provider, 'MISSING_SIGNATURE', 'telnyx-signature-ed25519 is missing.');
    if (timestamp === undefined || timestamp === null || timestamp === '') {
      return invalid(provider, 'MISSING_TIMESTAMP', 'telnyx-timestamp is missing.');
    }
    if (maxAgeSeconds !== false) {
      const time = validateTimestamp({ timestamp, maxAgeSeconds, maxFutureSkewSeconds, now });
      if (!time.valid) return { ...time, provider };
    }

    const received = decodeSignature(signature, 'base64');
    if (!received) return invalid(provider, 'MALFORMED_SIGNATURE', 'Telnyx signature is not valid Base64.');
    const payload = Buffer.concat([
      Buffer.from(String(timestamp)),
      Buffer.from('|'),
      asBuffer(rawBody, 'rawBody'),
    ]);
    const matches = verify(null, payload, ed25519PublicKey(publicKey), received);
    if (!matches) return invalid(provider, 'INVALID_SIGNATURE', 'Telnyx Ed25519 signature does not match.');
    return valid(provider, { timestamp: Number(timestamp) });
  } catch (error) {
    return configurationFailure(provider, error);
  }
}
