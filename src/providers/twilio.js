import {
  canonicalPairs,
  configurationFailure,
  constantTimeEqual,
  decodeSignature,
  hashBytes,
  hmacBytes,
  invalid,
  requireNonEmptyString,
  valid,
} from '../internal.js';

export function createTwilioSignature({ url, params = {}, authToken }) {
  requireNonEmptyString(url, 'url');
  requireNonEmptyString(authToken, 'authToken');
  const canonical = `${url}${canonicalPairs(params)}`;
  return hmacBytes('sha1', authToken, canonical).toString('base64');
}

export function verifyTwilioWebhook(options) {
  const provider = 'twilio';
  try {
    const {
      url,
      params = {},
      rawBody,
      signature,
      authToken,
      contentType = rawBody === undefined ? 'application/x-www-form-urlencoded' : 'application/json',
    } = options || {};
    if (!signature) return invalid(provider, 'MISSING_SIGNATURE', 'X-Twilio-Signature is missing.');
    requireNonEmptyString(url, 'url');
    requireNonEmptyString(authToken, 'authToken');

    let signatureParams = params;
    if (contentType.toLowerCase().includes('application/json')) {
      if (rawBody === undefined) {
        return invalid(provider, 'MISSING_RAW_BODY', 'Twilio JSON validation requires the exact raw body.');
      }
      const parsedUrl = new URL(url);
      const suppliedHash = parsedUrl.searchParams.get('bodySHA256');
      if (!suppliedHash) {
        return invalid(provider, 'MISSING_BODY_SHA256', 'Twilio JSON URL is missing bodySHA256.');
      }
      const expectedHash = hashBytes('sha256', rawBody);
      const receivedHash = decodeSignature(suppliedHash, 'hex');
      if (!receivedHash || !constantTimeEqual(receivedHash, expectedHash)) {
        return invalid(provider, 'BODY_HASH_MISMATCH', 'Twilio bodySHA256 does not match the raw body.');
      }
      signatureParams = {};
    }

    const expected = decodeSignature(
      createTwilioSignature({ url, params: signatureParams, authToken }),
      'base64',
    );
    const received = decodeSignature(signature, 'base64');
    if (!received) return invalid(provider, 'MALFORMED_SIGNATURE', 'Twilio signature is not valid Base64.');
    if (!constantTimeEqual(received, expected)) {
      return invalid(provider, 'INVALID_SIGNATURE', 'Twilio signature does not match.');
    }
    return valid(provider, { contentType });
  } catch (error) {
    return configurationFailure(provider, error);
  }
}
