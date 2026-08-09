import { getHeader, invalid, valid } from './internal.js';
import { normalizeSmsPayload, validateSmsPayload } from './policies/payload.js';
import { verifyHmacWebhook } from './providers/generic-hmac.js';
import { verifyPlivoWebhook } from './providers/plivo.js';
import { verifyTelnyxWebhook } from './providers/telnyx.js';
import { verifyTwilioWebhook } from './providers/twilio.js';
import { verifyVonageWebhook } from './providers/vonage.js';
import { protectAgainstReplay } from './replay.js';

export const PROVIDERS = Object.freeze(['twilio', 'telnyx', 'vonage', 'plivo', 'generic-hmac']);

export function verifyProviderWebhook(options = {}) {
  const { provider, headers = {}, params, body, rawBody = '' } = options;
  switch (provider) {
    case 'twilio':
      return verifyTwilioWebhook({
        ...options,
        params: params || body || {},
        signature: options.signature || getHeader(headers, 'x-twilio-signature'),
      });
    case 'telnyx':
      return verifyTelnyxWebhook({
        ...options,
        rawBody,
        signature: options.signature || getHeader(headers, 'telnyx-signature-ed25519'),
        timestamp: options.timestamp || getHeader(headers, 'telnyx-timestamp'),
      });
    case 'vonage':
      return verifyVonageWebhook({
        ...options,
        params: params || body || {},
        signature: options.signature || params?.sig || body?.sig,
      });
    case 'plivo':
      return verifyPlivoWebhook({
        ...options,
        params: params || body || {},
        signature: options.signature || getHeader(headers, 'x-plivo-signature-v3'),
        nonce: options.nonce || getHeader(headers, 'x-plivo-signature-v3-nonce'),
      });
    case 'generic-hmac':
      return verifyHmacWebhook({
        ...options,
        rawBody,
        signature: options.signature || getHeader(headers, options.signatureHeader || 'x-webhook-signature'),
        timestamp: options.timestamp || (options.timestampHeader && getHeader(headers, options.timestampHeader)),
        requireTimestamp: options.requireTimestamp ?? Boolean(options.timestampHeader),
      });
    default:
      return invalid(String(provider || 'unknown'), 'UNSUPPORTED_PROVIDER', `Unsupported provider: ${provider}`);
  }
}

export async function secureWebhook(options = {}) {
  const signature = verifyProviderWebhook(options);
  const checks = { signature };
  if (!signature.valid) return { ...signature, checks };

  const normalized = normalizeSmsPayload(
    options.provider,
    options.body || options.params,
    options.payloadOptions?.fields,
  );
  if (options.payloadValidation !== false) {
    const payload = validateSmsPayload(normalized, options.payloadOptions);
    checks.payload = payload;
    if (!payload.valid) {
      return invalid(options.provider, 'INVALID_PAYLOAD', 'SMS payload validation failed.', {
        checks,
        errors: payload.errors,
        warnings: payload.warnings,
      });
    }
  }

  if (options.replayStore) {
    const eventId = options.eventId
      || normalized?.eventId
      || (options.provider === 'plivo' ? signature.nonce : undefined);
    const replay = await protectAgainstReplay({
      provider: options.provider,
      store: options.replayStore,
      ttlMs: options.replayTtlMs,
      rawBody: options.rawBody || '',
      signature: options.signature || '',
      eventId,
      now: options.now,
    });
    checks.replay = replay;
    if (!replay.valid) return { ...replay, provider: options.provider, checks };
  }

  return valid(options.provider, {
    message: 'Webhook passed all enabled security checks.',
    checks,
    normalizedPayload: normalized,
    warnings: checks.payload?.warnings || [],
  });
}
