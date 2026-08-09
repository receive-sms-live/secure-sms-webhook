import {
  createExpressMiddleware,
  createHmacSignature,
  MemoryReplayStore,
  normalizeSmsPayload,
  protectAgainstReplay,
  redactWebhook,
  secureWebhook,
  validateSmsPayload,
  verifyTwilioWebhook,
  type Provider,
  type VerificationResult,
} from '../src/index.js';

const provider: Provider = 'generic-hmac';
const rawBody = Buffer.from('{"From":"+12125550123"}');
const signature: string = createHmacSignature({ rawBody, secret: 'test' });
const store = new MemoryReplayStore({ maxEntries: 100 });

const verification: Promise<VerificationResult> = secureWebhook({
  provider,
  rawBody,
  body: { From: '+12125550123', To: '+13105550123', Body: 'hello' },
  signature,
  secret: 'test',
  replayStore: store,
});

const replay: Promise<VerificationResult> = protectAgainstReplay({
  provider,
  rawBody,
  signature,
  store,
});

const twilio: VerificationResult = verifyTwilioWebhook({
  url: 'https://example.com/webhook',
  params: { From: '+12125550123' },
  signature: 'placeholder',
  authToken: 'test',
});

const normalized = normalizeSmsPayload('twilio', {
  From: '+12125550123',
  To: '+13105550123',
  Body: 'hello',
});
if (normalized) validateSmsPayload(normalized);

const redacted = redactWebhook({ From: '+12125550123', Body: 'OTP 123456' });
redacted.Body.toUpperCase();
createExpressMiddleware({ provider: 'twilio', authToken: 'test' });

void verification;
void replay;
void twilio;
