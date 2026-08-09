#!/usr/bin/env node

import { createPrivateKey } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import {
  createHmacSignature,
  createPlivoSignature,
  createTelnyxTestSignature,
  createTwilioSignature,
  createVonageSignature,
} from '../src/index.js';

const PROVIDERS = new Set(['generic-hmac', 'twilio', 'telnyx', 'vonage', 'plivo']);

function parseArgs(argv) {
  const options = { command: argv[0] || 'help' };
  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [rawKey, inlineValue] = arg.slice(2).split('=', 2);
    const key = rawKey.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (inlineValue !== undefined) options[key] = inlineValue;
    else if (argv[index + 1] && !argv[index + 1].startsWith('--')) options[key] = argv[++index];
    else options[key] = true;
  }
  return options;
}

function help() {
  console.log(`Secure SMS Webhook Validator

Usage:
  npx secure-sms-webhook test --url http://127.0.0.1:3000/webhooks/sms \\
    --provider generic-hmac --acknowledge-staging

Providers:
  generic-hmac, twilio, telnyx, vonage, plivo

Credential environment variables (never command-line arguments):
  SECURE_SMS_WEBHOOK_TEST_SECRET  Generic HMAC
  TWILIO_AUTH_TOKEN               Twilio
  TELNYX_TEST_PRIVATE_KEY         Telnyx test-only private key (PEM)
  VONAGE_SIGNATURE_SECRET         Vonage HMAC-SHA256
  PLIVO_AUTH_TOKEN                Plivo V3

Safety:
  Version 0.1 only tests explicit localhost/loopback staging endpoints.
  It does not scan, discover targets, follow redirects, or test public hosts.`);
}

function assertLoopback(target) {
  let url;
  try {
    url = new URL(target);
  } catch {
    throw new Error('Webhook URL is invalid.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Webhook URL must use http or https.');
  const allowed = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
  if (!allowed.has(url.hostname)) {
    throw new Error('Remote targets are disabled. Use an explicit localhost or loopback URL.');
  }
  if (url.username || url.password) throw new Error('Credentials in webhook URLs are not allowed.');
  return url.toString();
}

function statusClass(status) {
  if (status >= 200 && status < 300) return 'accepted';
  if ([400, 401, 403, 409, 422].includes(status)) return 'rejected';
  return 'unexpected';
}

async function send(target, request) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(target, {
      method: 'POST',
      redirect: 'manual',
      signal: controller.signal,
      ...request,
    });
    return {
      status: response.status,
      result: response.headers.get('x-secure-sms-webhook-result'),
      replay: response.headers.get('x-secure-sms-webhook-replay'),
    };
  } finally {
    clearTimeout(timer);
  }
}

function providerCredential(provider) {
  switch (provider) {
    case 'generic-hmac': return process.env.SECURE_SMS_WEBHOOK_TEST_SECRET;
    case 'twilio': return process.env.TWILIO_AUTH_TOKEN;
    case 'telnyx': return process.env.TELNYX_TEST_PRIVATE_KEY;
    case 'vonage': return process.env.VONAGE_SIGNATURE_SECRET;
    case 'plivo': return process.env.PLIVO_AUTH_TOKEN;
    default: return undefined;
  }
}

function buildPayload(provider, eventId, override = {}) {
  if (provider === 'telnyx') {
    return {
      data: {
        id: eventId,
        event_type: 'message.received',
        payload: {
          from: { phone_number: '+12125550123' },
          to: [{ phone_number: '+13105550123' }],
          text: 'Secure SMS Webhook local test',
          ...override,
        },
      },
    };
  }
  const mappings = {
    'generic-hmac': { From: '+12125550123', To: '+13105550123', Body: 'Secure SMS Webhook local test', eventId },
    twilio: { From: '+12125550123', To: '+13105550123', Body: 'Secure SMS Webhook local test', MessageSid: eventId },
    vonage: { msisdn: '+12125550123', to: '+13105550123', text: 'Secure SMS Webhook local test', messageId: eventId },
    plivo: { From: '+12125550123', To: '+13105550123', Text: 'Secure SMS Webhook local test', MessageUUID: eventId },
  };
  return { ...mappings[provider], ...override };
}

function buildRequest(provider, target, payload, credential, mode = 'valid') {
  const timestamp = Math.floor(Date.now() / 1000);
  if (provider === 'generic-hmac') {
    const rawBody = JSON.stringify(payload);
    const signature = mode === 'valid'
      ? createHmacSignature({ rawBody, secret: credential })
      : '00'.repeat(32);
    return {
      headers: {
        'content-type': 'application/json',
        ...(mode === 'unsigned' ? {} : { 'x-webhook-signature': signature }),
      },
      body: rawBody,
    };
  }
  if (provider === 'twilio') {
    const body = new URLSearchParams(payload).toString();
    const signature = mode === 'valid'
      ? createTwilioSignature({ url: target, params: payload, authToken: credential })
      : Buffer.alloc(20).toString('base64');
    return {
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(mode === 'unsigned' ? {} : { 'x-twilio-signature': signature }),
      },
      body,
    };
  }
  if (provider === 'telnyx') {
    const rawBody = JSON.stringify(payload);
    const privateKey = mode === 'valid'
      ? createPrivateKey(String(credential).replace(/\\n/g, '\n'))
      : null;
    const signature = mode === 'valid'
      ? createTelnyxTestSignature({ rawBody, timestamp, privateKey })
      : Buffer.alloc(64).toString('base64');
    return {
      headers: {
        'content-type': 'application/json',
        ...(mode === 'unsigned' ? {} : {
          'telnyx-signature-ed25519': signature,
          'telnyx-timestamp': String(timestamp),
        }),
      },
      body: rawBody,
    };
  }
  if (provider === 'vonage') {
    const params = { ...payload, timestamp: String(timestamp) };
    if (mode !== 'unsigned') {
      params.sig = mode === 'valid'
        ? createVonageSignature({ params, secret: credential, algorithm: 'sha256' })
        : '00'.repeat(32);
    }
    return {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params).toString(),
    };
  }
  const nonce = `${Date.now()}-${payload.MessageUUID}`;
  const signature = mode === 'valid'
    ? createPlivoSignature({ url: target, params: payload, nonce, authToken: credential })
    : Buffer.alloc(32).toString('base64');
  return {
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(mode === 'unsigned' ? {} : {
        'x-plivo-signature-v3': signature,
        'x-plivo-signature-v3-nonce': nonce,
      }),
    },
    body: new URLSearchParams(payload).toString(),
  };
}

function resultLine(level, text, detail = '') {
  const symbols = { pass: '✓', fail: '✗', warning: '!', skipped: '–' };
  console.log(`[${symbols[level]}] ${text}${detail ? ` — ${detail}` : ''}`);
}

async function runTests(target, provider, credential) {
  const results = [];
  const record = (level, name, detail) => {
    results.push({ level, name, detail });
    resultLine(level, name, detail);
  };
  const baseId = `SMSTEST${Date.now()}`;
  const payload = buildPayload(provider, `${baseId}A`);

  const unsigned = await send(target, buildRequest(provider, target, payload, credential || 'test', 'unsigned'));
  record(
    statusClass(unsigned.status) === 'rejected' ? 'pass' : 'fail',
    'Missing signature rejected',
    `HTTP ${unsigned.status}`,
  );

  const invalid = await send(target, buildRequest(provider, target, payload, credential || 'test', 'invalid'));
  record(
    statusClass(invalid.status) === 'rejected' ? 'pass' : 'fail',
    'Invalid signature rejected',
    `HTTP ${invalid.status}`,
  );

  if (!credential) {
    record('skipped', 'Valid signature accepted', 'provider test credential environment variable is not set');
    record('skipped', 'Invalid phone number rejected', 'requires a valid test signature');
    record('skipped', 'Replay protection observed', 'requires a valid test signature');
    record('skipped', 'Payload size limit observed', 'requires a valid test signature');
    return results;
  }

  const accepted = await send(target, buildRequest(provider, target, payload, credential, 'valid'));
  record(
    statusClass(accepted.status) === 'accepted' ? 'pass' : 'fail',
    'Valid signature accepted',
    `HTTP ${accepted.status}`,
  );

  const invalidPhonePayload = buildPayload(provider, `${baseId}B`, provider === 'telnyx'
    ? { from: { phone_number: 'not-a-phone' } }
    : provider === 'vonage'
      ? { msisdn: 'not-a-phone' }
      : { From: 'not-a-phone' });
  const invalidPhone = await send(target, buildRequest(provider, target, invalidPhonePayload, credential, 'valid'));
  record(
    statusClass(invalidPhone.status) === 'rejected' ? 'pass' : 'fail',
    'Invalid phone number rejected',
    `HTTP ${invalidPhone.status}`,
  );

  const replayPayload = buildPayload(provider, `${baseId}C`);
  const replayRequest = buildRequest(provider, target, replayPayload, credential, 'valid');
  const replayFirst = await send(target, replayRequest);
  const replaySecond = await send(target, replayRequest);
  if (replayFirst.status >= 200 && replayFirst.status < 300
      && (replaySecond.replay === 'rejected' || replaySecond.status === 409)) {
    record('pass', 'Replay protection observed', `HTTP ${replayFirst.status} then ${replaySecond.status}`);
  } else if (replayFirst.status >= 200 && replayFirst.status < 300
      && replaySecond.status >= 200 && replaySecond.status < 300) {
    record('warning', 'Replay protection inconclusive', 'duplicate returned 2xx; verify that side effects occurred only once');
  } else {
    record('warning', 'Replay protection inconclusive', `HTTP ${replayFirst.status} then ${replaySecond.status}`);
  }

  const largeText = 'A'.repeat(70 * 1024);
  const largePayload = buildPayload(provider, `${baseId}D`, provider === 'telnyx'
    ? { text: largeText }
    : provider === 'plivo'
      ? { Text: largeText }
      : provider === 'vonage'
        ? { text: largeText }
        : { Body: largeText });
  try {
    const large = await send(target, buildRequest(provider, target, largePayload, credential, 'valid'));
    record(
      large.status === 413 ? 'pass' : 'warning',
      'Payload size limit observed',
      large.status === 413 ? 'HTTP 413' : `HTTP ${large.status}; configure a pre-parser byte limit`,
    );
  } catch (error) {
    record('warning', 'Payload size limit inconclusive', error.name === 'AbortError' ? 'request timed out' : error.message);
  }
  return results;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.command !== 'test') {
    help();
    process.exitCode = args.command === 'help' || args.help ? 0 : 1;
    return;
  }

  let target = args.url;
  let provider = args.provider;
  let acknowledged = Boolean(args.acknowledgeStaging);
  if ((!target || !provider || !acknowledged) && input.isTTY) {
    const rl = createInterface({ input, output });
    target ||= await rl.question('Webhook URL (localhost only): ');
    provider ||= (await rl.question('Provider [generic-hmac]: ')) || 'generic-hmac';
    if (!acknowledged) {
      const answer = await rl.question('Type STAGING to confirm this is your non-production endpoint: ');
      acknowledged = answer === 'STAGING';
    }
    rl.close();
  }
  if (!acknowledged) throw new Error('Use --acknowledge-staging after confirming the endpoint is non-production and yours.');
  if (!PROVIDERS.has(provider)) throw new Error(`Unsupported provider: ${provider}`);
  target = assertLoopback(target);
  const credential = providerCredential(provider);

  console.log(`\nSecure SMS Webhook Validator\nTarget: ${target}\nProvider: ${provider}\n`);
  const results = await runTests(target, provider, credential);
  const counts = results.reduce((total, item) => {
    total[item.level] = (total[item.level] || 0) + 1;
    return total;
  }, {});
  console.log(`\nSecurity report\nPASS ${counts.pass || 0}  WARNING ${counts.warning || 0}  FAIL ${counts.fail || 0}  SKIPPED ${counts.skipped || 0}`);
  if (counts.fail) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
});
