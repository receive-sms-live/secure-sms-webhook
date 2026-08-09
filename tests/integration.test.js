import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
  createExpressMiddleware,
  createHmacSignature,
  MemoryReplayStore,
  secureWebhook,
} from '../src/index.js';

test('secureWebhook combines signature, payload, and replay checks', async () => {
  const body = { From: '+12125550123', To: '+13105550123', Body: 'hello', eventId: 'evt-1' };
  const rawBody = JSON.stringify(body);
  const signature = createHmacSignature({ rawBody, secret: 'secret' });
  const replayStore = new MemoryReplayStore();
  const options = { provider: 'generic-hmac', body, rawBody, signature, secret: 'secret', replayStore };
  const first = await secureWebhook(options);
  const second = await secureWebhook(options);
  assert.equal(first.valid, true);
  assert.equal(first.normalizedPayload.from, '+12125550123');
  assert.equal(second.code, 'REPLAY_DETECTED');
});

test('secureWebhook stops at signature failure', async () => {
  const result = await secureWebhook({
    provider: 'generic-hmac', body: {}, rawBody: '{}', signature: '00'.repeat(32), secret: 'secret',
  });
  assert.equal(result.code, 'INVALID_SIGNATURE');
  assert.equal(result.checks.payload, undefined);
});

test('Express middleware rejects invalid request and annotates replay', async () => {
  const middleware = createExpressMiddleware({ provider: 'generic-hmac', secret: 'secret' });
  const req = {
    body: { From: '+12125550123', To: '+13105550123', Body: 'hello' },
    rawBody: Buffer.from('{"wrong":true}'),
    headers: { host: 'localhost', 'x-webhook-signature': '00'.repeat(32), 'content-type': 'application/json' },
    protocol: 'http', originalUrl: '/webhook',
    get(name) { return this.headers[name.toLowerCase()]; },
  };
  const response = {
    headers: {},
    set(name, value) { this.headers[name] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
  let nextCalled = false;
  await middleware(req, response, () => { nextCalled = true; });
  assert.equal(nextCalled, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.code, 'INVALID_SIGNATURE');
});

test('CLI refuses public targets before making a request', () => {
  const run = spawnSync(process.execPath, [
    'cli/tester.js', 'test', '--url', 'https://example.com/webhook', '--provider', 'generic-hmac', '--acknowledge-staging',
  ], { encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /Remote targets are disabled/);
});

test('CLI help exits successfully', () => {
  const run = spawnSync(process.execPath, ['cli/tester.js', '--help'], { encoding: 'utf8' });
  assert.equal(run.status, 0);
  assert.match(run.stdout, /Secure SMS Webhook Validator/);
});

test('documentation site is static, disclosed, and contains no secret form fields', () => {
  const html = readFileSync('site/index.html', 'utf8');
  assert.match(html, /Secure SMS Webhook Validator/);
  assert.match(html, /receive-smss\.live\/sms\/us/);
  assert.match(html, /maintained by the same team/i);
  assert.doesNotMatch(html, /type=["']password/);
  assert.doesNotMatch(html, /<input[^>]+name=["'][^"']*(secret|token|key)/i);
});

test('package surface does not contain placeholder runtime imports', () => {
  const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
  assert.equal(packageJson.name, 'secure-sms-webhook');
  assert.equal(packageJson.dependencies, undefined);
  assert.equal(packageJson.scripts.postinstall, undefined);
  assert.deepEqual(packageJson.files, ['src', 'cli', 'README.md', 'SECURITY.md', 'LICENSE']);
});
