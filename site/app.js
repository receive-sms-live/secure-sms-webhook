const form = document.querySelector('#generator-form');
const provider = document.querySelector('#provider');
const language = document.querySelector('#language');
const urlInput = document.querySelector('#webhook-url');
const code = document.querySelector('#generated-code');
const codeLabel = document.querySelector('#code-label');
const codeNote = document.querySelector('#code-note');

const labels = { twilio: 'Twilio', telnyx: 'Telnyx', vonage: 'Vonage', plivo: 'Plivo', generic: 'Generic HMAC' };
const langLabels = { node: 'Node.js', python: 'Python', php: 'PHP' };

function safeUrl() {
  try {
    const parsed = new URL(urlInput.value);
    return ['https:', 'http:'].includes(parsed.protocol)
      ? parsed.toString().replaceAll("'", '%27').replaceAll('\\', '%5C')
      : 'https://example.com/webhooks/sms';
  } catch {
    return 'https://example.com/webhooks/sms';
  }
}

function selected(id) { return document.querySelector(`#${id}`).checked; }

function nodeExample(name, url) {
  const config = [];
  if (selected('replay')) config.push('  replayStore,', '  replayTtlMs: 10 * 60 * 1000,');
  if (!selected('payload')) config.push('  payloadValidation: false,');
  const setup = selected('replay')
    ? "const replayStore = new MemoryReplayStore(); // Use an atomic shared store in production.\n"
    : '';
  const imports = ['captureRawBody', 'createExpressMiddleware'];
  if (selected('replay')) imports.push('MemoryReplayStore');
  if (selected('redaction')) imports.push('redactWebhook');
  const providerConfig = {
    twilio: "  provider: 'twilio',\n  authToken: () => process.env.TWILIO_AUTH_TOKEN,",
    telnyx: "  provider: 'telnyx',\n  publicKey: () => process.env.TELNYX_PUBLIC_KEY,",
    vonage: "  provider: 'vonage',\n  secret: () => process.env.VONAGE_SIGNATURE_SECRET,\n  algorithm: 'sha256',",
    plivo: "  provider: 'plivo',\n  authToken: () => process.env.PLIVO_AUTH_TOKEN,",
    generic: "  provider: 'generic-hmac',\n  secret: () => process.env.WEBHOOK_SECRET,",
  }[name];
  const timestamp = selected('timestamp') && name === 'generic'
    ? "\n  timestampHeader: 'x-webhook-timestamp',\n  maxAgeSeconds: 300,"
    : '';
  const log = selected('redaction')
    ? "  console.log(redactWebhook(req.secureSmsWebhook.normalizedPayload));\n"
    : '';
  return `import express from 'express';
import { ${imports.join(', ')} } from 'secure-sms-webhook';

const app = express();
${setup}
app.use(express.json({ limit: '64kb', verify: captureRawBody }));
app.use(express.urlencoded({ extended: false, limit: '64kb', verify: captureRawBody }));

app.post('/webhooks/sms', createExpressMiddleware({
${providerConfig}
  publicUrl: '${url}',${timestamp}
${config.join('\n')}
}), (req, res) => {
${log}  // Process the verified SMS exactly once.
  res.sendStatus(204);
});`;
}

function pythonExample(name, url) {
  const providerLines = {
    twilio: `validator = RequestValidator(os.environ["TWILIO_AUTH_TOKEN"])
valid = validator.validate("${url}", dict(request.form), request.headers.get("X-Twilio-Signature", ""))`,
    telnyx: `event = telnyx.Webhook.construct_event(
    raw_body,
    request.headers.get("telnyx-signature-ed25519"),
    request.headers.get("telnyx-timestamp"),
)\nvalid = bool(event)`,
    vonage: `# Enable signed inbound SMS and prefer HMAC-SHA256 in the Vonage dashboard.
valid = vonage_client.http_client.auth.check_signature(dict(request.form))`,
    plivo: `valid = plivo.utils.validate_v3_signature(
    request.method, "${url}",
    request.headers.get("X-Plivo-Signature-V3-Nonce", ""),
    os.environ["PLIVO_AUTH_TOKEN"],
    request.headers.get("X-Plivo-Signature-V3", ""), dict(request.form),
)`,
    generic: `expected = hmac.new(
    os.environ["WEBHOOK_SECRET"].encode(), raw_body, hashlib.sha256
).hexdigest()
valid = hmac.compare_digest(expected, request.headers.get("x-webhook-signature", ""))`,
  }[name];
  return `# Use the official provider SDK where available.
# Enforce a request-size limit before reading raw_body.
import os
${name === 'generic' ? 'import hashlib, hmac' : ''}

raw_body = await request.body()
${providerLines}

if not valid:
    return Response(status_code=403)

# Atomically claim the event ID before processing.
# Log only a redacted copy of the payload.
return Response(status_code=204)`;
}

function phpExample(name, url) {
  const providerLines = {
    twilio: `$validator = new Twilio\\Security\\RequestValidator(getenv('TWILIO_AUTH_TOKEN'));
$valid = $validator->validate($_SERVER['HTTP_X_TWILIO_SIGNATURE'] ?? '', '${url}', $_POST);`,
    telnyx: `$timestamp = $_SERVER['HTTP_TELNYX_TIMESTAMP'] ?? '';
$signature = base64_decode($_SERVER['HTTP_TELNYX_SIGNATURE_ED25519'] ?? '', true);
$publicKey = base64_decode(getenv('TELNYX_PUBLIC_KEY'), true);
$valid = $signature !== false && $publicKey !== false
    && sodium_crypto_sign_verify_detached($signature, $timestamp . '|' . $rawBody, $publicKey);`,
    vonage: `$signature = new Vonage\\Client\\Signature($_POST, getenv('VONAGE_SIGNATURE_SECRET'), 'sha256');
$valid = $signature->check($_POST['sig'] ?? '');`,
    plivo: `$validator = new Plivo\\Util\\v3SignatureValidation();
$valid = $validator->validateV3Signature(
    'POST', '${url}',
    $_SERVER['HTTP_X_PLIVO_SIGNATURE_V3_NONCE'] ?? '',
    getenv('PLIVO_AUTH_TOKEN'),
    $_SERVER['HTTP_X_PLIVO_SIGNATURE_V3'] ?? '', $_POST
);`,
    generic: `$expected = hash_hmac('sha256', $rawBody, getenv('WEBHOOK_SECRET'));
$valid = hash_equals($expected, $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '');`,
  }[name];
  return `<?php
// Enforce a byte limit before reading and parsing the request.
$rawBody = file_get_contents('php://input');
${providerLines}

if (!$valid) {
    http_response_code(403);
    exit('Invalid webhook');
}

// Atomically claim the event ID before processing.
// Log only redacted fields.
http_response_code(204);`;
}

function generate() {
  const name = provider.value;
  const lang = language.value;
  const url = safeUrl();
  const generated = lang === 'node' ? nodeExample(name, url) : lang === 'python' ? pythonExample(name, url) : phpExample(name, url);
  code.textContent = generated;
  codeLabel.textContent = `${langLabels[lang]} · ${labels[name]}`;
  codeNote.textContent = lang === 'node'
    ? 'Uses secure-sms-webhook. Keep secrets in environment variables and test in staging.'
    : 'Reference snippet using the provider SDK. Verify API names against its current release before production.';
}

form.addEventListener('submit', (event) => { event.preventDefault(); generate(); });
form.addEventListener('change', generate);
document.querySelector('#copy-code').addEventListener('click', async (event) => {
  await navigator.clipboard.writeText(code.textContent);
  const button = event.currentTarget;
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = 'Copy code'; }, 1300);
});
generate();
