import { secureWebhook } from 'secure-sms-webhook';

export async function POST(request) {
  const rawBody = await request.text();
  const body = JSON.parse(rawBody);
  const result = await secureWebhook({
    provider: 'generic-hmac',
    url: request.url,
    headers: request.headers,
    rawBody,
    body,
    secret: process.env.WEBHOOK_SECRET,
    replayStore: globalThis.replayStore, // Replace with an atomic shared store.
  });
  if (!result.valid) {
    return Response.json({ error: 'Invalid webhook', code: result.code }, { status: 403 });
  }
  return new Response(null, { status: 204 });
}
