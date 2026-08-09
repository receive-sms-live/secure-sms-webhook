import { verifyHmacWebhook } from 'secure-sms-webhook';

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
    const rawBody = await request.text();
    const result = verifyHmacWebhook({
      rawBody,
      signature: request.headers.get('x-webhook-signature'),
      secret: env.WEBHOOK_SECRET,
    });
    if (!result.valid) return new Response('Invalid webhook', { status: 403 });

    // Use Durable Objects or another atomic shared store for replay protection.
    return new Response(null, { status: 204 });
  },
};
