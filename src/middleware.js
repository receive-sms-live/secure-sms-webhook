import { secureWebhook } from './guard.js';

function defaultPublicUrl(req) {
  const protocol = req.protocol || (req.socket?.encrypted ? 'https' : 'http');
  const host = typeof req.get === 'function' ? req.get('host') : req.headers?.host;
  return `${protocol}://${host}${req.originalUrl || req.url || ''}`;
}

function resolveConfig(value, req) {
  return typeof value === 'function' ? value(req) : value;
}

export function captureRawBody(req, _res, buffer) {
  req.rawBody = Buffer.from(buffer);
}

export function createExpressMiddleware(config = {}) {
  if (!config.provider) throw new TypeError('provider is required.');
  return async function secureSmsWebhookMiddleware(req, res, next) {
    const rawBody = req.rawBody
      ?? (typeof req.body === 'string' || Buffer.isBuffer(req.body)
        ? req.body
        : JSON.stringify(req.body || {}));
    const contentType = req.get?.('content-type') || req.headers?.['content-type'] || '';
    const options = {
      ...config,
      provider: config.provider,
      url: resolveConfig(config.publicUrl, req) || defaultPublicUrl(req),
      headers: req.headers,
      rawBody,
      body: req.body,
      params: contentType.includes('application/x-www-form-urlencoded') ? req.body : config.params,
      contentType,
      authToken: resolveConfig(config.authToken, req),
      secret: resolveConfig(config.secret, req),
      publicKey: resolveConfig(config.publicKey, req),
    };

    const result = await secureWebhook(options);
    req.secureSmsWebhook = result;
    if (!result.valid) {
      const replay = result.code === 'REPLAY_DETECTED';
      res.set?.('x-secure-sms-webhook-result', result.code);
      if (replay) res.set?.('x-secure-sms-webhook-replay', 'rejected');
      return res.status(replay ? (config.replayStatus || 409) : (config.invalidStatus || 403)).json({
        error: 'Invalid webhook',
        code: result.code,
      });
    }
    return next();
  };
}
