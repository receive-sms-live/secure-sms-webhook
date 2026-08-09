import express from 'express';
import {
  captureRawBody,
  createExpressMiddleware,
  MemoryReplayStore,
  redactWebhook,
} from 'secure-sms-webhook';

const app = express();
const replayStore = new MemoryReplayStore();

app.use(express.json({ limit: '64kb', verify: captureRawBody }));

app.post('/webhooks/sms', createExpressMiddleware({
  provider: 'generic-hmac',
  secret: () => process.env.WEBHOOK_SECRET,
  replayStore,
}), (req, res) => {
  console.log('Verified SMS:', redactWebhook(req.secureSmsWebhook.normalizedPayload));
  res.sendStatus(204);
});

app.listen(3000, '127.0.0.1', () => {
  console.log('Local example: http://127.0.0.1:3000/webhooks/sms');
});
