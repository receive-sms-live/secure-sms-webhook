import { createHash } from 'node:crypto';
import { asBuffer, invalid, valid } from './internal.js';

export class MemoryReplayStore {
  #entries = new Map();

  constructor(options = {}) {
    const { maxEntries = 10_000 } = options;
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new TypeError('maxEntries must be a positive integer.');
    }
    this.maxEntries = maxEntries;
  }

  async claim(key, ttlMs, now = Date.now()) {
    if (typeof key !== 'string' || key.length === 0) throw new TypeError('Replay key is required.');
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new TypeError('ttlMs must be positive.');
    this.#prune(now);
    const expiresAt = this.#entries.get(key);
    if (expiresAt && expiresAt > now) return false;
    if (this.#entries.size >= this.maxEntries) {
      const oldest = this.#entries.keys().next().value;
      if (oldest !== undefined) this.#entries.delete(oldest);
    }
    this.#entries.set(key, now + ttlMs);
    return true;
  }

  async delete(key) {
    return this.#entries.delete(key);
  }

  get size() {
    return this.#entries.size;
  }

  #prune(now) {
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt <= now) this.#entries.delete(key);
    }
  }
}

export function createReplayKey(options = {}) {
  const { provider = 'unknown', eventId, rawBody = '', signature = '' } = options;
  const fingerprint = eventId
    ? `event:${String(eventId)}`
    : `request:${createHash('sha256')
        .update(asBuffer(rawBody, 'rawBody'))
        .update('\0')
        .update(String(signature))
        .digest('hex')}`;
  return `${provider}:${fingerprint}`;
}

export async function protectAgainstReplay(options = {}) {
  const {
    store,
    ttlMs = 300_000,
    now = Date.now(),
  } = options;
  if (!store || typeof store.claim !== 'function') {
    return invalid('replay', 'CONFIGURATION_ERROR', 'Replay store must implement async claim(key, ttlMs, now).');
  }
  try {
    const key = createReplayKey(options);
    const claimed = await store.claim(key, ttlMs, now);
    if (!claimed) {
      return invalid('replay', 'REPLAY_DETECTED', 'Request has already been processed.', { key });
    }
    return valid('replay', { key, ttlMs });
  } catch (error) {
    return invalid('replay', 'REPLAY_STORE_ERROR', error instanceof Error ? error.message : String(error));
  }
}
