import {
  canonicalPairs,
  configurationFailure,
  constantTimeEqual,
  decodeSignature,
  hmacBytes,
  invalid,
  requireNonEmptyString,
  valid,
} from '../internal.js';

function sortedQuery(entries) {
  const grouped = new Map();
  for (const [key, value] of entries) {
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(String(value));
  }
  const pairs = [];
  for (const key of [...grouped.keys()].sort()) {
    for (const value of grouped.get(key).sort()) {
      pairs.push(`${key}=${value}`);
    }
  }
  return pairs.join('&');
}

function canonicalPlivoBase(url, params, method) {
  const parsed = new URL(url);
  const base = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  const queryEntries = [...parsed.searchParams.entries()];
  if (method === 'GET') {
    for (const [key, value] of Object.entries(params)) {
      const values = Array.isArray(value) ? value : [value];
      for (const item of values) queryEntries.push([key, item ?? '']);
    }
    const query = sortedQuery(queryEntries);
    return query ? `${base}?${query}` : base;
  }

  const query = sortedQuery(queryEntries);
  const post = canonicalPairs(params);
  if (!query && !post) return base;
  if (!query) return `${base}?${post}`;
  return post ? `${base}?${query}.${post}` : `${base}?${query}`;
}

export function createPlivoSignature({ url, params = {}, nonce, authToken, method = 'POST' }) {
  requireNonEmptyString(url, 'url');
  requireNonEmptyString(nonce, 'nonce');
  requireNonEmptyString(authToken, 'authToken');
  const normalizedMethod = String(method).toUpperCase();
  if (!['GET', 'POST'].includes(normalizedMethod)) {
    throw new TypeError('Plivo method must be GET or POST.');
  }
  const canonical = `${canonicalPlivoBase(url, params, normalizedMethod)}.${nonce}`;
  return hmacBytes('sha256', authToken, canonical).toString('base64');
}

export function verifyPlivoWebhook(options) {
  const provider = 'plivo';
  try {
    const { signature, nonce } = options || {};
    if (!signature) return invalid(provider, 'MISSING_SIGNATURE', 'X-Plivo-Signature-V3 is missing.');
    if (!nonce) return invalid(provider, 'MISSING_NONCE', 'X-Plivo-Signature-V3-Nonce is missing.');
    const expected = decodeSignature(createPlivoSignature(options), 'base64');
    const candidates = String(signature).split(',').map((value) => value.trim()).filter(Boolean);
    let malformed = true;
    for (const candidate of candidates) {
      const received = decodeSignature(candidate, 'base64');
      if (!received) continue;
      malformed = false;
      if (constantTimeEqual(received, expected)) return valid(provider, { nonce });
    }
    if (malformed) return invalid(provider, 'MALFORMED_SIGNATURE', 'Plivo signature is not valid Base64.');
    return invalid(provider, 'INVALID_SIGNATURE', 'Plivo signature does not match.');
  } catch (error) {
    return configurationFailure(provider, error);
  }
}
