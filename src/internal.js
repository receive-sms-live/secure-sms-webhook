import {
  createHash,
  createHmac,
  createPublicKey,
  timingSafeEqual,
} from 'node:crypto';

export const SUPPORTED_HMAC_ALGORITHMS = new Set([
  'sha1',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
]);

export function valid(provider, extra = {}) {
  return {
    valid: true,
    provider,
    code: 'VALID',
    message: 'Webhook signature is valid.',
    ...extra,
  };
}

export function invalid(provider, code, message, extra = {}) {
  return { valid: false, provider, code, message, ...extra };
}

export function asBuffer(value, name = 'value') {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new TypeError(`${name} must be a string or Buffer.`);
}

export function requireNonEmptyString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string.`);
  }
  return value;
}

export function normalizeAlgorithm(algorithm, allowed = SUPPORTED_HMAC_ALGORITHMS) {
  const normalized = String(algorithm || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!allowed.has(normalized)) {
    throw new TypeError(`Unsupported signature algorithm: ${algorithm}`);
  }
  return normalized;
}

export function hmacBytes(algorithm, secret, data) {
  return createHmac(normalizeAlgorithm(algorithm), asBuffer(secret, 'secret'))
    .update(asBuffer(data, 'data'))
    .digest();
}

export function hashBytes(algorithm, data) {
  return createHash(algorithm).update(asBuffer(data, 'data')).digest();
}

export function constantTimeEqual(left, right) {
  const a = asBuffer(left, 'left');
  const b = asBuffer(right, 'right');
  if (a.length === b.length) return timingSafeEqual(a, b);

  // Keep the mismatch path comparable without calling timingSafeEqual on
  // unequal-length inputs. Signature lengths themselves are not secret.
  timingSafeEqual(hashBytes('sha256', a), hashBytes('sha256', b));
  return false;
}

export function decodeSignature(value, encoding = 'hex', prefix = '') {
  if (typeof value !== 'string' || value.length === 0) return null;
  let normalized = value.trim();
  if (prefix) {
    if (!normalized.toLowerCase().startsWith(prefix.toLowerCase())) return null;
    normalized = normalized.slice(prefix.length);
  }

  try {
    if (encoding === 'hex') {
      if (!/^[a-f0-9]+$/i.test(normalized) || normalized.length % 2 !== 0) return null;
      return Buffer.from(normalized, 'hex');
    }
    if (encoding === 'base64') {
      if (!/^[a-z0-9+/]+={0,2}$/i.test(normalized)) return null;
      return Buffer.from(normalized, 'base64');
    }
    if (encoding === 'base64url') {
      if (!/^[a-z0-9_-]+$/i.test(normalized)) return null;
      return Buffer.from(normalized, 'base64url');
    }
  } catch {
    return null;
  }
  throw new TypeError(`Unsupported signature encoding: ${encoding}`);
}

export function encodeSignature(bytes, encoding = 'hex') {
  if (!['hex', 'base64', 'base64url'].includes(encoding)) {
    throw new TypeError(`Unsupported signature encoding: ${encoding}`);
  }
  return asBuffer(bytes).toString(encoding);
}

export function canonicalPairs(params, options = {}) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new TypeError('params must be an object.');
  }
  const {
    exclude = [],
    prefix = '',
    separator = '',
    assignment = '',
    sanitizeValue = (value) => String(value),
  } = options;
  const excluded = new Set(exclude);
  const parts = [];

  for (const key of Object.keys(params).filter((item) => !excluded.has(item)).sort()) {
    const values = Array.isArray(params[key]) ? [...params[key]].sort() : [params[key]];
    for (const value of values) {
      parts.push(`${key}${assignment}${sanitizeValue(value ?? '')}`);
    }
  }
  return prefix + parts.join(separator);
}

export function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return undefined;
}

export function ed25519PublicKey(value) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value)) {
    throw new TypeError('publicKey must be a PEM string or Base64-encoded Ed25519 key.');
  }
  if (typeof value === 'string' && value.includes('BEGIN PUBLIC KEY')) {
    return createPublicKey(value);
  }

  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value.trim(), 'base64');
  if (bytes.length === 32) {
    return createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: bytes.toString('base64url') },
      format: 'jwk',
    });
  }
  return createPublicKey({ key: bytes, format: 'der', type: 'spki' });
}

export function configurationFailure(provider, error) {
  return invalid(
    provider,
    'CONFIGURATION_ERROR',
    error instanceof Error ? error.message : String(error),
  );
}
