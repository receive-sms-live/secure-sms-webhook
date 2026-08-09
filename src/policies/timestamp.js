import { invalid, valid } from '../internal.js';

export function validateTimestamp(options = {}) {
  const {
    timestamp,
    maxAgeSeconds = 300,
    maxFutureSkewSeconds = 30,
    now = Date.now(),
  } = options;
  const seconds = Number(timestamp);
  if (!Number.isFinite(seconds)) {
    return invalid('timestamp', 'INVALID_TIMESTAMP', 'Timestamp must be Unix seconds.');
  }
  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) {
    return invalid('timestamp', 'CONFIGURATION_ERROR', 'maxAgeSeconds must be a non-negative number.');
  }
  if (!Number.isFinite(maxFutureSkewSeconds) || maxFutureSkewSeconds < 0) {
    return invalid('timestamp', 'CONFIGURATION_ERROR', 'maxFutureSkewSeconds must be a non-negative number.');
  }

  const ageSeconds = Math.floor(now / 1000) - seconds;
  if (ageSeconds > maxAgeSeconds) {
    return invalid('timestamp', 'TIMESTAMP_TOO_OLD', 'Webhook timestamp is outside the allowed age.', {
      ageSeconds,
      maxAgeSeconds,
    });
  }
  if (ageSeconds < -maxFutureSkewSeconds) {
    return invalid('timestamp', 'TIMESTAMP_IN_FUTURE', 'Webhook timestamp is too far in the future.', {
      ageSeconds,
      maxFutureSkewSeconds,
    });
  }
  return valid('timestamp', { ageSeconds, timestamp: seconds });
}
