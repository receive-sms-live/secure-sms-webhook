const E164 = /^\+[1-9]\d{1,14}$/;
const SAFE_TEXT = /^[^\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]*$/u;

const PROVIDER_FIELDS = {
  twilio: { from: 'From', to: 'To', body: 'Body', eventId: 'MessageSid' },
  plivo: { from: 'From', to: 'To', body: 'Text', eventId: 'MessageUUID' },
  vonage: { from: 'msisdn', to: 'to', body: 'text', eventId: 'messageId' },
  'generic-hmac': { from: 'From', to: 'To', body: 'Body', eventId: 'eventId' },
};

export function normalizeSmsPayload(provider, payload, customFields = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  if (provider === 'telnyx') {
    const event = payload.data || {};
    const message = event.payload || {};
    return {
      from: message.from?.phone_number,
      to: Array.isArray(message.to) ? message.to[0]?.phone_number : message.to?.phone_number,
      body: message.text,
      eventId: event.id,
      original: payload,
    };
  }
  const fields = { ...(PROVIDER_FIELDS[provider] || PROVIDER_FIELDS['generic-hmac']), ...customFields };
  return {
    from: payload[fields.from],
    to: payload[fields.to],
    body: payload[fields.body],
    eventId: payload[fields.eventId],
    original: payload,
  };
}

export function validateSmsPayload(payload, options = {}) {
  const {
    maxBodyLength = 5000,
    requireFrom = true,
    requireTo = true,
    requireBody = true,
    allowAlphanumericSender = false,
    knownFields,
    warnUnknown = false,
  } = options;
  const errors = [];
  const warnings = [];

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      valid: false,
      errors: [{ field: '$', code: 'INVALID_PAYLOAD', message: 'Payload must be an object.' }],
      warnings,
    };
  }

  const checkPhone = (field, value, required, alphanumeric = false) => {
    if (value === undefined || value === null || value === '') {
      if (required) errors.push({ field, code: 'REQUIRED', message: `${field} is required.` });
      return;
    }
    if (typeof value !== 'string') {
      errors.push({ field, code: 'INVALID_TYPE', message: `${field} must be a string.` });
      return;
    }
    if (!E164.test(value) && !(alphanumeric && /^[A-Za-z0-9 ]{1,15}$/.test(value))) {
      errors.push({ field, code: 'INVALID_E164', message: `${field} must be an E.164 phone number.` });
    }
  };

  checkPhone('from', payload.from, requireFrom, allowAlphanumericSender);
  checkPhone('to', payload.to, requireTo, false);

  if (payload.body === undefined || payload.body === null) {
    if (requireBody) errors.push({ field: 'body', code: 'REQUIRED', message: 'body is required.' });
  } else if (typeof payload.body !== 'string') {
    errors.push({ field: 'body', code: 'INVALID_TYPE', message: 'body must be a string.' });
  } else {
    if (payload.body.length > maxBodyLength) {
      errors.push({
        field: 'body',
        code: 'TOO_LONG',
        message: `body exceeds ${maxBodyLength} characters.`,
      });
    }
    if (!SAFE_TEXT.test(payload.body)) {
      errors.push({ field: 'body', code: 'CONTROL_CHARACTERS', message: 'body contains unsafe control characters.' });
    }
  }

  if (warnUnknown && knownFields && payload.original) {
    const allowed = new Set(knownFields);
    for (const key of Object.keys(payload.original)) {
      if (!allowed.has(key)) {
        warnings.push({ field: key, code: 'UNKNOWN_FIELD', message: `Unknown field: ${key}` });
      }
    }
  }
  return { valid: errors.length === 0, errors, warnings };
}

export { E164 as E164_PATTERN };
