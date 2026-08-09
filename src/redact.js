const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
const PHONE_PATTERN = /(?<!\w)\+[1-9]\d{7,14}(?!\w)/g;
const OTP_CONTEXT_PATTERN = /\b(otp|code|verification(?:\s+code)?|pin)\b([\s:=#-]*)([A-Z0-9][A-Z0-9-]{2,10})/giu;
const OTP_AR_CONTEXT_PATTERN = /(رمز(?:\s+التحقق)?|كود|رقم\s+التأكيد)([\s:=#-]*)([\p{L}\p{N}][\p{L}\p{N}-]{2,10})/gu;
const OTP_NUMERIC_PATTERN = /(?<!\d)\d{4,8}(?!\d)/g;
const PHONE_KEYS = /^(from|to|phone|phone_number|phonenumber|msisdn)$/i;

function maskPhone(phone) {
  if (phone.length < 9) return '[REDACTED_PHONE]';
  return `${phone.slice(0, 5)}***${phone.slice(-4)}`;
}

function redactString(value, options, key = '') {
  let output = value;
  const phoneField = PHONE_KEYS.test(key);
  if (options.phoneNumbers) {
    if (phoneField && PHONE_PATTERN.test(output)) {
      PHONE_PATTERN.lastIndex = 0;
      output = maskPhone(output);
    } else {
      PHONE_PATTERN.lastIndex = 0;
      output = output.replace(PHONE_PATTERN, (phone) => maskPhone(phone));
    }
  }
  if (options.email) output = output.replace(EMAIL_PATTERN, '[REDACTED_EMAIL]');
  if (options.otp && !phoneField) {
    output = output
      .replace(OTP_CONTEXT_PATTERN, '$1$2[REDACTED_OTP]')
      .replace(OTP_AR_CONTEXT_PATTERN, '$1$2[REDACTED_OTP]')
      .replace(OTP_NUMERIC_PATTERN, '[REDACTED_OTP]');
  }
  return output;
}

export function redactWebhook(value, options = {}) {
  const config = { phoneNumbers: true, otp: true, email: true, ...options };
  const seen = new WeakSet();

  const visit = (input, key = '') => {
    if (typeof input === 'string') return redactString(input, config, key);
    if (input === null || typeof input !== 'object') return input;
    if (seen.has(input)) return '[CIRCULAR]';
    seen.add(input);
    if (Array.isArray(input)) return input.map((item) => visit(item, key));
    const copy = {};
    for (const [childKey, childValue] of Object.entries(input)) {
      Object.defineProperty(copy, childKey, {
        value: visit(childValue, childKey),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return copy;
  };

  return visit(value);
}
