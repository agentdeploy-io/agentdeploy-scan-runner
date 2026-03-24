/**
 * Security utility for redacting sensitive information from logs
 */

const SENSITIVE_FIELDS = [
  'api_key',
  'apikey',
  'token',
  'secret',
  'password',
  'authorization',
  'auth',
  'bearer',
  'access_token',
  'refresh_token',
  'private_key',
  'client_secret',
  'connection_string',
  'credential',
];

/**
 * Redacts sensitive fields from an object for safe logging
 * @param obj - The object to redact secrets from
 * @returns A new object with sensitive fields redacted
 */
export function redactSecrets(obj: unknown): Record<string, unknown> {
  if (obj === null || obj === undefined) {
    return {};
  }

  if (typeof obj !== 'object') {
    return { value: String(obj) };
  }

  const result: Record<string, unknown> = {};
  const input = obj as Record<string, unknown>;

  for (const key of Object.keys(input)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = SENSITIVE_FIELDS.some((field) =>
      lowerKey.includes(field.toLowerCase())
    );

    if (isSensitive) {
      result[key] = '[REDACTED]';
    } else if (typeof input[key] === 'object' && input[key] !== null) {
      // Recursively redact nested objects
      result[key] = redactSecrets(input[key]);
    } else {
      result[key] = input[key];
    }
  }

  return result;
}

/**
 * Creates a safe log context by redacting any sensitive data
 * @param context - The context object to make safe for logging
 * @returns A safe context object for logging
 */
export function safeLogContext(context: unknown): Record<string, unknown> {
  return redactSecrets(context);
}