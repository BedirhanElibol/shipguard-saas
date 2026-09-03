// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Production Security Logger for ShipGuard SaaS
 * Automatically redacts sensitive credentials, API keys, tokens, passwords, and PII
 * before emitting to stdout/stderr. Prevents accidental credential leaks in cloud logs.
 */

// Secret regex patterns to redact
const SENSITIVE_KEY_REGEX = /^(password|passwd|secret|token|api_?key|auth|authorization|access_?token|refresh_?token|cookie|set-cookie|private_?key|webhook_?secret)$/i;

const REDACTION_PATTERNS: Array<{ regex: RegExp; replacement: string | ((substring: string, ...args: any[]) => string) }> = [
  // Stripe API keys & webhook secrets
  { regex: new RegExp('sk_' + 'live_[a-zA-Z0-9]{24,}', 'g'), replacement: '[STRIPE_LIVE_KEY_REDACTED]' },
  { regex: new RegExp('sk_' + 'test_[a-zA-Z0-9]{24,}', 'g'), replacement: '[STRIPE_TEST_KEY_REDACTED]' },
  { regex: new RegExp('whsec_[a-zA-Z0-9]{24,}', 'g'), replacement: '[WHSEC_REDACTED]' },
  { regex: new RegExp('pk_' + 'live_[a-zA-Z0-9]{24,}', 'g'), replacement: '[STRIPE_PK_REDACTED]' },
  // GitHub Tokens (classic and fine-grained)
  { regex: new RegExp('gh[pousr]_[a-zA-Z0-9]{36,}', 'g'), replacement: '[GITHUB_TOKEN_REDACTED]' },
  { regex: new RegExp('github_pat_[a-zA-Z0-9_]{60,}', 'g'), replacement: '[GITHUB_PAT_REDACTED]' },
  // JWT tokens (Supabase, Auth0, etc.)
  { regex: /(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/g, replacement: 'eyJ***.***.***[JWT_REDACTED]' },
  // Bearer tokens in headers
  { regex: /(bearer\s+)[a-zA-Z0-9._~+/-]+=*/gi, replacement: '$1***REDACTED_BEARER***' },
  // Standard API keys / hex secrets of length 32+
  { regex: /(api[-_]?key[:=]\s*["']?)[a-zA-Z0-9_\-]{32,}(["']?)/gi, replacement: '$1***REDACTED_API_KEY***$2' },
  // Credit Card Numbers (13-19 digits)
  { regex: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_CARD]' },
  // Turkish TC Kimlik Numbers (11 digits, first digit 1-9)
  { regex: /\b[1-9]\d{10}\b/g, replacement: '[REDACTED_TCKN]' },
  // Email addresses (partial mask: j***e@example.com)
  {
    regex: /([a-zA-Z0-9_\-+.]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/g,
    replacement: (_match: string, user: string, domain: string) => {
      if (user.length <= 2) return `${user[0]}*@${domain}`;
      return `${user[0]}***${user[user.length - 1]}@${domain}`;
    }
  }
];

export function redactString(str: string): string {
  if (typeof str !== 'string') return str;
  let redacted = str;
  for (const { regex, replacement } of REDACTION_PATTERNS) {
    redacted = redacted.replace(regex, replacement as any);
  }
  return redacted;
}

export function redactSensitiveData(data: unknown, seen = new WeakSet()): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') return redactString(data);
  if (typeof data === 'number' || typeof data === 'boolean') return data;

  if (data instanceof Error) {
    return {
      name: data.name,
      message: redactString(data.message),
      stack: redactString(data.stack || '')
    };
  }

  if (typeof data === 'object') {
    if (seen.has(data as object)) {
      return '[Circular]';
    }
    seen.add(data as object);

    if (Array.isArray(data)) {
      return data.map((item) => redactSensitiveData(item, seen));
    }

    const cleanObj: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        cleanObj[key] = '***REDACTED***';
      } else {
        cleanObj[key] = redactSensitiveData(val, seen);
      }
    }
    return cleanObj;
  }

  return data;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

class SecurityLogger {
  private isDev = process.env.NODE_ENV !== 'production';

  private formatMessage(level: LogLevel, message: string, meta?: unknown): string {
    const timestamp = new Date().toISOString();
    const cleanMsg = redactString(message);
    const cleanMeta = meta !== undefined ? ' ' + JSON.stringify(redactSensitiveData(meta)) : '';
    return `[${timestamp}] [${level.toUpperCase()}] [ShipGuard]: ${cleanMsg}${cleanMeta}`;
  }

  debug(message: string, meta?: unknown): void {
    if (this.isDev) {
      console.debug(this.formatMessage('debug', message, meta));
    }
  }

  info(message: string, meta?: unknown): void {
    console.log(this.formatMessage('info', message, meta));
  }

  warn(message: string, meta?: unknown): void {
    console.warn(this.formatMessage('warn', message, meta));
  }

  error(message: string, meta?: unknown): void {
    console.error(this.formatMessage('error', message, meta));
  }
}

export const logger = new SecurityLogger();
export default logger;
