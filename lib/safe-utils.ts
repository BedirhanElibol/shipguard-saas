/**
 * Global Defensive String & Object Utilities
 * Eliminates unhandled TypeErrors across all data ingestion and UI render pipelines.
 */

export function safeString(value: unknown, fallback: string = ''): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  if (typeof value === 'symbol') {
    return value.description || fallback;
  }
  try {
    return JSON.stringify(value) || fallback;
  } catch {
    return fallback;
  }
}

export function safeLower(value: unknown, fallback: string = ''): string {
  return safeString(value, fallback).toLowerCase();
}

export function safeUpper(value: unknown, fallback: string = ''): string {
  return safeString(value, fallback).toUpperCase();
}

export function safeTrim(value: unknown, fallback: string = ''): string {
  return safeString(value, fallback).trim();
}

export function safeReplace(
  value: unknown,
  pattern: string | RegExp,
  replacement: string | ((substring: string, ...args: any[]) => string),
  fallback: string = ''
): string {
  const str = safeString(value, fallback);
  try {
    if (typeof replacement === 'function') {
      return str.replace(pattern, replacement as any);
    }
    return str.replace(pattern, replacement);
  } catch {
    return str;
  }
}

export function safeUrl(value: unknown, fallback: string = ''): string {
  const clean = safeTrim(value);
  if (!clean) return fallback;
  try {
    const parsed = new URL(clean.startsWith('http://') || clean.startsWith('https://') ? clean : `https://${clean}`);
    return parsed.toString();
  } catch {
    return fallback;
  }
}

export function safeArray<T>(value: unknown, fallback: T[] = []): T[] {
  if (Array.isArray(value)) return value;
  return fallback;
}

export function safeRecord<K extends string | number | symbol, V>(
  value: unknown,
  fallback: Record<K, V> = {} as Record<K, V>
): Record<K, V> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<K, V>;
  }
  return fallback;
}
