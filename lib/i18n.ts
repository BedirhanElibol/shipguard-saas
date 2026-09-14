import en from '../public/locales/en.json';

export type LocaleKey = keyof typeof en;

export function t(keyPath: string, fallback: string = ''): string {
  const keys = keyPath.split('.');
  let current: unknown = en;
  for (const k of keys) {
    if (current && typeof current === 'object' && k in current) {
      current = (current as Record<string, unknown>)[k];
    } else {
      return fallback || keyPath;
    }
  }
  return typeof current === 'string' ? current : fallback || keyPath;
}
