/**
 * Environment configuration and isolation utilities.
 * Governs host detection, execution environment boundaries,
 * and security-sensitive audit feature access.
 */

/**
 * Detects whether the application is running in local development mode.
 * Safe for both client-side (browser) and server-side (Node.js runtime) execution.
 */
export function isDevelopment(): boolean {
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname.endsWith('.local')
    );
  }
  return process.env.NODE_ENV === 'development';
}

/**
 * Detects whether the application is running in production mode.
 */
export function isProduction(): boolean {
  return !isDevelopment();
}

/**
 * Determines whether the local workspace self-audit feature can be accessed.
 * - In production environments (*.vercel.app or zelsis.com), always returns false.
 * - In local development environments, returns true.
 * - Allows explicit test override via NEXT_PUBLIC_ALLOW_LOCAL_AUDIT === 'true' (except in production domains).
 */
export function canAccessLocalAudit(): boolean {
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    // Explicit production domain check: Always block local audit in public production
    if (
      hostname.includes('vercel.app') ||
      hostname === 'zelsis.com' ||
      hostname.endsWith('.zelsis.com') ||
      hostname === 'shipguard.dev' ||
      hostname.endsWith('.shipguard.dev')
    ) {
      return false;
    }
  }

  if (process.env.NEXT_PUBLIC_ALLOW_LOCAL_AUDIT === 'true') {
    return true;
  }

  return isDevelopment();
}
