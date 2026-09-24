/**
 * Production Resilient Chunk Load Error Detection & Auto-Recovery
 * Handles Next.js deployment synchronization when old bundle hashes are replaced on Vercel/CDN.
 */

const CHUNK_RELOAD_KEY = 'zelsis_chunk_reload_ts';
const COOLDOWN_MS = 12000; // 12 seconds cooldown to prevent rapid reload loops

/**
 * Checks whether an error or unhandled rejection corresponds to a Next.js / Webpack ChunkLoadError.
 */
export function isChunkLoadError(error: unknown): boolean {
  if (!error) return false;

  const err = error as { name?: string; message?: string; target?: { tagName?: string; src?: string } };
  const name = typeof err.name === 'string' ? err.name : '';
  const message = typeof err.message === 'string' ? err.message : '';

  // 1. Direct Webpack ChunkLoadError
  if (name === 'ChunkLoadError') return true;

  // 2. Next.js / Webpack chunk loading pattern
  if (/loading chunk \d+ failed/i.test(message)) return true;
  if (/loading CSS chunk \d+ failed/i.test(message)) return true;

  // 3. Dynamic import failures for module scripts
  if (
    message.includes('Failed to fetch dynamically imported module') ||
    message.includes('Importing a module script failed') ||
    message.includes('error loading dynamically imported module') ||
    message.includes('_next/static/chunks')
  ) {
    return true;
  }

  // 4. HTML script tag onerror events
  if (err.target?.tagName === 'SCRIPT' && typeof err.target.src === 'string') {
    if (err.target.src.includes('/_next/static/chunks/')) {
      return true;
    }
  }

  return false;
}

/**
 * Executes a resilient, timestamp-controlled page reload to acquire latest deployment chunk manifests.
 * Returns true if reload was dispatched, false if reload was suppressed by cooldown.
 */
export function handleChunkLoadRecovery(force = false): boolean {
  if (typeof window === 'undefined') return false;

  try {
    const rawTs = sessionStorage.getItem(CHUNK_RELOAD_KEY);
    const lastReload = rawTs ? parseInt(rawTs, 10) : 0;
    const now = Date.now();

    if (!force && Number.isFinite(lastReload) && now - lastReload < COOLDOWN_MS) {
      console.warn('[Zelsis ChunkRecovery] Suppressing auto-reload: cooldown active (%d ms remaining)', COOLDOWN_MS - (now - lastReload));
      return false;
    }

    sessionStorage.setItem(CHUNK_RELOAD_KEY, String(now));
    console.info('[Zelsis ChunkRecovery] Stale deployment chunk detected. Reloading application...');

    // Perform a hard page reload
    window.location.reload();
    return true;
  } catch (storageErr) {
    console.warn('[Zelsis ChunkRecovery] Storage access error during recovery:', storageErr);
    window.location.reload();
    return true;
  }
}

/**
 * Clears the reload cooldown in sessionStorage (useful when user clicks manual retry)
 */
export function clearChunkReloadCooldown(): void {
  if (typeof window === 'undefined') return;
  try {
    sessionStorage.removeItem(CHUNK_RELOAD_KEY);
  } catch {
    // Sandboxed storage fallback
  }
}
