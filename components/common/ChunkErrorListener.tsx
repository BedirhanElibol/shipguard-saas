'use client';

import { useEffect } from 'react';
import { isChunkLoadError, handleChunkLoadRecovery } from '@/lib/chunk-reload';

/**
 * Global Chunk Error Listener
 * Traps stale deployment script 404s and unhandled chunk promise rejections
 * at the browser window level, transparently refreshing to the latest release.
 */
export function ChunkErrorListener() {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleError = (event: ErrorEvent) => {
      // 1. Script tag loading failure (e.g. 404 on _next/static/chunks/...)
      const target = event.target as HTMLElement | null;
      if (target && target.tagName === 'SCRIPT') {
        const src = (target as HTMLScriptElement).src || '';
        if (src.includes('/_next/static/chunks/')) {
          console.warn('[ChunkErrorListener] Stale script chunk failed to load:', src);
          handleChunkLoadRecovery();
          return;
        }
      }

      // 2. Direct ChunkLoadError runtime exception
      if (event.error && isChunkLoadError(event.error)) {
        console.warn('[ChunkErrorListener] ChunkLoadError intercepted in window error event:', event.error);
        handleChunkLoadRecovery();
      }
    };

    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      if (event.reason && isChunkLoadError(event.reason)) {
        console.warn('[ChunkErrorListener] ChunkLoadError intercepted in unhandled rejection:', event.reason);
        handleChunkLoadRecovery();
      }
    };

    window.addEventListener('error', handleError, true);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      window.removeEventListener('error', handleError, true);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  return null;
}
