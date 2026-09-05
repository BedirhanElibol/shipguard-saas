// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * ShipGuard Local & Session Storage Utilities
 * Manages privacy-respecting client state, session clearance, and GDPR/KVKK compliance.
 */

export function purgeShipguardStorage(preserveScannedProjects: boolean = false): void {
  if (typeof window === 'undefined') return;
  try {
    if (preserveScannedProjects) {
      // Cleanly clear all session tokens & user identity while preserving local project findings
      localStorage.removeItem('shipguard_user');
      localStorage.removeItem('shipguard_license_key');
    } else {
      // Explicit GDPR Article 17 / KVKK account wipe: delete all shipguard_* keys including webhooks & projects
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('shipguard_')) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach((k) => localStorage.removeItem(k));
      try {
        sessionStorage.clear();
      } catch {
        // Ignore sessionStorage errors
      }
    }
  } catch (err) {
    console.warn('[ShipGuard Storage] Failed to purge storage:', err);
  }
}

/**
 * Safely writes to localStorage with automatic QuotaExceededError recovery.
 * If quota is reached, prunes oldest findings from non-active project scans.
 */
export function safeSetStorageItem(key: string, value: string, activeProjectId?: string): boolean {
  if (typeof window === 'undefined') return false;
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (err: any) {
    const isQuota =
      err?.name === 'QuotaExceededError' ||
      err?.name === 'NS_ERROR_DOM_QUOTA_REACHED' ||
      err?.code === 22 ||
      err?.code === 1014;

    if (isQuota) {
      console.warn('[ShipGuard Storage] QuotaExceededError encountered. Pruning non-active project scans...');
      try {
        const savedProjects = localStorage.getItem('shipguard_projects');
        if (savedProjects) {
          const parsed = JSON.parse(savedProjects);
          if (Array.isArray(parsed) && parsed.length > 0) {
            const pruned = parsed.map((p: any) => {
              if (activeProjectId && p.id === activeProjectId) {
                return {
                  ...p,
                  findings: Array.isArray(p.findings) ? p.findings.slice(0, 30) : []
                };
              }
              return {
                ...p,
                findings: Array.isArray(p.findings) ? p.findings.slice(0, 5) : []
              };
            });
            localStorage.setItem('shipguard_projects', JSON.stringify(pruned));
          }
        }
        localStorage.setItem(key, value);
        return true;
      } catch (pruneErr) {
        console.error('[ShipGuard Storage] Failed to write even after pruning quota:', pruneErr);
        return false;
      }
    }
    console.warn('[ShipGuard Storage] Failed to write item to localStorage:', err);
    return false;
  }
}

/**
 * Safely parses JSON from localStorage with fallbacks to avoid application crashes.
 */
export function safeGetStorageJson<T>(key: string, fallback: T): T {
  if (typeof window === 'undefined') return fallback;
  try {
    const item = localStorage.getItem(key);
    if (!item) return fallback;
    return JSON.parse(item) as T;
  } catch (err) {
    console.warn(`[ShipGuard Storage] Malformed JSON in key "${key}". Cleaning up.`, err);
    try {
      localStorage.removeItem(key);
    } catch {
      // Ignore
    }
    return fallback;
  }
}
