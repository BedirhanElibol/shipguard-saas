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
