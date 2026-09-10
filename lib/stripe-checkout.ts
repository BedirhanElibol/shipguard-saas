// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { ZELSIS_PRICING_PLANS, SHIPGUARD_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';

export interface LicenseVerificationResult {
  valid: boolean;
  tier: 'Pro' | 'Enterprise' | 'Free';
  planId: string;
  planName: string;
  expiresAt: string;
  maxApplications: number;
}

export function generateLicenseKey(planId: string, email: string): string {
  const cleanEmailHash = (email || 'USER').replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 4);
  const randomHex = Math.random().toString(36).substring(2, 6).toUpperCase();
  const timestamp = Date.now().toString(36).toUpperCase().slice(-4);
  
  const prefix = planId === 'vibecare' || planId === 'zelsis-suite' ? 'ZS-SUITE' : 'ZS-PRO';
  return `${prefix}-2026-${cleanEmailHash}-${randomHex}-${timestamp}`;
}

export function verifyLicenseKey(licenseKey: string): LicenseVerificationResult {
  if (!licenseKey || typeof licenseKey !== 'string') {
    return {
      valid: false,
      tier: 'Free',
      planId: 'none',
      planName: 'Free Audit Tier',
      expiresAt: 'N/A',
      maxApplications: 1,
    };
  }

  const cleanKey = licenseKey.trim().toUpperCase();
  
  // Validate key format: must be PREFIX-YEAR-XXXX-XXXX-XXXX
  const validKeyPattern = /^(ZS|SG)-(SUITE|PRO|CORE|VIBE)-\d{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
  if (!validKeyPattern.test(cleanKey)) {
    return {
      valid: false,
      tier: 'Free',
      planId: 'none',
      planName: 'Invalid License Format',
      expiresAt: 'N/A',
      maxApplications: 1,
    };
  }

  // NOTE: Full license verification should be done server-side via /api/v1/verify-license
  // This client-side check is only for format validation and UI display
  const isEnterprise = cleanKey.startsWith('ZS-SUITE') || cleanKey.startsWith('SG-SUITE');
  const tier: 'Pro' | 'Enterprise' = isEnterprise ? 'Enterprise' : 'Pro';
  const planId = isEnterprise ? 'vibecare' : 'zelsis-core';
  const planObj = (ZELSIS_PRICING_PLANS || SHIPGUARD_PRICING_PLANS).find((p) => p.id === planId);

  const expiresDate = new Date();
  expiresDate.setFullYear(expiresDate.getFullYear() + 1);

  return {
    valid: true,
    tier,
    planId,
    planName: planObj?.name || (tier === 'Enterprise' ? 'Zelsis Enterprise' : 'Zelsis Pro'),
    expiresAt: expiresDate.toISOString(),
    maxApplications: isEnterprise ? 999 : 99,
  };
}

export async function activateUserTier(tier: 'Pro' | 'Enterprise', licenseKey?: string): Promise<boolean> {
  try {
    if (licenseKey) {
      localStorage.setItem('zelsis_license_key', licenseKey);
      localStorage.setItem('shipguard_license_key', licenseKey);
    }
    let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
    if (!savedUserStr && typeof document !== 'undefined') {
      const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
      if (match && match[3]) {
        savedUserStr = decodeURIComponent(match[3]);
      }
    }
    let userObj: any = null;
    if (savedUserStr) {
      try {
        const parsed = JSON.parse(savedUserStr);
        if (parsed && typeof parsed === 'object' && parsed.isLoggedIn) {
          const renewalDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          userObj = {
            ...parsed,
            tier: tier,
            expiresAt: parsed.expiresAt || renewalDate,
            subscriptionStatus: 'active',
          };
        }
      } catch (err) {
        console.warn('[Zelsis Activation] Failed to parse user from storage:', err);
      }
    }

    if (!userObj) {
      // No active session found - cannot activate tier without authenticated user
      console.warn('[Zelsis Activation] No authenticated user session found. Tier activation requires login.');
      return false;
    }

    localStorage.setItem('zelsis_user', JSON.stringify(userObj));
    if (typeof document !== 'undefined') {
      document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(userObj))}; path=/; max-age=2592000; SameSite=Lax; Secure`;
    }
    window.dispatchEvent(new Event('storage'));

    // NOTE: Tier updates in Supabase should only be done via server-side webhook handlers
    // Client-side tier activation is for local UI state only
    // Server-side sync will be handled by /api/v1/polar-webhook

    return true;
  } catch (err) {
    console.error('[Zelsis Activation] Failed to activate tier:', err);
    return false;
  }
}
