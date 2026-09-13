import { ZELSIS_PRICING_PLANS, SHIPGUARD_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';
import { syncUserProfileToSupabase } from '@/lib/supabase';

export interface LicenseVerificationResult {
  valid: boolean;
  tier: 'Pro' | 'Enterprise' | 'Free';
  planId: string;
  planName: string;
  expiresAt: string;
  maxApplications: number;
}

/**
 * Computes a deterministic 4-character checksum derived from email + planId + '2026'.
 * Uses a robust 32-bit FNV-1a hash algorithm formatted as uppercase hexadecimal.
 */
export function computeLicenseChecksum(email: string, planId: string): string {
  const normalizedEmail = (email || 'USER').trim().toLowerCase();
  const normalizedPlan = (planId || 'zelsis-core').trim().toLowerCase();
  const seed = `${normalizedEmail}:${normalizedPlan}:2026`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).toUpperCase().padStart(8, '0').slice(0, 4);
}

export function generateLicenseKey(planId: string, email: string): string {
  const cleanEmailHash = (email || 'USER').replace(/[^a-zA-Z0-9]/g, '').toUpperCase().padEnd(4, 'X').slice(0, 4);
  const randomHex = Math.random().toString(36).substring(2, 6).toUpperCase().padEnd(4, '0');
  const checksum = computeLicenseChecksum(email, planId);
  
  const prefix = planId === 'vibecare' || planId === 'zelsis-suite' ? 'ZS-SUITE' : 'ZS-PRO';
  return `${prefix}-2026-${cleanEmailHash}-${randomHex}-${checksum}`;
}

export function verifyLicenseKey(licenseKey: string, userEmail?: string): LicenseVerificationResult {
  const invalidResult = (reason: string): LicenseVerificationResult => ({
    valid: false,
    tier: 'Free',
    planId: 'none',
    planName: reason,
    expiresAt: 'N/A',
    maxApplications: 1,
  });

  if (!licenseKey || typeof licenseKey !== 'string') {
    return invalidResult('Free Audit Tier');
  }

  const cleanKey = licenseKey.trim().toUpperCase();

  const normalizedUserEmail = (userEmail || '').trim().toLowerCase();

  // Master Founder & Architectural Lifetime Licenses (Strictly restricted to bedirelibol7@gmail.com)
  const isMasterKey =
    cleanKey === 'ZS-PRO-MASTER-2026' ||
    cleanKey === 'ZS-ENTERPRISE-MASTER-2026' ||
    cleanKey === 'ZS-SUITE-2026-ADMIN-MASTER-0000' ||
    cleanKey.includes('FOUNDER') ||
    cleanKey.includes('MASTER');

  if (isMasterKey) {
    if (normalizedUserEmail === 'bedirelibol7@gmail.com') {
      const isEnterprise = cleanKey.includes('ENTERPRISE') || cleanKey.includes('SUITE') || cleanKey.includes('FOUNDER');
      return {
        valid: true,
        tier: isEnterprise ? 'Enterprise' : 'Pro',
        planId: isEnterprise ? 'vibecare' : 'zelsis-core',
        planName: isEnterprise ? 'Zelsis Enterprise (Lifetime Founder Clearance)' : 'Zelsis Pro (Master Clearance)',
        expiresAt: '2099-12-31T23:59:59.999Z',
        maxApplications: isEnterprise ? 999 : 99,
      };
    }
    return invalidResult('Master clearance restricted to platform founder');
  }
  
  // Validate key format: must be PREFIX-YEAR-XXXX-YYYY-ZZZZ
  const validKeyPattern = /^(ZS|SG)-(SUITE|PRO|CORE|VIBE)-(\d{4})-([A-Z0-9]{4})-([A-Z0-9]{4})-([A-Z0-9]{4})$/;
  const match = cleanKey.match(validKeyPattern);
  if (!match) {
    return invalidResult('Invalid License Format');
  }

  const [, org, planCode, year, segEmail, segRand, checksum] = match;

  // Validate license year
  if (year !== '2026') {
    return invalidResult('Expired License Year');
  }

  const isEnterprise = planCode === 'SUITE' || planCode === 'VIBE';
  const tier: 'Pro' | 'Enterprise' = isEnterprise ? 'Enterprise' : 'Pro';
  const planId = isEnterprise ? 'vibecare' : 'zelsis-core';

  // Strict Account Isolation: Verify checksum against the exact authenticated user email
  if (!normalizedUserEmail) {
    return invalidResult('Email binding required for license validation');
  }

  const expectedChecksum = computeLicenseChecksum(normalizedUserEmail, planId);
  if (expectedChecksum !== checksum) {
    return invalidResult('Invalid License Checksum for Account');
  }

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

export async function activateUserTier(
  tier: 'Pro' | 'Enterprise',
  licenseKey?: string,
  fallbackProfile?: { name?: string; email?: string; avatarUrl?: string } | null
): Promise<boolean> {
  try {
    let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
    if (!savedUserStr && typeof document !== 'undefined') {
      const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
      if (match && match[3]) {
        savedUserStr = decodeURIComponent(match[3]);
      }
    }
    let userObj: any = null;
    const renewalDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    if (savedUserStr) {
      try {
        const parsed = JSON.parse(savedUserStr);
        const isMatchingEmail = !fallbackProfile?.email || (parsed?.email && parsed.email.toLowerCase().trim() === fallbackProfile.email.toLowerCase().trim());
        if (parsed && typeof parsed === 'object' && isMatchingEmail) {
          userObj = {
            ...parsed,
            tier: tier,
            isLoggedIn: true,
            expiresAt: parsed.expiresAt && new Date(parsed.expiresAt).getTime() > Date.now() ? parsed.expiresAt : renewalDate,
            subscriptionStatus: 'active',
            status: 'active',
            lastVerifiedAt: Date.now(),
          };
        }
      } catch (err) {
        console.warn('[Zelsis Activation] Failed to parse user from storage:', err);
      }
    }

    if (!userObj && fallbackProfile?.email) {
      userObj = {
        name: fallbackProfile.name || fallbackProfile.email.split('@')[0] || 'Customer',
        email: fallbackProfile.email.toLowerCase().trim(),
        avatarUrl: fallbackProfile.avatarUrl,
        tier: tier,
        isLoggedIn: true,
        emailVerified: true,
        expiresAt: renewalDate,
        subscriptionStatus: 'active',
        status: 'active',
        lastVerifiedAt: Date.now(),
      };
    }

    if (!userObj) {
      userObj = {
        name: 'Subscriber',
        email: 'customer@zelsis.dev',
        tier: tier,
        isLoggedIn: true,
        emailVerified: true,
        expiresAt: renewalDate,
        subscriptionStatus: 'active',
        status: 'active',
        lastVerifiedAt: Date.now(),
      };
    }

    const planId = tier === 'Enterprise' ? 'vibecare' : 'zelsis-core';
    const effectiveKey = licenseKey && verifyLicenseKey(licenseKey, userObj.email).valid
      ? licenseKey
      : generateLicenseKey(planId, userObj.email || 'customer@zelsis.dev');

    localStorage.setItem('zelsis_license_key', effectiveKey);
    localStorage.setItem('shipguard_license_key', effectiveKey);

    localStorage.setItem('zelsis_user', JSON.stringify(userObj));
    if (typeof document !== 'undefined') {
      document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(userObj))}; path=/; max-age=2592000; SameSite=Lax; Secure`;
    }
    window.dispatchEvent(new Event('storage'));

    // Synchronize directly with Supabase Auth user metadata so session refreshes never revert to Free
    await syncUserProfileToSupabase({
      tier,
      expiresAt: userObj.expiresAt,
      status: 'active',
    }).catch((syncErr) => {
      console.warn('[Zelsis Activation] Supabase auth metadata sync notice:', syncErr);
    });

    return true;
  } catch (err) {
    console.error('[Zelsis Activation] Failed to activate tier:', err);
    return false;
  }
}
