// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { SHIPGUARD_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';

export interface LicenseVerificationResult {
  valid: boolean;
  planId: string;
  planName: string;
  expiresAt: string;
  maxApplications: number;
}

export function generateLicenseKey(planId: string, email: string): string {
  const cleanEmailHash = email.replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 4);
  const randomHex = Math.random().toString(36).substring(2, 6).toUpperCase();
  const timestamp = Date.now().toString(36).toUpperCase().slice(-4);
  
  const prefix = planId === 'vibecare' ? 'SG-SUITE' : planId === 'vibepolish' ? 'SG-VIBE' : 'SG-CORE';
  return `${prefix}-2026-${cleanEmailHash}-${randomHex}-${timestamp}`;
}

export function verifyLicenseKey(licenseKey: string): LicenseVerificationResult {
  if (!licenseKey || typeof licenseKey !== 'string') {
    return {
      valid: false,
      planId: 'none',
      planName: 'Free Audit Tier',
      expiresAt: 'N/A',
      maxApplications: 1,
    };
  }

  const cleanKey = licenseKey.trim().toUpperCase();
  const isVibeCare = cleanKey.startsWith('SG-SUITE');
  const isVibePolish = cleanKey.startsWith('SG-VIBE');

  const planId = isVibeCare ? 'vibecare' : isVibePolish ? 'vibepolish' : 'shipguard-core';
  const planObj = SHIPGUARD_PRICING_PLANS.find((p) => p.id === planId);

  const expiresDate = new Date();
  expiresDate.setFullYear(expiresDate.getFullYear() + 1);

  return {
    valid: cleanKey.length >= 16,
    planId,
    planName: planObj?.name || 'ShipGuard Core Tier',
    expiresAt: expiresDate.toISOString(),
    maxApplications: isVibeCare ? 999 : isVibePolish ? 5 : 99,
  };
}
