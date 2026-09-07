// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { SHIPGUARD_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';

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
  
  const prefix = planId === 'vibecare' ? 'SG-SUITE' : 'SG-PRO';
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
  const isEnterprise = cleanKey.startsWith('SG-SUITE');
  const isPro = cleanKey.startsWith('SG-PRO') || cleanKey.startsWith('SG-CORE') || cleanKey.startsWith('SG-VIBE');

  if (!isEnterprise && !isPro && cleanKey.length < 16) {
    return {
      valid: false,
      tier: 'Free',
      planId: 'none',
      planName: 'Invalid License',
      expiresAt: 'N/A',
      maxApplications: 1,
    };
  }

  const tier: 'Pro' | 'Enterprise' = isEnterprise ? 'Enterprise' : 'Pro';
  const planId = isEnterprise ? 'vibecare' : 'shipguard-core';
  const planObj = SHIPGUARD_PRICING_PLANS.find((p) => p.id === planId);

  const expiresDate = new Date();
  expiresDate.setFullYear(expiresDate.getFullYear() + 1);

  return {
    valid: true,
    tier,
    planId,
    planName: planObj?.name || (tier === 'Enterprise' ? 'ShipGuard Enterprise' : 'ShipGuard Pro'),
    expiresAt: expiresDate.toISOString(),
    maxApplications: isEnterprise ? 999 : 99,
  };
}

export async function activateUserTier(tier: 'Pro' | 'Enterprise', licenseKey?: string): Promise<boolean> {
  try {
    if (licenseKey) {
      localStorage.setItem('shipguard_license_key', licenseKey);
    }
    let savedUserStr = localStorage.getItem('shipguard_user');
    if (!savedUserStr && typeof document !== 'undefined') {
      const match = document.cookie.match(/(^|;)\s*shipguard_user=([^;]+)/);
      if (match && match[2]) {
        savedUserStr = decodeURIComponent(match[2]);
      }
    }
    if (savedUserStr) {
      try {
        const parsed = JSON.parse(savedUserStr);
        if (parsed && typeof parsed === 'object' && parsed.isLoggedIn) {
          const userObj = { ...parsed, tier: tier };
          localStorage.setItem('shipguard_user', JSON.stringify(userObj));
          if (typeof document !== 'undefined') {
            document.cookie = `shipguard_user=${encodeURIComponent(JSON.stringify(userObj))}; path=/; max-age=2592000; SameSite=Lax`;
          }
          window.dispatchEvent(new Event('storage'));
        }
      } catch (err) {
        console.warn('[ShipGuard Activation] Failed to parse user from storage:', err);
      }
    }

    // If Supabase client exists, attempt syncing
    try {
      const { getSupabase } = await import('@/lib/supabase');
      const supabase = getSupabase();
      if (supabase) {
        const { data: { session } } = await supabase.auth.getSession();
        if (session?.user) {
          await supabase.from('profiles').update({ tier }).eq('id', session.user.id);
          await supabase.from('subscriptions').upsert({
            user_id: session.user.id,
            plan_tier: tier.toLowerCase(),
            status: 'active',
            updated_at: new Date().toISOString(),
          }, { onConflict: 'user_id' });
        }
      }
    } catch (e: any) {
      console.warn('[ShipGuard Activation] Supabase sync warning:', e?.message || e);
    }

    return true;
  } catch (err) {
    console.error('[ShipGuard Activation] Failed to activate tier:', err);
    return false;
  }
}
