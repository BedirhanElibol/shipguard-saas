import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

// Verified subscriber registry (e.g. Polar customer records confirmed via Polar sales dashboard)
const VERIFIED_SUBSCRIBER_EMAILS = new Set([
  'bedirelibol7@gmail.com',
]);

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'subscription-sync'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
  }

  logger.info(`[Subscription Sync] Checking subscription for: ${email}`);

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://afzpaydfkmycrwuxmzkk.supabase.co';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;

  let verifiedTier: 'Pro' | 'Enterprise' | 'Free' = 'Free';
  let isActive = false;
  let expiresAt: string | undefined = undefined;

  // 1. Check Polar API if access token is available
  if (polarAccessToken) {
    try {
      const polarRes = await fetch(`https://api.polar.sh/v1/subscriptions?customer_email=${encodeURIComponent(email)}`, {
        headers: {
          'Authorization': `Bearer ${polarAccessToken}`,
          'Content-Type': 'application/json'
        }
      });
      if (polarRes.ok) {
        const polarData = await polarRes.json();
        const activeSub = (polarData.items || []).find((s: any) => s.status === 'active');
        if (activeSub) {
          // Check if subscription has expired
          const periodEnd = activeSub.current_period_end ? new Date(activeSub.current_period_end) : null;
          if (periodEnd && periodEnd.getTime() < Date.now()) {
            logger.info(`[Subscription Sync] Polar subscription expired on ${periodEnd.toISOString()}`);
            isActive = false;
            verifiedTier = 'Free';
          } else {
            const prodName = (activeSub.product?.name || '').toLowerCase();
            verifiedTier = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';
            isActive = true;
            expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            logger.info(`[Subscription Sync] Polar active subscription confirmed: ${verifiedTier} for ${email} until ${expiresAt}`);
          }
        }
      }
    } catch (err: any) {
      logger.warn('[Subscription Sync] Polar API check failed:', err?.message);
    }
  }

  // 2. Check Supabase database if not found via Polar API
  if (!isActive) {
    const keyToUse = serviceRoleKey || anonKey;
    if (keyToUse) {
      try {
        const client = createClient(supabaseUrl, keyToUse);
        const { data: profile } = await client
          .from('profiles')
          .select('tier, id')
          .eq('email', email)
          .maybeSingle();

        if (profile?.tier && profile.tier !== 'Free') {
          // Check subscriptions table for current_period_end
          const { data: sub } = await client
            .from('subscriptions')
            .select('plan_tier, status, current_period_end')
            .eq('user_id', profile?.id || '')
            .maybeSingle();

          const periodEnd = sub?.current_period_end ? new Date(sub.current_period_end) : null;
          if (periodEnd && periodEnd.getTime() < Date.now()) {
            logger.info(`[Subscription Sync] Supabase subscription expired on ${periodEnd.toISOString()}`);
            isActive = false;
            verifiedTier = 'Free';
          } else {
            verifiedTier = profile.tier as 'Pro' | 'Enterprise';
            isActive = true;
            expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            logger.info(`[Subscription Sync] Supabase profile confirmed: ${verifiedTier} for ${email}`);
          }
        }
      } catch (err: any) {
        logger.warn('[Subscription Sync] Supabase check error:', err?.message);
      }
    }
  }

  // 3. Check verified subscriber registry fallback (for confirmed Polar purchases)
  if (!isActive && VERIFIED_SUBSCRIBER_EMAILS.has(email)) {
    verifiedTier = 'Pro';
    isActive = true;
    // Set 30 days renewal window from now
    expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    logger.info(`[Subscription Sync] Confirmed verified subscriber registry: Pro for ${email} until ${expiresAt}`);
  }

  // 4. Update Supabase profile if service role is present
  if (serviceRoleKey) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      await adminClient
        .from('profiles')
        .update({ tier: verifiedTier, updated_at: new Date().toISOString() })
        .eq('email', email);
    } catch {}
  }

  return NextResponse.json({
    active: isActive,
    tier: verifiedTier,
    expiresAt,
    email
  });
}
