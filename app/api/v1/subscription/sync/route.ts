import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

// Verified subscriber registry (configured via environment variables without hardcoded PII)
const VERIFIED_SUBSCRIBER_EMAILS = new Set(
  (process.env.VERIFIED_SUBSCRIBERS || process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
);

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'subscription-sync'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 1. Enforce Supabase JWT Bearer token authentication
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!token) {
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://afzpaydfkmycrwuxmzkk.supabase.co';
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFmenBheWRma215Y3J3dXhtemtrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5MTc5NzEsImV4cCI6MjEwMzQ5Mzk3MX0.MNtKjLI3mNmGIRmcirzwnGknw0VJy58A2noAnEZZKZA';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;

  const authClient = createClient(supabaseUrl, anonKey);
  const { data: authData, error: authError } = await authClient.auth.getUser(token);

  if (authError || !authData?.user) {
    logger.warn('[Subscription Sync] Unauthorized attempt with invalid or expired token:', authError?.message);
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  const authenticatedEmail = authData.user.email?.toLowerCase().trim();
  if (!authenticatedEmail) {
    return NextResponse.json(
      { error: 'Authentication required to synchronize subscription status' },
      { status: 401 }
    );
  }

  let body: { email?: string } = {};
  try {
    const rawText = await req.text();
    if (rawText) {
      body = JSON.parse(rawText);
    }
  } catch (parseErr) {
    void parseErr;
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const requestedEmail = (body?.email || '').trim().toLowerCase();
  if (requestedEmail && requestedEmail !== authenticatedEmail) {
    logger.warn(`[Subscription Sync] Email mismatch: authenticated user ${authenticatedEmail} requested ${requestedEmail}`);
    return NextResponse.json(
      { error: 'Forbidden: You can only query or synchronize your own subscription' },
      { status: 403 }
    );
  }

  const email = requestedEmail || authenticatedEmail;
  if (!email || !email.includes('@')) {
    return NextResponse.json({ error: 'Valid email is required' }, { status: 400 });
  }

  logger.info(`[Subscription Sync] Checking subscription for: ${email}`);

  let verifiedTier: 'Pro' | 'Enterprise' | 'Free' = 'Free';
  let isActive = false;
  let subStatus: 'active' | 'past_due' | 'canceled' = 'canceled';
  let expiresAt: string | undefined = undefined;
  let gracePeriodUntil: string | undefined = undefined;

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
        const polarSub = (polarData.items || []).find(
          (s: { status?: string; current_period_end?: string | null; product?: { name?: string } }) => s.status === 'active' || s.status === 'past_due'
        );
        if (polarSub) {
          const periodEnd = polarSub.current_period_end ? new Date(polarSub.current_period_end) : null;
          if (polarSub.status === 'past_due') {
            // Failed renewal charge: grant 3-day grace period
            const prodName = (polarSub.product?.name || '').toLowerCase();
            verifiedTier = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';
            isActive = true;
            subStatus = 'past_due';
            gracePeriodUntil = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
            expiresAt = gracePeriodUntil;
            logger.info(`[Subscription Sync] Polar subscription past_due for ${email}. Grace period until ${gracePeriodUntil}`);
          } else if (periodEnd && periodEnd.getTime() < Date.now()) {
            logger.info(`[Subscription Sync] Polar subscription expired on ${periodEnd.toISOString()}`);
            isActive = false;
            subStatus = 'canceled';
            verifiedTier = 'Free';
          } else {
            const prodName = (polarSub.product?.name || '').toLowerCase();
            verifiedTier = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';
            isActive = true;
            subStatus = 'active';
            expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            logger.info(`[Subscription Sync] Polar active subscription confirmed: ${verifiedTier} for ${email} until ${expiresAt}`);
          }
        }
      }
    } catch (err: unknown) {
      logger.warn('[Subscription Sync] Polar API check failed:', err instanceof Error ? err.message : String(err));
    }
  }

  // 2. Check Supabase database if not found via Polar API
  if (!isActive) {
    const keyToUse = serviceRoleKey || anonKey;
    if (keyToUse) {
      try {
        const client = createClient(supabaseUrl, keyToUse);
        // Find user by email in profiles
        const { data: profile } = await client
          .from('profiles')
          .select('id, email')
          .eq('email', email)
          .maybeSingle();

        if (profile?.id) {
          // Check subscriptions table for tier and status
          const { data: sub } = await client
            .from('subscriptions')
            .select('plan_tier, status, current_period_end')
            .eq('user_id', profile.id)
            .maybeSingle();

          const rawPlanTier = sub?.plan_tier as string | undefined;
          const subPlanTier = rawPlanTier === 'Enterprise' ? 'Enterprise' : (rawPlanTier === 'Pro' ? 'Pro' : undefined);

          if (subPlanTier) {
            const periodEnd = sub?.current_period_end ? new Date(sub.current_period_end) : null;
            if (sub?.status === 'past_due') {
              verifiedTier = subPlanTier;
              isActive = true;
              subStatus = 'past_due';
              gracePeriodUntil = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
              expiresAt = gracePeriodUntil;
            } else if (periodEnd && periodEnd.getTime() < Date.now()) {
              logger.info(`[Subscription Sync] Supabase subscription expired on ${periodEnd.toISOString()}`);
              isActive = false;
              subStatus = 'canceled';
              verifiedTier = 'Free';
            } else {
              verifiedTier = subPlanTier;
              isActive = true;
              subStatus = (sub?.status === 'past_due' || sub?.status === 'canceled') ? sub.status : 'active';
              expiresAt = periodEnd ? periodEnd.toISOString() : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
              logger.info(`[Subscription Sync] Supabase subscription confirmed: ${verifiedTier} for ${email}`);
            }
          }
        }
      } catch (err: unknown) {
        logger.warn('[Subscription Sync] Supabase check error:', err instanceof Error ? err.message : String(err));
      }
    }
  }

  // 3. Check authenticated user metadata in Supabase auth
  const userMetadata = authData.user.user_metadata || {};
  const metaTier = userMetadata.tier as 'Pro' | 'Enterprise' | 'Free' | undefined;
  const metaExpiresAt = userMetadata.expiresAt as string | undefined;
  const metaStatus = userMetadata.subscriptionStatus as string | undefined;

  if (!isActive && (metaTier === 'Pro' || metaTier === 'Enterprise')) {
    const expiryTime = metaExpiresAt ? new Date(metaExpiresAt).getTime() : null;
    const isExpired = expiryTime ? !isNaN(expiryTime) && Date.now() > expiryTime : false;
    if (!isExpired) {
      verifiedTier = metaTier;
      isActive = true;
      subStatus = (metaStatus === 'past_due' || metaStatus === 'active') ? metaStatus : 'active';
      expiresAt = metaExpiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      logger.info(`[Subscription Sync] Confirmed via Supabase user_metadata: ${verifiedTier} for ${email} until ${expiresAt}`);
    }
  }

  // 4. Check verified subscriber registry fallback (for confirmed Polar purchases)
  if (!isActive && VERIFIED_SUBSCRIBER_EMAILS.has(email)) {
    verifiedTier = 'Pro';
    isActive = true;
    subStatus = 'active';
    expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    logger.info(`[Subscription Sync] Confirmed verified subscriber registry: Pro for ${email} until ${expiresAt}`);
  }

  // 5. Update Supabase subscriptions and profiles if service role is present
  if (serviceRoleKey && isActive) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      const { data: matchedProfile } = await adminClient
        .from('profiles')
        .select('id')
        .eq('email', email)
        .maybeSingle();

      const userId = matchedProfile?.id || authData.user.id;
      if (userId) {
        await adminClient.from('subscriptions').upsert({
          user_id: userId,
          plan_tier: verifiedTier,
          status: subStatus,
          current_period_end: expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });

        await adminClient.auth.admin.updateUserById(userId, {
          user_metadata: {
            ...userMetadata,
            tier: verifiedTier,
            subscriptionStatus: subStatus,
            expiresAt: expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
          }
        }).catch(() => {});
      }
    } catch (syncUpdateErr: unknown) {
      logger.warn('[Subscription Sync] Admin update notice:', syncUpdateErr instanceof Error ? syncUpdateErr.message : String(syncUpdateErr));
    }
  }

  return NextResponse.json({
    active: isActive,
    status: subStatus,
    tier: verifiedTier,
    expiresAt,
    gracePeriodUntil,
    email
  });
}
