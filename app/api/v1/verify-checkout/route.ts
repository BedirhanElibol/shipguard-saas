import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

export const maxDuration = 15;
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'verify-checkout'
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

  const { checkoutId, email, planId } = body;
  if (!checkoutId || typeof checkoutId !== 'string') {
    return NextResponse.json({ error: 'checkout_id is required' }, { status: 400 });
  }

  // F-14: Caller Authorization Check
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;

  let authenticatedUserId: string | null = null;
  let authenticatedEmail: string | null = null;

  if (token && supabaseUrl && anonKey) {
    try {
      const authClient = createClient(supabaseUrl, anonKey);
      const { data: authData, error: authError } = await authClient.auth.getUser(token);
      if (!authError && authData?.user) {
        authenticatedUserId = authData.user.id;
        authenticatedEmail = authData.user.email?.toLowerCase().trim() || null;
      }
    } catch (authErr) {
      logger.warn('[Verify Checkout] Session auth check notice:', authErr);
    }
  }

  logger.info(`[Verify Checkout] Verifying checkout: ${checkoutId} for user: ${authenticatedEmail || email || 'unauthenticated'}`);

  // 1. Enforce Polar API verification requirement
  if (!polarAccessToken) {
    logger.warn('[Verify Checkout] Polar API access token is missing');
    return NextResponse.json(
      { verified: false, status: 'unverified', error: 'Polar API verification is not configured on server' },
      { status: 500 }
    );
  }

  let isVerified = false;
  let resolvedTier: 'Pro' | 'Enterprise' = planId === 'vibecare' ? 'Enterprise' : 'Pro';
  let customerEmail = authenticatedEmail || email || null;
  let effectiveExpiry: string = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  // 2. Query Polar API for authentic checkout status
  try {
    const response = await fetch(`https://api.polar.sh/v1/checkouts/${checkoutId}`, {
      headers: {
        'Authorization': `Bearer ${polarAccessToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const checkout = await response.json();
      if (checkout.status === 'succeeded' || checkout.status === 'confirmed') {
        isVerified = true;
        customerEmail = checkout.customer_email || customerEmail;
        const prodName = (checkout.product?.name || '').toLowerCase();
        resolvedTier = prodName.includes('enterprise') || prodName.includes('suite') ? 'Enterprise' : 'Pro';

        // F-14: Read authentic subscription expiration period from Polar API if available
        if (checkout.subscription?.current_period_end) {
          const polarExpiry = new Date(checkout.subscription.current_period_end);
          if (!isNaN(polarExpiry.getTime())) {
            effectiveExpiry = polarExpiry.toISOString();
          }
        } else if (checkout.expires_at) {
          const polarExpiry = new Date(checkout.expires_at);
          if (!isNaN(polarExpiry.getTime())) {
            effectiveExpiry = polarExpiry.toISOString();
          }
        }

        logger.info(`[Verify Checkout] Verified via Polar API: ${resolvedTier} for ${customerEmail} (expires: ${effectiveExpiry})`);
      }
    }
  } catch (apiErr: any) {
    logger.warn('[Verify Checkout] Polar API check exception:', apiErr?.message);
  }

  // Reject if Polar API did not verify the checkout
  if (!isVerified) {
    return NextResponse.json(
      { verified: false, status: 'unverified', error: 'Polar API checkout verification failed or pending' },
      { status: 400 }
    );
  }

  // 3. Persist verified tier to Supabase subscriptions and metadata via direct O(1) user ID lookup (F-14)
  if (isVerified && serviceRoleKey && supabaseUrl) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      const normalizedEmail = (customerEmail || '').toLowerCase().trim();

      // Direct O(1) user ID resolution (F-14: No O(N) listUsers({ perPage: 1000 }))
      let targetUserId = authenticatedUserId;

      if (!targetUserId && normalizedEmail) {
        // Query profiles table by email
        const { data: profile } = await adminClient
          .from('profiles')
          .select('id')
          .ilike('email', normalizedEmail)
          .maybeSingle();

        if (profile?.id) {
          targetUserId = profile.id;
        }
      }

      if (targetUserId) {
        // Fetch existing metadata directly for this user (O(1))
        let existingMetadata: Record<string, unknown> = {};
        try {
          const { data: userData } = await adminClient.auth.admin.getUserById(targetUserId);
          if (userData?.user?.user_metadata) {
            existingMetadata = userData.user.user_metadata;
          }
        } catch (getUserErr) {
          logger.warn(`[Verify Checkout] getUserById error for ${targetUserId}:`, getUserErr);
        }

        // Update user metadata in auth.users
        await adminClient.auth.admin.updateUserById(targetUserId, {
          user_metadata: {
            ...existingMetadata,
            tier: resolvedTier,
            subscriptionStatus: 'active',
            expiresAt: effectiveExpiry,
            billingCycle: 'monthly',
          }
        });

        // Upsert profiles record first to satisfy foreign key constraint
        await adminClient.from('profiles').upsert({
          id: targetUserId,
          email: normalizedEmail || existingMetadata.email,
          tier: resolvedTier,
          status: 'active',
          updated_at: new Date().toISOString()
        }, { onConflict: 'id' });

        // Upsert subscriptions record
        await adminClient.from('subscriptions').upsert({
          user_id: targetUserId,
          plan_tier: resolvedTier,
          status: 'active',
          current_period_end: effectiveExpiry,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'user_id' });

        logger.info(`[Verify Checkout] Persisted subscription tier ${resolvedTier} for user ${targetUserId} (expires: ${effectiveExpiry})`);
      }
    } catch (dbErr: any) {
      logger.warn('[Verify Checkout] Database update notice:', dbErr?.message);
    }
  }

  return NextResponse.json({
    verified: true,
    status: 'confirmed',
    tier: resolvedTier,
    expiresAt: effectiveExpiry,
    email: customerEmail
  });
}
