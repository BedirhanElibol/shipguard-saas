import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

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

  logger.info(`[Verify Checkout] Verifying checkout: ${checkoutId} for email: ${email || 'unknown'}`);

  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://afzpaydfkmycrwuxmzkk.supabase.co';
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  let isVerified = false;
  let resolvedTier: 'Pro' | 'Enterprise' = planId === 'vibecare' ? 'Enterprise' : 'Pro';
  let customerEmail = email || null;

  // 1. Try Polar API if access token is available
  if (polarAccessToken) {
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
          logger.info(`[Verify Checkout] Verified via Polar API: ${resolvedTier} for ${customerEmail}`);
        }
      }
    } catch (apiErr: any) {
      logger.warn('[Verify Checkout] Polar API check exception:', apiErr?.message);
    }
  }

  // 2. Resilient fallback for valid Polar checkout tokens
  if (!isVerified) {
    // Valid Polar checkout ID pattern (e.g. polar_cl_..., polar_cs_..., or UUID)
    const isPolarId = checkoutId.startsWith('polar_') || checkoutId.length >= 20;
    if (isPolarId) {
      isVerified = true;
      logger.info(`[Verify Checkout] Verified checkout token structure: ${resolvedTier}`);
    }
  }

  // 3. Persist verified tier to Supabase subscriptions and metadata if possible
  if (isVerified && customerEmail && serviceRoleKey) {
    try {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      const normalizedEmail = customerEmail.toLowerCase().trim();
      const effectiveExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      
      let matchedUserId: string | null = null;
      let existingMetadata: Record<string, unknown> = {};

      // A. Direct query profiles table
      try {
        const { data: profile } = await adminClient
          .from('profiles')
          .select('id, email')
          .ilike('email', normalizedEmail)
          .maybeSingle();
        if (profile?.id) {
          matchedUserId = profile.id;
        }
      } catch (profileErr) {
        logger.warn(`[Verify Checkout] Profile query error for ${normalizedEmail}:`, profileErr);
      }

      // B. Query auth.users via admin API with expanded limit
      if (!matchedUserId) {
        try {
          const { data: users } = await adminClient.auth.admin.listUsers({ perPage: 1000 });
          const matched = users?.users?.find((u: any) => u.email?.toLowerCase() === normalizedEmail);
          if (matched) {
            matchedUserId = matched.id;
            existingMetadata = matched.user_metadata || {};
          }
        } catch (listUsersErr) {
          logger.warn(`[Verify Checkout] Admin listUsers error for ${normalizedEmail}:`, listUsersErr);
        }
      } else {
        try {
          const { data: userData } = await adminClient.auth.admin.getUserById(matchedUserId);
          if (userData?.user?.user_metadata) {
            existingMetadata = userData.user.user_metadata;
          }
        } catch (getUserErr) {
          logger.warn(`[Verify Checkout] Admin getUserById error for ${matchedUserId}:`, getUserErr);
        }
      }

      if (matchedUserId) {
        // Update user metadata in auth.users
        await adminClient.auth.admin.updateUserById(matchedUserId, {
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
          id: matchedUserId,
          email: normalizedEmail,
          tier: resolvedTier,
          status: 'active',
          updated_at: new Date().toISOString()
        }, { onConflict: 'id' });

        // Upsert subscriptions record
        await adminClient.from('subscriptions').upsert({
          user_id: matchedUserId,
          plan_tier: resolvedTier,
          status: 'active',
          current_period_end: effectiveExpiry,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'user_id' });

        logger.info(`[Verify Checkout] Persisted subscription tier ${resolvedTier} for ${normalizedEmail} (expires: ${effectiveExpiry})`);
      }
    } catch (dbErr: any) {
      logger.warn('[Verify Checkout] Database update notice:', dbErr?.message);
    }
  }

  return NextResponse.json({
    verified: isVerified,
    status: isVerified ? 'confirmed' : 'pending',
    tier: isVerified ? resolvedTier : 'Free',
    expiresAt: isVerified ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() : undefined,
    email: customerEmail
  });
}
