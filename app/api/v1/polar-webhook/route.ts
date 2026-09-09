// Polar subscription webhook handler
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';

// Polar webhook events we handle
const HANDLED_EVENTS = [
  'subscription.created',
  'subscription.updated', 
  'subscription.active',
  'subscription.uncanceled',
  'subscription.canceled',
  'subscription.revoked',
  'subscription.past_due',
  'order.created',
  'order.refunded',
];

export async function POST(req: NextRequest) {
  // Rate limit: max 60 webhook events per minute
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 60,
    windowSeconds: 60,
    prefix: 'polar-webhook'
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

  const eventType = body?.type;
  if (!eventType || !HANDLED_EVENTS.includes(eventType)) {
    logger.debug(`[Polar Webhook] Unhandled event type: ${eventType}`);
    return NextResponse.json({ received: true, handled: false });
  }

  logger.info(`[Polar Webhook] Received event: ${eventType}`);

  try {
    const data = body?.data;
    const customerEmail = data?.customer?.email || data?.user?.email;
    
    if (!customerEmail) {
      logger.warn(`[Polar Webhook] No customer email in ${eventType} event`);
      return NextResponse.json({ received: true, error: 'No customer email' }, { status: 200 });
    }

    // Determine tier and subscription status based on event
    let tier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
    let status: 'active' | 'past_due' | 'canceled' = 'canceled';
    const currentPeriodEnd = data?.current_period_end || data?.subscription?.current_period_end || null;

    if (['subscription.created', 'subscription.updated', 'subscription.active', 'subscription.uncanceled', 'order.created'].includes(eventType)) {
      const productName = (data?.product?.name || data?.subscription?.product?.name || '').toLowerCase();
      tier = productName.includes('enterprise') || productName.includes('suite') ? 'Enterprise' : 'Pro';
      status = 'active';
    } else if (['subscription.past_due'].includes(eventType)) {
      // Grace period: preserve Pro/Enterprise tier during the 3-day grace period
      const productName = (data?.product?.name || data?.subscription?.product?.name || '').toLowerCase();
      tier = productName.includes('enterprise') || productName.includes('suite') ? 'Enterprise' : 'Pro';
      status = 'past_due';
    } else if (['subscription.canceled', 'subscription.revoked', 'order.refunded'].includes(eventType)) {
      tier = 'Free';
      status = 'canceled';
    }

    // Update Supabase profile and subscription records if service role key is available
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    
    if (serviceRoleKey && supabaseUrl) {
      const { createClient } = await import('@supabase/supabase-js');
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      
      // Find user by email in auth.users
      const { data: users } = await adminClient.auth.admin.listUsers();
      const matchedUser = users?.users?.find(
        (u: any) => u.email?.toLowerCase() === customerEmail.toLowerCase()
      );

      if (matchedUser) {
        const formattedTier: 'Free' | 'Pro' | 'Enterprise' =
          tier === 'Enterprise' ? 'Enterprise' : (tier === 'Pro' ? 'Pro' : 'Free');

        // 1. Update user metadata in auth.users
        try {
          await adminClient.auth.admin.updateUserById(matchedUser.id, {
            user_metadata: { tier: formattedTier, subscriptionStatus: status }
          });
        } catch (authMetaErr: any) {
          logger.warn('[Polar Webhook] User metadata update warning:', authMetaErr?.message);
        }

        // 2. Upsert subscriptions record
        try {
          await adminClient.from('subscriptions').upsert({
            user_id: matchedUser.id,
            plan_tier: formattedTier,
            status,
            current_period_end: currentPeriodEnd,
            updated_at: new Date().toISOString(),
          }, { onConflict: 'user_id' });
          logger.info(`[Polar Webhook] Upserted subscriptions for ${customerEmail} tier ${formattedTier} (status: ${status})`);
        } catch (subErr: any) {
          logger.warn('[Polar Webhook] Subscriptions table update warning:', subErr?.message);
        }

        // 3. Update profiles table updated_at
        try {
          await adminClient
            .from('profiles')
            .update({ updated_at: new Date().toISOString() })
            .eq('id', matchedUser.id);
        } catch (profileError: any) {
          logger.warn(`[Polar Webhook] Profile update notice: ${profileError?.message}`);
        }
      } else {
        logger.warn(`[Polar Webhook] No user found for email: ${customerEmail}`);
      }
    } else {
      logger.warn('[Polar Webhook] SUPABASE_SERVICE_ROLE_KEY not configured - cannot update tier server-side');
    }

    return NextResponse.json({ received: true, tier, email: customerEmail });
  } catch (err: any) {
    logger.error(`[Polar Webhook] Error processing ${eventType}:`, err?.message);
    return NextResponse.json({ error: 'Processing error' }, { status: 500 });
  }
}
