// Polar subscription webhook handler
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';

// Polar webhook events we handle
const HANDLED_EVENTS = [
  'subscription.created',
  'subscription.updated', 
  'subscription.active',
  'subscription.canceled',
  'subscription.revoked',
  'order.created',
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

    // Determine tier based on event
    let tier: string = 'Free';
    if (['subscription.created', 'subscription.updated', 'subscription.active', 'order.created'].includes(eventType)) {
      const productName = data?.product?.name?.toLowerCase() || '';
      tier = productName.includes('enterprise') || productName.includes('suite') ? 'Enterprise' : 'Pro';
    } else if (['subscription.canceled', 'subscription.revoked'].includes(eventType)) {
      tier = 'Free';
    }

    // Update Supabase profile if service role key is available
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
        // Update profile tier
        const { error: profileError } = await adminClient
          .from('profiles')
          .update({ tier, updated_at: new Date().toISOString() })
          .eq('id', matchedUser.id);

        if (profileError) {
          logger.warn(`[Polar Webhook] Profile update failed: ${profileError.message}`);
        } else {
          logger.info(`[Polar Webhook] Updated ${customerEmail} tier to ${tier}`);
        }

        // Update user metadata
        await adminClient.auth.admin.updateUserById(matchedUser.id, {
          user_metadata: { tier }
        });
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
