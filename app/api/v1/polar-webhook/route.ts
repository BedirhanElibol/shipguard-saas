// Polar subscription webhook handler
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
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

/**
 * Verifies Polar / Standard Webhooks HMAC-SHA256 signatures.
 * Supports both Standard Webhooks format (v1,base64... where toSign is ${webhookId}.${timestamp}.${rawBody})
 * and raw HMAC-SHA256 hex or base64 signatures.
 */
function verifyPolarWebhookSignature(
  rawBody: string,
  headers: Headers,
  secret: string
): boolean {
  const signatureHeader =
    headers.get('webhook-signature') ||
    headers.get('polar-webhook-signature') ||
    headers.get('x-polar-signature');

  if (!signatureHeader) {
    return false;
  }

  const webhookId =
    headers.get('webhook-id') ||
    headers.get('polar-webhook-id') ||
    '';
  const timestamp =
    headers.get('webhook-timestamp') ||
    headers.get('polar-webhook-timestamp') ||
    '';

  // Support keys starting with "whsec_" (standard webhooks) as base64 or raw
  const secretKeys: Buffer[] = [];
  if (secret.startsWith('whsec_')) {
    try {
      secretKeys.push(Buffer.from(secret.slice(6), 'base64'));
    } catch {
      // Ignore decoding failure
    }
  }
  secretKeys.push(Buffer.from(secret, 'utf-8'));

  // Prepare possible signing payloads
  const payloads: string[] = [];
  if (webhookId && timestamp) {
    payloads.push(`${webhookId}.${timestamp}.${rawBody}`);
  }
  payloads.push(rawBody);

  // Signatures can be space-delimited list of tokens, e.g. "v1,abc v1,def"
  const tokens = signatureHeader.trim().split(/\s+/);

  for (const token of tokens) {
    let sigCandidate = token;
    if (token.startsWith('v1,')) {
      sigCandidate = token.slice(3);
    } else if (token.includes(',')) {
      const parts = token.split(',');
      sigCandidate = parts[parts.length - 1];
    }

    for (const key of secretKeys) {
      for (const payload of payloads) {
        try {
          const hmac = crypto.createHmac('sha256', key).update(payload, 'utf-8').digest();
          const expectedBase64 = hmac.toString('base64');
          const expectedHex = hmac.toString('hex');

          // Base64 compare
          const candBase64Buf = Buffer.from(sigCandidate, 'utf-8');
          const expBase64Buf = Buffer.from(expectedBase64, 'utf-8');
          if (candBase64Buf.length === expBase64Buf.length && crypto.timingSafeEqual(candBase64Buf, expBase64Buf)) {
            return true;
          }

          // Hex compare
          const candHexBuf = Buffer.from(sigCandidate.toLowerCase(), 'utf-8');
          const expHexBuf = Buffer.from(expectedHex.toLowerCase(), 'utf-8');
          if (candHexBuf.length === expHexBuf.length && crypto.timingSafeEqual(candHexBuf, expHexBuf)) {
            return true;
          }

          // Direct byte buffer compare (if candidate is valid base64)
          try {
            const rawCandBuf = Buffer.from(sigCandidate, 'base64');
            if (rawCandBuf.length === hmac.length && crypto.timingSafeEqual(rawCandBuf, hmac)) {
              return true;
            }
          } catch {
            // Ignore
          }
        } catch {
          // Continue trying candidates
        }
      }
    }
  }

  return false;
}

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

  const rawBody = await req.text();
  const webhookSecret = process.env.POLAR_WEBHOOK_SECRET;

  if (webhookSecret) {
    const isValid = verifyPolarWebhookSignature(rawBody, req.headers, webhookSecret);
    if (!isValid) {
      logger.warn('[Polar Webhook] Rejected webhook payload due to invalid HMAC signature');
      return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 });
    }
  } else if (process.env.NODE_ENV === 'production') {
    logger.warn('[Polar Webhook Security Warning] POLAR_WEBHOOK_SECRET is not configured in production environment. Webhook verification is bypassed.');
  }

  let body: any;
  try {
    body = JSON.parse(rawBody);
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
