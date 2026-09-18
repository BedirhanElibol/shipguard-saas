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

  // Enforce timestamp freshness: reject payloads older than 5 minutes (300 seconds) or in the future
  if (timestamp) {
    const tsNum = parseInt(timestamp, 10);
    if (isNaN(tsNum)) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const eventSec = tsNum > 1e11 ? Math.floor(tsNum / 1000) : tsNum;
    if (Math.abs(nowSec - eventSec) > 300) {
      logger.warn('[Polar Webhook] Rejected webhook payload due to stale/future timestamp');
      return false;
    }
  }

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
  if (process.env.NODE_ENV === 'production' && !webhookSecret) {
    logger.error('[Polar Webhook] POLAR_WEBHOOK_SECRET is not configured in production environment. Rejecting request for security.');
    return NextResponse.json({ error: 'Webhook configuration error' }, { status: 500 });
  }

  if (webhookSecret) {
    const isValid = verifyPolarWebhookSignature(rawBody, req.headers, webhookSecret);
    if (!isValid) {
      logger.warn('[Polar Webhook] Rejected webhook payload due to invalid HMAC signature');
      return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 });
    }
  }

  let body: {
    type?: string;
    data?: {
      id?: string;
      subscription_id?: string;
      metadata?: Record<string, unknown>;
      customer?: { email?: string };
      user?: { email?: string };
      product?: { name?: string };
      current_period_end?: string | null;
      subscription?: {
        id?: string;
        metadata?: Record<string, unknown>;
        current_period_end?: string | null;
        product?: { name?: string };
      };
    };
  } | null = null;
  try {
    body = JSON.parse(rawBody);
  } catch (parseErr) {
    void parseErr;
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
    const productName = (data?.product?.name || data?.subscription?.product?.name || '').toLowerCase();
    const isAnnual = productName.includes('annual') || productName.includes('year');
    const detectedTier: 'Pro' | 'Enterprise' =
      productName.includes('enterprise') || productName.includes('suite') ? 'Enterprise' : 'Pro';

    const rawPeriodEnd = data?.current_period_end || data?.subscription?.current_period_end || null;
    const periodEndTime = rawPeriodEnd ? new Date(rawPeriodEnd).getTime() : 0;
    const isFuturePeriodEnd = periodEndTime > Date.now();

    if (['subscription.created', 'subscription.updated', 'subscription.active', 'subscription.uncanceled', 'order.created'].includes(eventType)) {
      tier = detectedTier;
      status = 'active';
    } else if (['subscription.past_due'].includes(eventType)) {
      // Per strict user directive: zero grace period extension on renewal failure.
      // If the current paid period is still valid, user keeps access until period ends.
      // If already past period end, access is revoked immediately.
      status = 'past_due';
      tier = isFuturePeriodEnd ? detectedTier : 'Free';
    } else if (['subscription.canceled'].includes(eventType)) {
      // Cancellation means do not renew next cycle; user keeps remaining paid time
      status = 'canceled';
      tier = isFuturePeriodEnd ? detectedTier : 'Free';
    } else if (['subscription.revoked', 'order.refunded'].includes(eventType)) {
      // Immediate revocation or refund drops tier instantly
      tier = 'Free';
      status = 'canceled';
    }

    let effectiveCurrentPeriodEnd: string;
    if (rawPeriodEnd) {
      effectiveCurrentPeriodEnd = new Date(rawPeriodEnd).toISOString();
    } else if (status === 'active' || (tier !== 'Free' && isFuturePeriodEnd)) {
      const daysToAdd = isAnnual ? 365 : 30;
      effectiveCurrentPeriodEnd = new Date(Date.now() + daysToAdd * 24 * 60 * 60 * 1000).toISOString();
    } else {
      effectiveCurrentPeriodEnd = new Date().toISOString();
    }

    // Update Supabase profile and subscription records if service role key is available
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    
    if (serviceRoleKey && supabaseUrl) {
      const { createClient } = await import('@supabase/supabase-js');
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      
      const normalizedEmail = customerEmail.toLowerCase().trim();
      const metadataUserId = (data?.metadata?.userId || data?.metadata?.user_id || data?.subscription?.metadata?.userId) as string | undefined;
      let matchedUserId: string | null = metadataUserId || null;
      let existingMetadata: Record<string, unknown> = {};

      // 1. Direct query in profiles table by case-insensitive email
      if (!matchedUserId) {
        try {
          const { data: profile } = await adminClient
            .from('profiles')
            .select('id, email')
            .ilike('email', normalizedEmail)
            .maybeSingle();
          if (profile?.id) {
            matchedUserId = profile.id;
          }
        } catch (profileLookupErr) {
          void profileLookupErr;
        }
      }

      // 2. Query auth.users via admin API with expanded perPage limit
      if (!matchedUserId) {
        try {
          const { data: users } = await adminClient.auth.admin.listUsers({ perPage: 1000 });
          const matchedUser = users?.users?.find(
            (u: { email?: string; id: string; user_metadata?: Record<string, unknown> }) =>
              u.email?.toLowerCase() === normalizedEmail
          );
          if (matchedUser) {
            matchedUserId = matchedUser.id;
            existingMetadata = matchedUser.user_metadata || {};
          }
        } catch (adminListErr) {
          void adminListErr;
        }
      } else {
        try {
          const { data: userData } = await adminClient.auth.admin.getUserById(matchedUserId);
          if (userData?.user?.user_metadata) {
            existingMetadata = userData.user.user_metadata;
          }
        } catch (fetchUserErr) {
          void fetchUserErr;
        }
      }

      if (matchedUserId) {
        const formattedTier: 'Free' | 'Pro' | 'Enterprise' =
          tier === 'Enterprise' ? 'Enterprise' : (tier === 'Pro' ? 'Pro' : 'Free');

        // A. Update user metadata in auth.users with complete subscription lifecycle properties
        try {
          await adminClient.auth.admin.updateUserById(matchedUserId, {
            user_metadata: {
              ...existingMetadata,
              tier: formattedTier,
              subscriptionStatus: status,
              expiresAt: effectiveCurrentPeriodEnd,
              billingCycle: isAnnual ? 'annual' : 'monthly',
              lastPaymentEvent: eventType,
              lastPaymentDate: new Date().toISOString(),
            }
          });
          logger.info(`[Polar Webhook] Synced auth user_metadata for ${normalizedEmail} (ID: ${matchedUserId}) -> ${formattedTier} (expires: ${effectiveCurrentPeriodEnd})`);
        } catch (authMetaErr: unknown) {
          logger.warn('[Polar Webhook] User metadata update warning:', authMetaErr instanceof Error ? authMetaErr.message : String(authMetaErr));
        }

        // B. Upsert profiles table first to satisfy foreign key constraint on subscriptions
        try {
          await adminClient.from('profiles').upsert({
            id: matchedUserId,
            email: normalizedEmail,
            tier: formattedTier,
            status,
            updated_at: new Date().toISOString()
          }, { onConflict: 'id' });
          logger.info(`[Polar Webhook] Upserted profiles record for ${normalizedEmail} (tier: ${formattedTier}, status: ${status})`);
        } catch (profileError: unknown) {
          logger.warn(`[Polar Webhook] Profile upsert notice: ${profileError instanceof Error ? profileError.message : String(profileError)}`);
        }

        // C. Upsert subscriptions record with complete period end
        try {
          await adminClient.from('subscriptions').upsert({
            user_id: matchedUserId,
            plan_tier: formattedTier,
            status,
            current_period_end: effectiveCurrentPeriodEnd,
            polar_subscription_id: data?.id || data?.subscription_id || null,
            updated_at: new Date().toISOString(),
          }, { onConflict: 'user_id' });
          logger.info(`[Polar Webhook] Upserted subscriptions record for ${normalizedEmail} (tier: ${formattedTier}, status: ${status})`);
        } catch (subErr: unknown) {
          logger.warn('[Polar Webhook] Subscriptions table update warning:', subErr instanceof Error ? subErr.message : String(subErr));
        }
      } else {
        logger.warn(`[Polar Webhook] No registered user found for email: ${normalizedEmail}. Pending account registration.`);
      }
    } else {
      logger.warn('[Polar Webhook] SUPABASE_SERVICE_ROLE_KEY not configured - cannot update tier server-side');
    }

    return NextResponse.json({ received: true, tier, email: customerEmail });
  } catch (err: unknown) {
    logger.error(`[Polar Webhook] Error processing ${eventType}:`, err instanceof Error ? err.message : String(err));
    return NextResponse.json({ error: 'Processing error' }, { status: 500 });
  }
}
