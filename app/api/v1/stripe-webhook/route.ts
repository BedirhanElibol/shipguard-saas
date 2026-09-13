// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { verifyStripeSignature } from '@/lib/stripe-webhook';
import { getSupabase } from '@/lib/supabase';

// In-memory idempotency cache for processed Stripe event IDs (VULN-08)
const PROCESSED_WEBHOOK_EVENTS = new Set<string>();
const MAX_IDEMPOTENCY_CACHE = 5000;

export async function POST(req: NextRequest) {
  // 1. Rate Limiting Check (Max 60 webhook events per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 60,
    windowSeconds: 60,
    prefix: 'stripe-webhook'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    logger.error('[Stripe Webhook] STRIPE_WEBHOOK_SECRET environment variable is not configured');
    return NextResponse.json(
      { error: 'Webhook secret is not configured on server' },
      { status: 500 }
    );
  }

  // 2. Read raw request body as text (mandatory for HMAC verification)
  let rawBody: string;
  try {
    rawBody = await req.text();
  } catch (err: any) {
    logger.error('[Stripe Webhook] Failed to read request body', err?.message);
    return NextResponse.json({ error: 'Failed to read request body' }, { status: 400 });
  }

  // 3. Extract and verify stripe-signature header
  const signatureHeader = req.headers.get('stripe-signature');
  if (!signatureHeader) {
    logger.warn('[Stripe Webhook] Missing "stripe-signature" header');
    return NextResponse.json(
      { error: 'Missing stripe-signature header' },
      { status: 400 }
    );
  }

  const verification = verifyStripeSignature(rawBody, signatureHeader, webhookSecret);
  if (!verification.valid) {
    logger.warn(`[Stripe Webhook] Verification failed: ${verification.reason}`);
    return NextResponse.json(
      { error: 'Invalid Stripe signature', details: verification.reason },
      { status: 400 }
    );
  }

  // 4. Safely parse verified event payload
  let event: any;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    logger.error('[Stripe Webhook] Failed to parse JSON event body');
    return NextResponse.json({ error: 'Malformed JSON payload' }, { status: 400 });
  }

  // VULN-08: Webhook Idempotency Check
  if (event?.id) {
    if (PROCESSED_WEBHOOK_EVENTS.has(event.id)) {
      logger.info(`[Stripe Webhook] Duplicate event detected (ID: ${event.id}), skipping duplicate processing.`);
      return NextResponse.json({ received: true, deduplicated: true }, { status: 200 });
    }

    if (PROCESSED_WEBHOOK_EVENTS.size >= MAX_IDEMPOTENCY_CACHE) {
      const oldestKey = PROCESSED_WEBHOOK_EVENTS.values().next().value;
      if (oldestKey) PROCESSED_WEBHOOK_EVENTS.delete(oldestKey);
    }
    PROCESSED_WEBHOOK_EVENTS.add(event.id);
  }

  logger.info(`[Stripe Webhook] Successfully verified and received event: ${event?.type} (ID: ${event?.id})`);

  // 5. Handle supported Stripe event types
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data?.object;
        const customerEmail = session?.customer_details?.email || session?.customer_email;
        const clientReferenceId = session?.client_reference_id;
        const metadata = session?.metadata || {};
        const tier = metadata.tier || (session?.amount_total && session.amount_total > 5000 ? 'Enterprise' : 'Pro');

        logger.info(`[Stripe Webhook] Checkout completed for email: ${customerEmail}, ref: ${clientReferenceId}, tier: ${tier}`);

        // Synchronize tier to Supabase using service role if configured
        if (customerEmail) {
          const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (serviceRoleKey && supabaseUrl) {
            try {
              const { createClient } = await import('@supabase/supabase-js');
              const adminClient = createClient(supabaseUrl, serviceRoleKey);
              const { data: users } = await adminClient.auth.admin.listUsers();
              const matchedUser = users?.users?.find(
                (u: { email?: string; id: string }) => u.email?.toLowerCase() === customerEmail.toLowerCase()
              );
              if (matchedUser) {
                await adminClient.auth.admin.updateUserById(matchedUser.id, {
                  user_metadata: { tier, subscriptionStatus: 'active' }
                });
                await adminClient.from('subscriptions').upsert({
                  user_id: matchedUser.id,
                  plan_tier: tier,
                  status: 'active',
                  current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
                  updated_at: new Date().toISOString()
                }, { onConflict: 'user_id' });
              }
            } catch (adminErr: any) {
              logger.warn(`[Stripe Webhook] Admin sync notice: ${adminErr?.message}`);
            }
          }

          const supabase = getSupabase();
          if (supabase) {
            try {
              await supabase
                .from('profiles')
                .update({ tier, updated_at: new Date().toISOString() })
                .eq('email', customerEmail);
            } catch (syncErr: any) {
              logger.warn(`[Stripe Webhook] Supabase sync exception: ${syncErr?.message}`);
            }
          }
        }
        break;
      }

      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const subscription = event.data?.object;
        logger.info(`[Stripe Webhook] Subscription event "${event.type}" for customer: ${subscription?.customer}, status: ${subscription?.status}`);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data?.object;
        const cancelEmail = subscription?.customer_email || subscription?.metadata?.email;
        logger.info(`[Stripe Webhook] Subscription canceled: ${subscription?.id}, email: ${cancelEmail}`);
        
        // Downgrade user tier to Free
        if (cancelEmail) {
          const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (serviceRoleKey && supabaseUrl) {
            try {
              const { createClient } = await import('@supabase/supabase-js');
              const adminClient = createClient(supabaseUrl, serviceRoleKey);
              const { data: users } = await adminClient.auth.admin.listUsers();
              const matchedUser = users?.users?.find(
                (u: { email?: string; id: string }) => u.email?.toLowerCase() === cancelEmail.toLowerCase()
              );
              if (matchedUser) {
                await adminClient.auth.admin.updateUserById(matchedUser.id, {
                  user_metadata: { tier: 'Free', subscriptionStatus: 'canceled' }
                });
                await adminClient.from('subscriptions').upsert({
                  user_id: matchedUser.id,
                  plan_tier: 'Free',
                  status: 'canceled',
                  updated_at: new Date().toISOString()
                }, { onConflict: 'user_id' });
              }
            } catch (adminErr: any) {
              logger.warn(`[Stripe Webhook] Admin cancel notice: ${adminErr?.message}`);
            }
          }

          const supabase = getSupabase();
          if (supabase) {
            await supabase
              .from('profiles')
              .update({ tier: 'Free', updated_at: new Date().toISOString() })
              .eq('email', cancelEmail);
            logger.info(`[Stripe Webhook] Downgraded ${cancelEmail} to Free tier`);
          }
        }
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data?.object;
        logger.info(`[Stripe Webhook] Invoice payment succeeded: ${invoice?.id} amount: ${invoice?.amount_paid}`);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data?.object;
        const failedEmail = invoice?.customer_email;
        logger.warn(`[Stripe Webhook] Invoice payment failed: ${invoice?.id}, email: ${failedEmail}`);
        
        // After 3 failed attempts, downgrade to Free
        const attemptCount = invoice?.attempt_count || 0;
        if (failedEmail && attemptCount >= 3) {
          const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
          const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
          if (serviceRoleKey && supabaseUrl) {
            try {
              const { createClient } = await import('@supabase/supabase-js');
              const adminClient = createClient(supabaseUrl, serviceRoleKey);
              const { data: users } = await adminClient.auth.admin.listUsers();
              const matchedUser = users?.users?.find(
                (u: { email?: string; id: string }) => u.email?.toLowerCase() === failedEmail.toLowerCase()
              );
              if (matchedUser) {
                await adminClient.auth.admin.updateUserById(matchedUser.id, {
                  user_metadata: { tier: 'Free', subscriptionStatus: 'past_due' }
                });
              }
            } catch (adminErr: any) {
              logger.warn(`[Stripe Webhook] Admin failed payment notice: ${adminErr?.message}`);
            }
          }

          const supabase = getSupabase();
          if (supabase) {
            await supabase
              .from('profiles')
              .update({ tier: 'Free', updated_at: new Date().toISOString() })
              .eq('email', failedEmail);
            logger.warn(`[Stripe Webhook] Downgraded ${failedEmail} to Free after ${attemptCount} failed payments`);
          }
        }
        break;
      }

      default:
        logger.debug(`[Stripe Webhook] Unhandled event type: ${event.type}`);
    }

    return NextResponse.json({ received: true, eventId: event?.id });
  } catch (err: any) {
    logger.error(`[Stripe Webhook] Error processing event ${event?.type}`, err);
    return NextResponse.json(
      { error: 'Webhook event processing error' },
      { status: 500 }
    );
  }
}
