// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { verifyStripeSignature } from '@/lib/stripe-webhook';

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

  logger.info(`[Stripe Webhook] Successfully verified and received event: ${event?.type} (ID: ${event?.id})`);

  // 5. Handle supported Stripe event types
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data?.object;
        const customerEmail = session?.customer_details?.email || session?.customer_email;
        const clientReferenceId = session?.client_reference_id;
        logger.info(`[Stripe Webhook] Checkout completed for email: ${customerEmail}, ref: ${clientReferenceId}`);
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
        logger.info(`[Stripe Webhook] Subscription canceled: ${subscription?.id}`);
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data?.object;
        logger.info(`[Stripe Webhook] Invoice payment succeeded: ${invoice?.id} amount: ${invoice?.amount_paid}`);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data?.object;
        logger.warn(`[Stripe Webhook] Invoice payment failed: ${invoice?.id}`);
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
