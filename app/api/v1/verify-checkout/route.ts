// Server-side Polar checkout verification
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';

export async function POST(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 20,
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

  const { checkoutId } = body;
  if (!checkoutId || typeof checkoutId !== 'string') {
    return NextResponse.json({ error: 'checkout_id is required' }, { status: 400 });
  }

  logger.info(`[Verify Checkout] Verifying checkout: ${checkoutId}`);

  // For now, return a pending status - full Polar API integration requires POLAR_ACCESS_TOKEN
  // This endpoint prevents client-side bypass by centralizing verification
  const polarAccessToken = process.env.POLAR_ACCESS_TOKEN;
  
  if (!polarAccessToken) {
    logger.warn('[Verify Checkout] POLAR_ACCESS_TOKEN not configured');
    return NextResponse.json({
      verified: false,
      status: 'pending',
      message: 'Checkout verification is pending. Your subscription will be activated shortly via webhook.'
    });
  }

  try {
    // Verify with Polar API
    const response = await fetch(`https://api.polar.sh/v1/checkouts/${checkoutId}`, {
      headers: {
        'Authorization': `Bearer ${polarAccessToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      logger.warn(`[Verify Checkout] Polar API returned ${response.status}`);
      return NextResponse.json({
        verified: false,
        status: 'error',
        message: 'Unable to verify checkout. Please contact support if your subscription is not activated.'
      });
    }

    const checkout = await response.json();
    const isSuccessful = checkout.status === 'succeeded' || checkout.status === 'confirmed';
    
    return NextResponse.json({
      verified: isSuccessful,
      status: checkout.status,
      tier: isSuccessful ? 'Pro' : 'Free',
      email: checkout.customer_email || null
    });
  } catch (err: any) {
    logger.error(`[Verify Checkout] Error:`, err?.message);
    return NextResponse.json({
      verified: false,
      status: 'error',
      message: 'Verification service temporarily unavailable.'
    }, { status: 500 });
  }
}
