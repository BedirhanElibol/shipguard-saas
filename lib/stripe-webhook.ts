import crypto from 'crypto';

/**
 * Stripe Webhook Signature Verifier
 * Uses HMAC-SHA256 and constant-time comparison to prevent timing attacks.
 * Verifies timestamp tolerance to prevent replay attacks.
 */

export const STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300; // 5 minutes

export interface StripeSignatureVerificationResult {
  valid: boolean;
  reason?: string;
}

export function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string,
  toleranceSeconds: number = STRIPE_SIGNATURE_TOLERANCE_SECONDS
): StripeSignatureVerificationResult {
  if (!signatureHeader || !secret) {
    return { valid: false, reason: 'Missing signature header or webhook secret' };
  }

  // Parse header: t=1614555821,v1=5257a869e7ec...,v0=...
  const items = signatureHeader.split(',').map((item) => item.trim());
  let timestamp: string | null = null;
  const signatures: string[] = [];

  for (const item of items) {
    const [key, value] = item.split('=');
    if (key === 't') {
      timestamp = value;
    } else if (key === 'v1') {
      signatures.push(value);
    }
  }

  if (!timestamp || signatures.length === 0) {
    return { valid: false, reason: 'Invalid stripe-signature format' };
  }

  // Check timestamp tolerance to prevent replay attacks
  const eventTime = parseInt(timestamp, 10);
  const currentTime = Math.floor(Date.now() / 1000);
  if (isNaN(eventTime) || Math.abs(currentTime - eventTime) > toleranceSeconds) {
    return { valid: false, reason: 'Webhook signature timestamp outside tolerance window (replay protection)' };
  }

  // Compute expected HMAC-SHA256 signature
  const signedPayload = `${timestamp}.${rawBody}`;
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(signedPayload, 'utf8');
  const computedSignatureHex = hmac.digest('hex');

  // Verify against all v1 signatures in header using timingSafeEqual
  const computedBuffer = Buffer.from(computedSignatureHex, 'hex');

  const match = signatures.some((candidateSig) => {
    try {
      const candidateBuffer = Buffer.from(candidateSig, 'hex');
      if (candidateBuffer.length !== computedBuffer.length) return false;
      return crypto.timingSafeEqual(candidateBuffer, computedBuffer);
    } catch {
      return false;
    }
  });

  if (!match) {
    return { valid: false, reason: 'HMAC-SHA256 signature mismatch' };
  }

  return { valid: true };
}
