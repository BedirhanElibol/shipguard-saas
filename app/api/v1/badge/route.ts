import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { BadgeQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { escapeSvgText } from '@/lib/sanitize';

/**
 * Hardened Dynamic SVG Shield Badge Generator Endpoint
 * Usage: GET /api/v1/badge?status=PASSED&score=98&label=Zelsis
 * Returns a secure, high-res SVG shield badge for GitHub README.md files.
 * Enforces Zod validation, sliding-window rate limiting, and strict XML/SVG escaping
 * to prevent SVG-based Cross-Site Scripting (XSS) and XML Entity Injection.
 */
export async function GET(req: NextRequest) {
  // 1. Rate Limiting Check (Max 120 badge requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 120,
    windowSeconds: 60,
    prefix: 'badge'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Strict Zod Parameter Validation
  const validation = validateQueryParams(BadgeQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { status, score, label } = validation.data;

  const isPassed = status === 'PASSED';
  const isWarning = status === 'WARNING';

  const statusBg = isPassed ? '#10B981' : isWarning ? '#F59E0B' : '#EF4444';
  const rawStatusText = isPassed ? `PASSED ${score}%` : isWarning ? `WARNING ${score}%` : `FAILED (${score}%)`;

  // 3. Prevent SVG XML injection with rigorous XML entity escaping
  const safeLabel = escapeSvgText(label, 32);
  const safeStatusText = escapeSvgText(rawStatusText, 32);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="28" viewBox="0 0 220 28" fill="none">
  <rect width="220" height="28" rx="6" fill="#141414" stroke="#ffffff1a"/>
  <rect x="1" y="1" width="125" height="26" rx="5" fill="#0A0A0A"/>
  <text x="12" y="18" fill="#F5F3EF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="800" letter-spacing="0.5">${safeLabel}</text>
  <rect x="130" y="4" width="84" height="20" rx="4" fill="${statusBg}"/>
  <text x="172" y="18" fill="#0A0A0A" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="900" text-anchor="middle" letter-spacing="0.5">${safeStatusText}</text>
</svg>`;

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
      'Cache-Control': 'public, max-age=60, s-maxage=300'
    }
  });
}
