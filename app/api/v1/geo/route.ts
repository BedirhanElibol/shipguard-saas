// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitResponse, getClientIp } from '@/lib/rate-limiter';

/**
 * Edge Geolocation API Route
 * Extracts visitor geolocation telemetry from standard edge CDN headers
 * with sliding-window rate limiting and Cache-Control headers.
 */
export async function GET(req: NextRequest) {
  // 1. Sliding-Window Rate Limiting (60 requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 60,
    windowSeconds: 60,
    prefix: 'geo'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Extract edge headers and telemetry
  const country = req.headers.get('x-vercel-ip-country') || req.headers.get('cf-ipcountry') || 'Global Edge';
  const city = req.headers.get('x-vercel-ip-city') || 'Cloud Datacenter';
  const region = req.headers.get('x-vercel-ip-country-region') || '';
  const ip = getClientIp(req);
  const asNumber = req.headers.get('x-vercel-ip-as-number');
  const organization = asNumber ? `AS${asNumber}` : 'Autonomous System (Vercel Edge Network)';

  return NextResponse.json(
    {
      ip,
      country,
      city,
      region,
      organization,
      timestamp: new Date().toISOString()
    },
    {
      headers: {
        'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600'
      }
    }
  );
}

