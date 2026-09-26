import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { checkRateLimit, createRateLimitResponse, getClientIp } from '@/lib/rate-limiter';

/**
 * Edge Geolocation API Route
 * Extracts visitor geolocation telemetry from standard edge CDN headers
 * with sliding-window rate limiting, ETag hashing, and stale-while-revalidate caching.
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

  const payload = {
    ip,
    country,
    city,
    region,
    organization,
    timestamp: new Date().toISOString()
  };

  const payloadStr = JSON.stringify(payload);
  const etag = `"${crypto.createHash('sha256').update(`${ip}:${country}:${city}:${region}`).digest('base64url').substring(0, 27)}"`;
  const ifNoneMatch = req.headers.get('if-none-match');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'private, max-age=60, s-maxage=60, stale-while-revalidate=300',
    'ETag': etag,
    'Vary': 'Accept-Encoding, x-vercel-ip, cf-connecting-ip'
  };

  if (ifNoneMatch && ifNoneMatch === etag) {
    return new NextResponse(null, { status: 304, headers });
  }

  return new NextResponse(payloadStr, { headers });
}

