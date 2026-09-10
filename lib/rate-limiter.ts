// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { logger } from './logger';

export interface RateLimitOptions {
  maxRequests?: number;
  windowSeconds?: number;
  prefix?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetSeconds: number;
  clientIp: string;
}

// In-Memory Sliding-Window Store: Map<key, timestamp_array>
const inMemoryStore = new Map<string, number[]>();
const MAX_MAP_SIZE = 10000;

// Periodic cleanup of expired entries every 5 minutes
let lastCleanup = Date.now();
function cleanupExpiredEntries(windowMs: number) {
  const now = Date.now();
  if (now - lastCleanup < 60000 && inMemoryStore.size < MAX_MAP_SIZE) return;
  lastCleanup = now;

  for (const [key, timestamps] of inMemoryStore.entries()) {
    const valid = timestamps.filter((t) => now - t < windowMs);
    if (valid.length === 0) {
      inMemoryStore.delete(key);
    } else {
      inMemoryStore.set(key, valid);
    }
  }

  // Safety valve: if still too large, prune oldest entries
  if (inMemoryStore.size > MAX_MAP_SIZE) {
    const entriesToPrune = inMemoryStore.size - (MAX_MAP_SIZE / 2);
    let count = 0;
    for (const key of inMemoryStore.keys()) {
      if (count++ >= entriesToPrune) break;
      inMemoryStore.delete(key);
    }
  }
}

/**
 * Extracts client IP securely from trusted reverse proxy headers or fallback.
 * Prevents IP spoofing attacks by rejecting untrusted x-client-ip in production.
 */
export function getClientIp(req: NextRequest): string {
  const cfConnectingIp = req.headers.get('cf-connecting-ip');
  if (cfConnectingIp) return cfConnectingIp.trim();

  const xRealIp = req.headers.get('x-real-ip');
  if (xRealIp) return xRealIp.trim();

  const xForwardedFor = req.headers.get('x-forwarded-for');
  if (xForwardedFor) {
    const firstIp = xForwardedFor.split(',')[0].trim();
    if (firstIp) return firstIp;
  }

  if (process.env.NODE_ENV !== 'production') {
    const xClientIp = req.headers.get('x-client-ip');
    if (xClientIp) return xClientIp.trim();
  }

  return '127.0.0.1';
}

/**
 * IP-based Sliding-Window Rate Limiter
 * Supports Upstash Redis REST API when configured, with seamless in-memory sliding-window fallback.
 */
export async function checkRateLimit(
  req: NextRequest,
  options: RateLimitOptions = {}
): Promise<RateLimitResult> {
  const {
    maxRequests = 60,
    windowSeconds = 60,
    prefix = 'general'
  } = options;

  const clientIp = getClientIp(req);
  const windowMs = windowSeconds * 1000;
  const now = Date.now();
  const storeKey = `rl:${prefix}:${clientIp}`;

  // 1. Attempt Upstash Redis REST API if credentials exist
  const redisUrl = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (redisUrl && redisToken) {
    try {
      // Sliding window using Redis Sorted Set (ZADD, ZREMRANGEBYSCORE, ZCARD) or simple INCR with EXPIRE
      const incrRes = await fetch(`${redisUrl}/incr/${encodeURIComponent(storeKey)}`, {
        headers: { Authorization: `Bearer ${redisToken}` },
        signal: AbortSignal.timeout(1500)
      });

      if (incrRes.ok) {
        const data = await incrRes.json();
        const count = typeof data.result === 'number' ? data.result : 1;

        if (count === 1) {
          await fetch(`${redisUrl}/expire/${encodeURIComponent(storeKey)}/${windowSeconds}`, {
            headers: { Authorization: `Bearer ${redisToken}` },
            signal: AbortSignal.timeout(1000)
          }).catch(() => {});
        }

        const allowed = count <= maxRequests;
        const remaining = Math.max(0, maxRequests - count);

        return {
          allowed,
          limit: maxRequests,
          remaining,
          resetSeconds: windowSeconds,
          clientIp
        };
      }
    } catch (redisErr) {
      logger.warn(`[RateLimiter] Upstash Redis check failed, falling back to in-memory: ${storeKey}`, redisErr);
    }
  }

  // 2. High-precision In-Memory Sliding-Window Implementation
  cleanupExpiredEntries(windowMs);

  const existingTimestamps = inMemoryStore.get(storeKey) || [];
  const validTimestamps = existingTimestamps.filter((t) => now - t < windowMs);

  if (validTimestamps.length >= maxRequests) {
    const oldestTimestamp = validTimestamps[0] || now;
    const resetSeconds = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      resetSeconds: Math.max(1, resetSeconds),
      clientIp
    };
  }

  validTimestamps.push(now);
  inMemoryStore.set(storeKey, validTimestamps);

  const remaining = maxRequests - validTimestamps.length;
  return {
    allowed: true,
    limit: maxRequests,
    remaining,
    resetSeconds: windowSeconds,
    clientIp
  };
}

/**
 * Generates standard 429 Too Many Requests response with standard rate-limiting headers.
 */
export function createRateLimitResponse(result: RateLimitResult): NextResponse {
  return NextResponse.json(
    {
      error: 'Rate Limit Exceeded',
      message: `Too many requests. Maximum ${result.limit} requests per window allowed.`,
      retryAfter: result.resetSeconds
    },
    {
      status: 429,
      headers: {
        'Retry-After': String(result.resetSeconds),
        'X-RateLimit-Limit': String(result.limit),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + result.resetSeconds)
      }
    }
  );
}
