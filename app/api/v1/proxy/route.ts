// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { ProxyQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';
import { logger } from '@/lib/logger';

/**
 * Hardened ShipGuard Serverless Proxy Endpoint
 * Allows server-side website fetching for live web release gate audits
 * without browser CORS restrictions or reliance on unverified third-party proxies.
 * Includes strict SSRF protection against RFC 1918 CIDRs, loopbacks, cloud metadata,
 * DNS rebinding, and port probing attacks.
 */
export async function GET(req: NextRequest) {
  // 1. Sliding-Window Rate Limit Check (Max 30 requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 30,
    windowSeconds: 60,
    prefix: 'proxy'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Server-side Zod Query Validation
  const validation = validateQueryParams(ProxyQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { url: rawUrl } = validation.data;

  // 3. Enterprise SSRF Defense: Check RFC 1918 CIDRs, IPv6, Cloud Metadata, DNS Rebinding
  const ssrfCheck = await validateSafeTargetUrl(rawUrl);
  if (!ssrfCheck.safe || !ssrfCheck.url) {
    logger.warn(`[SSRF Blocked] Prohibited request to target: ${rawUrl} - Reason: ${ssrfCheck.reason}`);
    return NextResponse.json(
      {
        error: 'SSRF Protection Blocked Request',
        message: ssrfCheck.reason || 'Access to internal, private, or restricted network endpoints is forbidden.'
      },
      { status: 403 }
    );
  }

  const targetUrl = ssrfCheck.url.toString();

  let currentUrl = targetUrl;
  let finalRes: Response | null = null;
  let redirectHops = 0;
  const MAX_REDIRECTS = 3;

  try {
    while (true) {
      logger.info(`[Proxy Fetch] Requesting verified target: ${currentUrl}`);
      const res: Response = await fetch(currentUrl, {
        headers: {
          'User-Agent': 'ShipGuard-Release-Gate-Scanner/4.0 (Enterprise Auditor)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(10000)
      });

      // Handle HTTP redirects with strict SSRF re-validation
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        redirectHops++;
        if (redirectHops > MAX_REDIRECTS) {
          return NextResponse.json(
            { error: 'SSRF Protection Blocked Request', message: 'Exceeded maximum redirect depth (3 hops).' },
            { status: 403 }
          );
        }

        const locationHeader = res.headers.get('location');
        if (!locationHeader) {
          finalRes = res;
          break;
        }

        const resolvedRedirectUrl = new URL(locationHeader, currentUrl).toString();
        const redirectCheck = await validateSafeTargetUrl(resolvedRedirectUrl);
        if (!redirectCheck.safe || !redirectCheck.url) {
          logger.warn(`[SSRF Blocked] Prohibited redirect to: ${resolvedRedirectUrl} - ${redirectCheck.reason}`);
          return NextResponse.json(
            {
              error: 'SSRF Protection Blocked Request',
              message: redirectCheck.reason || 'Redirect to restricted or internal endpoint forbidden.'
            },
            { status: 403 }
          );
        }

        currentUrl = redirectCheck.url.toString();
        continue;
      }

      finalRes = res;
      break;
    }

    if (!finalRes) {
      throw new Error('No response received from proxy target.');
    }

    const bodyText = await finalRes.text();
    const headersObj: Record<string, string> = {};

    // Forward safe HTTP response headers (excluding sensitive set-cookie)
    finalRes.headers.forEach((val, key) => {
      const lowerKey = key.toLowerCase();
      if (lowerKey !== 'set-cookie' && lowerKey !== 'set-cookie2') {
        headersObj[lowerKey] = val;
      }
    });

    return NextResponse.json({
      url: currentUrl,
      status: finalRes.status,
      statusText: finalRes.statusText,
      headers: headersObj,
      content: bodyText.slice(0, 1000000) // Cap to 1MB to prevent memory exhaustion
    });
  } catch (err: any) {
    logger.error(`[Proxy Fetch Error] Failed to fetch: ${targetUrl}`, err?.message);
    return NextResponse.json(
      {
        error: 'Proxy Fetch Failed',
        message: process.env.NODE_ENV === 'production'
          ? 'Failed to establish connection to target website.'
          : (err?.message || 'Failed to reach target URL')
      },
      { status: 502 }
    );
  }
}
