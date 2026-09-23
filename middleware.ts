import { NextRequest, NextResponse } from 'next/server';

/**
 * Global Edge Security Middleware for Zelsis SaaS
 * - Injects enterprise-grade security headers (HSTS, CSP, X-Frame-Options, etc.) across all routes
 * - Enforces Origin whitelist and CORS policy on /api/:path* endpoints
 * - Sanitizes client IP headers to prevent IP-spoofing rate limit bypass (VULN-10)
 * - Protects against Clickjacking (CWE-1021) and MIME sniffing (CWE-79)
 */

const ALLOWED_ORIGINS = new Set([
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000',
  'https://zelsis.com',
  'https://zelsis-saas.vercel.app',
  'https://shipguard.dev',
  'https://shipguard-saas.vercel.app'
]);

// Dynamically add production client URL from env if configured
const prodClientUrl = process.env.PRODUCTION_CLIENT_URL;
if (prodClientUrl) {
  try {
    ALLOWED_ORIGINS.add(new URL(prodClientUrl).origin);
  } catch {
    ALLOWED_ORIGINS.add(prodClientUrl);
  }
}

const nextPublicUrl = process.env.NEXT_PUBLIC_APP_URL;
if (nextPublicUrl) {
  try {
    const formatted = nextPublicUrl.startsWith('http') ? nextPublicUrl : `https://${nextPublicUrl}`;
    ALLOWED_ORIGINS.add(new URL(formatted).origin);
  } catch (_err) {
    // Ignore malformed NEXT_PUBLIC_APP_URL
  }
}

const vercelUrl = process.env.VERCEL_URL;
if (vercelUrl) {
  try {
    ALLOWED_ORIGINS.add(new URL(`https://${vercelUrl}`).origin);
  } catch (_err) {
    // Ignore malformed VERCEL_URL
  }
}

/**
 * Injects OWASP Top 10 recommended global security headers
 */
function applySecurityHeaders(res: NextResponse): NextResponse {
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('X-Content-Type-Options', 'nosniff');
  res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(self)');
  res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://api.fontshare.com; style-src 'self' 'unsafe-inline' https://api.fontshare.com https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://api.fontshare.com https://cdn.fontshare.com https://fonts.gstatic.com https://fonts.googleapis.com; connect-src 'self' https://*.supabase.co https://api.polar.sh https://api.github.com https://raw.githubusercontent.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
  );
  return res;
}

export function middleware(req: NextRequest) {
  // VULN-10: Prioritize trusted proxy IP headers to neutralize IP spoofing
  const clientIp =
    req.headers.get('cf-connecting-ip') ||
    req.headers.get('x-real-ip') ||
    req.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    '127.0.0.1';

  const requestHeaders = new Headers(req.headers);
  requestHeaders.set('x-client-ip', clientIp);

  const origin = req.headers.get('origin');
  const pathname = req.nextUrl.pathname;

  // Handle API route CORS & preflight
  if (pathname.startsWith('/api/')) {
    // Badges are public resources embedded in markdown/HTML across domains
    if (pathname.startsWith('/api/v1/badge')) {
      const response = NextResponse.next({ request: { headers: requestHeaders } });
      response.headers.set('Access-Control-Allow-Origin', '*');
      response.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
      return applySecurityHeaders(response);
    }

    // Polar webhooks are posted directly from Polar servers without browser Origin
    if (pathname.startsWith('/api/v1/polar-webhook')) {
      const response = NextResponse.next({ request: { headers: requestHeaders } });
      return applySecurityHeaders(response);
    }

    // Handle OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
      const isAllowed = origin ? ALLOWED_ORIGINS.has(origin) : false;
      if (origin && !isAllowed) {
        return new NextResponse(null, { status: 403 });
      }

      const preflightHeaders = new Headers({
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, polar-webhook-signature',
        'Access-Control-Max-Age': '86400'
      });

      if (origin && isAllowed) {
        preflightHeaders.set('Access-Control-Allow-Origin', origin);
        preflightHeaders.set('Access-Control-Allow-Credentials', 'true');
      }

      const preflightResponse = new NextResponse(null, { status: 204, headers: preflightHeaders });
      return applySecurityHeaders(preflightResponse);
    }

    const response = NextResponse.next({ request: { headers: requestHeaders } });

    // If an Origin header is present (browser-initiated request), validate against whitelist
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }

    return applySecurityHeaders(response);
  }

  // Non-API routes (HTML pages, layouts, SSR documents)
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  return applySecurityHeaders(response);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
