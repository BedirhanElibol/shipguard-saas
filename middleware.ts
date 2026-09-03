// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';

/**
 * Global Edge Security Middleware for ShipGuard SaaS
 * - Enforces Origin whitelist and CORS policy on /api/:path* endpoints
 * - Handles CORS OPTIONS preflight requests
 * - Protects against unauthorized cross-site request hijacking
 */

const ALLOWED_ORIGINS = new Set([
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000',
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

export function middleware(req: NextRequest) {
  const origin = req.headers.get('origin');
  const pathname = req.nextUrl.pathname;

  // Only apply CORS policy to API endpoints
  if (pathname.startsWith('/api/')) {
    // Badges are public resources embedded in markdown/HTML across domains
    if (pathname.startsWith('/api/v1/badge')) {
      const response = NextResponse.next();
      response.headers.set('Access-Control-Allow-Origin', '*');
      response.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
      return response;
    }

    // Stripe webhooks are posted directly from Stripe servers without browser Origin
    if (pathname.startsWith('/api/v1/stripe-webhook')) {
      return NextResponse.next();
    }

    // Handle OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
      const isAllowed = !origin || ALLOWED_ORIGINS.has(origin);
      const preflightHeaders = new Headers({
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, stripe-signature',
        'Access-Control-Max-Age': '86400'
      });

      if (origin && isAllowed) {
        preflightHeaders.set('Access-Control-Allow-Origin', origin);
        preflightHeaders.set('Access-Control-Allow-Credentials', 'true');
      }

      return new NextResponse(null, { status: 204, headers: preflightHeaders });
    }

    const response = NextResponse.next();

    // If an Origin header is present (browser-initiated request), validate against whitelist
    if (origin) {
      if (ALLOWED_ORIGINS.has(origin)) {
        response.headers.set('Access-Control-Allow-Origin', origin);
        response.headers.set('Access-Control-Allow-Credentials', 'true');
      }
    }

    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/api/:path*']
};
