import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

export async function GET(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 10,
    windowSeconds: 3600,
    prefix: 'user-export'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const authHeader = req.headers.get('authorization');
  const token = authHeader?.replace('Bearer ', '') || null;

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://afzpaydfkmycrwuxmzkk.supabase.co';
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!token || !anonKey) {
    return NextResponse.json({ error: 'Authentication required for data export' }, { status: 401 });
  }

  try {
    const userClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false }
    });
    const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
    if (authErr || !user) {
      return NextResponse.json({ error: 'Unauthorized request' }, { status: 401 });
    }

    // Fetch user profile and project telemetry
    const { data: profile } = await userClient.from('profiles').select('*').eq('id', user.id).maybeSingle();
    const { data: projects } = await userClient.from('projects').select('*').eq('user_id', user.id);
    const { data: scans } = await userClient.from('scans').select('*').eq('user_id', user.id);
    const { data: subscription } = await userClient.from('subscriptions').select('*').eq('user_id', user.id).maybeSingle();

    const exportPayload = {
      exportVersion: '1.0',
      exportedAt: new Date().toISOString(),
      complianceFramework: ['GDPR Article 20 (Right to Data Portability)', 'KVKK Madde 11'],
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.created_at,
        lastSignInAt: user.last_sign_in_at,
        profile: profile || null,
        subscription: subscription || null,
      },
      projects: projects || [],
      recentScans: scans || [],
    };

    logger.info(`[GDPR Portability] Exported personal data archive for user: ${user.id}`);

    return new NextResponse(JSON.stringify(exportPayload, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="zelsis-user-data-${user.id.slice(0, 8)}.json"`
      }
    });
  } catch (err: any) {
    logger.error('[GDPR Portability] Exception during export:', err?.message);
    return NextResponse.json({ error: 'Failed to generate data export' }, { status: 500 });
  }
}
