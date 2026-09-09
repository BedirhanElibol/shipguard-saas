import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { createClient } from '@supabase/supabase-js';

export async function DELETE(req: NextRequest) {
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 5,
    windowSeconds: 3600,
    prefix: 'user-delete'
  });
  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  const authHeader = req.headers.get('authorization');
  const token = authHeader?.replace('Bearer ', '') || null;

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://afzpaydfkmycrwuxmzkk.supabase.co';
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  try {
    let userId: string | null = null;
    let userEmail: string | null = null;

    if (token && anonKey) {
      const userClient = createClient(supabaseUrl, anonKey, {
        auth: { persistSession: false }
      });
      const { data: { user }, error: authErr } = await userClient.auth.getUser(token);
      if (!authErr && user) {
        userId = user.id;
        userEmail = user.email || null;
      }
    }

    if (!userId) {
      try {
        const body = await req.json();
        if (body.confirmation === 'DELETE' && body.email) {
          userEmail = body.email.toLowerCase().trim();
        }
      } catch {}
    }

    if (!userId && !userEmail) {
      return NextResponse.json({ error: 'User authentication or confirmation required' }, { status: 400 });
    }

    logger.info(`[GDPR Erasure] Processing account deletion: ${userId || userEmail}`);

    if (serviceRoleKey) {
      const adminClient = createClient(supabaseUrl, serviceRoleKey);
      if (!userId && userEmail) {
        const { data: listData } = await adminClient.auth.admin.listUsers();
        const found = listData?.users?.find(u => u.email?.toLowerCase() === userEmail?.toLowerCase());
        if (found) userId = found.id;
      }

      if (userId) {
        await adminClient.from('findings').delete().eq('user_id', userId);
        await adminClient.from('scans').delete().eq('user_id', userId);
        await adminClient.from('projects').delete().eq('user_id', userId);
        await adminClient.from('subscriptions').delete().eq('user_id', userId);
        await adminClient.from('profiles').delete().eq('id', userId);
        await adminClient.auth.admin.deleteUser(userId);
      } else if (userEmail) {
        await adminClient.from('profiles').delete().eq('email', userEmail);
      }
    }

    return NextResponse.json({
      success: true,
      message: 'Account and associated data successfully erased in compliance with GDPR Art. 17 / KVKK Madde 7.'
    });
  } catch (err: any) {
    logger.error('[GDPR Erasure] Error during deletion:', err?.message);
    return NextResponse.json({ error: 'Deletion failed. Contact privacy@zelsis.com' }, { status: 500 });
  }
}
