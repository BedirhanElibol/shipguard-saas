import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';

export const dynamic = 'force-dynamic';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(req: NextRequest, { params }: RouteParams) {
  try {
    const { id: jobId } = await params;

    if (!jobId || !/^[0-9a-fA-F-]{36}$/.test(jobId)) {
      return NextResponse.json(
        { status: 'ERROR', error: 'Invalid Job UUID format' },
        { status: 400 }
      );
    }

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
      return NextResponse.json(
        { status: 'ERROR', error: 'Database service configuration missing' },
        { status: 500 }
      );
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false }
    });

    const { data: job, error: jobErr } = await adminClient
      .from('scan_jobs')
      .select('*')
      .eq('id', jobId)
      .maybeSingle();

    if (jobErr) {
      logger.error('[Scan Jobs API] Database query error:', jobErr);
      return NextResponse.json(
        { status: 'ERROR', error: 'Failed to retrieve scan job' },
        { status: 500 }
      );
    }

    if (!job) {
      return NextResponse.json(
        { status: 'ERROR', error: `Scan job "${jobId}" not found` },
        { status: 404 }
      );
    }

    // BOLA/IDOR Defense: Validate caller access rights if job is bound to a tenant
    if (job.user_id) {
      const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
      const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

      let callerUserId: string | null = null;
      let isCallerAdmin = false;

      if (authHeader && anonKey) {
        try {
          const authClient = createClient(supabaseUrl, anonKey, { auth: { persistSession: false } });
          const { data: { user } } = await authClient.auth.getUser(authHeader);
          if (user) {
            callerUserId = user.id;
            const { data: profile } = await adminClient
              .from('profiles')
              .select('role')
              .eq('id', user.id)
              .maybeSingle();
            if (profile?.role === 'admin' || profile?.role === 'super_admin' || user.app_metadata?.role === 'admin') {
              isCallerAdmin = true;
            }
          }
        } catch {
          // Token decoding failure
        }
      }

      if (!callerUserId || (callerUserId !== job.user_id && !isCallerAdmin)) {
        // Return 404 to prevent malicious tenant job enumeration
        return NextResponse.json(
          { status: 'ERROR', error: `Scan job "${jobId}" not found` },
          { status: 404 }
        );
      }
    }

    // Optional: Fetch scan summary if job has finished successfully
    let scanSummary: any = null;
    if (job.status === 'COMPLETED' && job.scan_id) {
      const { data: scanRow } = await adminClient
        .from('scans')
        .select('id, readiness_score, gate_status, critical_count, high_count, medium_count, low_count, ui_cliche_count')
        .eq('id', job.scan_id)
        .maybeSingle();

      if (scanRow) {
        scanSummary = scanRow;
      }
    }

    return NextResponse.json(
      {
        status: 'SUCCESS',
        job: {
          id: job.id,
          projectId: job.project_id,
          repoUrl: job.repo_url,
          commitSha: job.commit_sha,
          status: job.status,
          progress: job.progress_percent,
          currentPhase: job.current_phase,
          currentFile: job.current_file,
          totalFiles: job.total_files,
          processedFiles: job.processed_files,
          findingsCount: job.findings_count,
          readinessScore: job.readiness_score,
          gateStatus: job.gate_status,
          scanId: job.scan_id,
          errorMessage: job.error_message,
          result: job.result_data,
          createdAt: job.created_at,
          updatedAt: job.updated_at
        },
        scanSummary
      },
      { status: 200 }
    );
  } catch (err: any) {
    logger.error('[Scan Jobs API] Unexpected error:', err);
    return NextResponse.json(
      { status: 'ERROR', error: err?.message || 'Internal job query error' },
      { status: 500 }
    );
  }
}
