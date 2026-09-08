// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { runStaticCodeScan } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData, isValidGithubUrl, parseGithubUrl } from '@/lib/github-api';
import { fetchWebsiteAuditData, isValidWebUrl } from '@/lib/website-scanner';
import { WORKSPACE_SOURCE_FILES } from '@/data/workspaceFiles';
import { dispatchWebhookAlerts } from '@/lib/notifications';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { GateCheckRequestSchema, validateRequestBody } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';
import { canAccessLocalAudit } from '@/lib/env-config';

export async function POST(req: NextRequest) {
  try {
    // 1. Sliding-Window Rate Limiting (Max 20 audits per minute per IP)
    const rateLimit = await checkRateLimit(req, {
      maxRequests: 20,
      windowSeconds: 60,
      prefix: 'gate-check'
    });

    if (!rateLimit.allowed) {
      return createRateLimitResponse(rateLimit);
    }

    // 2. Safe JSON body extraction and Zod validation
    const rawBody = await req.json().catch(() => null);
    if (!rawBody || typeof rawBody !== 'object') {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: 'Bad Request: JSON body is missing or malformed',
          timestamp: new Date().toISOString()
        },
        { status: 400 }
      );
    }

    const validation = validateRequestBody(GateCheckRequestSchema, rawBody);
    if (!validation.success) {
      return validation.response;
    }

    const body = validation.data;
    const rawRepoUrl = (body.repoUrl || body.targetUrl || '').trim();

    const authHeader = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
    const githubToken = (body.githubToken || authHeader || '').trim() || undefined;

    const isWebTarget = isValidWebUrl(rawRepoUrl);
    const isGithubTarget = !isWebTarget && (isValidGithubUrl(rawRepoUrl) || parseGithubUrl(rawRepoUrl) !== null);

    if (!isWebTarget && !isGithubTarget && rawRepoUrl.toLowerCase() !== 'local') {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: `Bad Request: Provided URL "${rawRepoUrl}" is neither a valid GitHub repository URL nor a valid HTTP/HTTPS website URL.`,
          timestamp: new Date().toISOString()
        },
        { status: 400 }
      );
    }

    if (rawRepoUrl.toLowerCase() === 'local' && !canAccessLocalAudit()) {
      return NextResponse.json(
        {
          status: 'ERROR',
          gateStatus: 'FAILED',
          error: 'Local workspace self-audit is restricted to local development environments.',
          timestamp: new Date().toISOString()
        },
        { status: 403 }
      );
    }

    let filesToScan: typeof WORKSPACE_SOURCE_FILES = [];
    let targetName = rawRepoUrl;

    if (rawRepoUrl.toLowerCase() === 'local') {
      filesToScan = WORKSPACE_SOURCE_FILES;
      targetName = 'ShipGuard Local Workspace';
    } else if (isWebTarget) {
      logger.info(`[Gate Check] Initiating website audit for ${rawRepoUrl}`);
      const webData = await fetchWebsiteAuditData(rawRepoUrl);
      filesToScan = webData?.files || [];
      targetName = webData?.title || rawRepoUrl;
    } else if (isGithubTarget) {
      logger.info(`[Gate Check] Initiating GitHub repository audit for ${rawRepoUrl}`);
      const liveData = await fetchGithubRepositoryData(rawRepoUrl, githubToken);
      filesToScan = liveData?.files || [];
      targetName = liveData?.name || rawRepoUrl;
    }

    const result = runStaticCodeScan(filesToScan, targetName);

    // Auto-dispatch webhook notifications if URLs provided
    const slackWebhookUrl = body.slackWebhookUrl || process.env.SLACK_WEBHOOK_URL;
    const discordWebhookUrl = body.discordWebhookUrl || process.env.DISCORD_WEBHOOK_URL;
    if (slackWebhookUrl || discordWebhookUrl) {
      dispatchWebhookAlerts(targetName, rawRepoUrl, result, { slackWebhookUrl, discordWebhookUrl }).catch((err) =>
        logger.warn('[Webhook Auto-dispatch Error]:', err?.message)
      );
    }

    const isPassed = result.gateStatus === 'PASSED';
    const statusCode = isPassed ? 200 : 422;

    return NextResponse.json(
      {
        status: 'SUCCESS',
        gateStatus: result.gateStatus,
        readinessScore: result.score,
        summary: result.gateStatus === 'PASSED'
          ? 'Production Audit PASSED. All security and design compliance checks cleared.'
          : result.gateStatus === 'WARNING'
          ? `Release WARNING. Detected ${result.highCount} High and ${result.mediumCount} Medium findings. Review recommended before production deployment.`
          : `Release BLOCKED. Detected ${result.criticalCount} Critical blocker(s) requiring immediate remediation.`,
        metrics: {
          score: result.score,
          criticalCount: result.criticalCount,
          highCount: result.highCount,
          mediumCount: result.mediumCount,
          lowCount: result.lowCount,
          uiClicheCount: result.uiClicheCount,
          filesAnalyzed: filesToScan.length,
          openFindingsCount: result.findings.length
        },
        findings: result.findings.map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          category: f.category,
          filePath: f.filePath,
          lineRange: f.lineRange,
          remediationPrompt: f.remediationPrompt
        })),
        timestamp: new Date().toISOString()
      },
      { status: statusCode }
    );
  } catch (error: any) {
    logger.error('[Gate Check] Internal execution error:', error);
    return NextResponse.json(
      {
        status: 'ERROR',
        gateStatus: 'FAILED',
        error: process.env.NODE_ENV === 'production'
          ? 'Internal Release Gate Audit Error'
          : (error?.message || 'Internal Release Gate Audit Error'),
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({
    service: 'ShipGuard 3.0 Release Gate API Engine',
    status: 'HEALTHY',
    version: '3.0.0',
    documentation: 'Send POST requests with { repoUrl: string, githubToken?: string } to trigger automated release gate audits.'
  });
}
