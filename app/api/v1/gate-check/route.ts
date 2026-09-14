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
import { validateSafeTargetUrl } from '@/lib/ssrf-guard';

function isAllowedWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    // Only allow HTTPS
    if (parsed.protocol !== 'https:') return false;
    // Block private/internal IPs
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('172.') ||
      hostname === '169.254.169.254' ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.local')
    ) {
      return false;
    }
    // Only allow known webhook domains
    const allowedDomains = ['hooks.slack.com', 'discord.com', 'discordapp.com'];
    return allowedDomains.some(d => hostname === d || hostname.endsWith('.' + d));
  } catch {
    return false;
  }
}

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

    // Early validation of webhook URLs to prevent SSRF and avoid wasting compute
    const slackWebhookUrl = body.slackWebhookUrl || process.env.SLACK_WEBHOOK_URL;
    const discordWebhookUrl = body.discordWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

    if (slackWebhookUrl && !isAllowedWebhookUrl(slackWebhookUrl)) {
      return NextResponse.json({ error: 'Invalid Slack webhook URL' }, { status: 400 });
    }
    if (discordWebhookUrl && !isAllowedWebhookUrl(discordWebhookUrl)) {
      return NextResponse.json({ error: 'Invalid Discord webhook URL' }, { status: 400 });
    }

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
      targetName = 'Zelsis Local Workspace';
    } else if (isWebTarget) {
      const ssrfCheck = await validateSafeTargetUrl(rawRepoUrl);
      if (!ssrfCheck.safe || !ssrfCheck.url) {
        logger.warn(`[SSRF Blocked in Gate-Check] Prohibited target: ${rawRepoUrl} - Reason: ${ssrfCheck.reason}`);
        return NextResponse.json(
          {
            status: 'ERROR',
            gateStatus: 'FAILED',
            error: `SSRF Protection Blocked Request: ${ssrfCheck.reason || 'Access to internal, private, or restricted network endpoints is forbidden.'}`,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        );
      }

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
    if (slackWebhookUrl || discordWebhookUrl) {
      dispatchWebhookAlerts(targetName, rawRepoUrl, result, { slackWebhookUrl, discordWebhookUrl }).catch((err) =>
        logger.warn('[Webhook Auto-dispatch Error]:', err?.message)
      );
    }

    const failOnBlock = req.nextUrl.searchParams.get('failOnBlock') === 'true';
    const isPassed = result.gateStatus === 'PASSED';
    const statusCode = (failOnBlock && !isPassed) ? 422 : 200;

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
    service: 'Zelsis 3.0 Release Gate API Engine',
    status: 'HEALTHY',
    version: '3.0.0',
    documentation: 'Send POST requests with { repoUrl: string, githubToken?: string } to trigger automated release gate audits.'
  });
}
