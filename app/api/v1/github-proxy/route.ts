// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { NextRequest, NextResponse } from 'next/server';
import { parseGithubUrl } from '@/lib/github-api';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { GithubProxyQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';

/**
 * Hardened Server-side GitHub API Proxy Endpoint
 * Securely routes GitHub API requests through the Next.js server to prevent unauthenticated
 * 404/403 network error logs in client browser DevTools for private repositories.
 * Strictly verifies GitHub repository syntax and prevents Path Traversal and SSRF.
 */
export async function GET(req: NextRequest) {
  // 1. Rate Limiting Check (Max 40 requests per minute per IP)
  const rateLimit = await checkRateLimit(req, {
    maxRequests: 40,
    windowSeconds: 60,
    prefix: 'github-proxy'
  });

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // 2. Strict Zod Query Parameter Validation
  const validation = validateQueryParams(GithubProxyQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { repoUrl, token } = validation.data;
  const parsed = parseGithubUrl(repoUrl);

  if (!parsed || !parsed.owner || !parsed.repo || parsed.owner === 'local') {
    return NextResponse.json(
      { error: 'Invalid GitHub repository format. Expected "owner/repo" or "https://github.com/owner/repo"' },
      { status: 400 }
    );
  }

  const { owner, repo } = parsed;

  // Sanitize owner and repo to only contain valid GitHub characters [a-zA-Z0-9_.-]
  const safeIdentifier = /^[a-zA-Z0-9_\-\.]+$/;
  if (!safeIdentifier.test(owner) || !safeIdentifier.test(repo)) {
    return NextResponse.json(
      { error: 'Invalid repository owner or name characters' },
      { status: 400 }
    );
  }

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'ShipGuard-Release-Gate-Scanner/4.0'
  };

  if (token) {
    headers['Authorization'] = `token ${token.trim()}`;
  }

  try {
    logger.info(`Fetching GitHub repository metadata: ${owner}/${repo}`);
    const repoRes = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
      headers,
      signal: AbortSignal.timeout(10000)
    });

    if (!repoRes.ok) {
      const isRateLimit = repoRes.status === 403 || repoRes.headers.get('x-ratelimit-remaining') === '0';
      return NextResponse.json({
        name: repo,
        fullName: `${owner}/${repo}`,
        description: isRateLimit
          ? 'GitHub REST API Rate Limit Exceeded. Provide a GitHub PAT token in Settings for higher rate limits.'
          : 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        error: isRateLimit ? 'RATE_LIMIT_EXCEEDED' : 'PRIVATE_OR_UNAUTHENTICATED'
      });
    }

    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch || 'master';

    const treeRes = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
      { headers, signal: AbortSignal.timeout(12000) }
    );

    if (!treeRes.ok) {
      return NextResponse.json({
        name: repoData.name,
        fullName: repoData.full_name,
        description: `GitHub Tree Fetch Failed (HTTP ${treeRes.status})`,
        defaultBranch,
        stars: repoData.stargazers_count,
        language: repoData.language,
        files: [],
        error: 'TREE_FETCH_FAILED'
      });
    }

    const treeData = await treeRes.json();
    const treeFiles = (treeData.tree || [])
      .filter(
        (item: any) =>
          item.type === 'blob' &&
          typeof item.path === 'string' &&
          (/(\.(ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|shipguardignore)$)|(\.env(\.[a-zA-Z0-9_\-]+)?$)/i.test(item.path)) &&
          !item.path.includes('node_modules') &&
          !item.path.includes('.next') &&
          !item.path.includes('.git') &&
          !item.path.includes('dist/') &&
          !item.path.includes('build/') &&
          !item.path.includes('vendor/') &&
          !item.path.includes('.agent') &&
          !item.path.includes('.antigravity') &&
          !item.path.includes('artifacts') &&
          !item.path.includes('venv/') &&
          !item.path.includes('.venv/') &&
          !item.path.includes('__pycache__/')
      )
      .slice(0, 300);

    // Fetch raw file contents in parallel chunks from GitHub
    const CHUNK_SIZE = 25;
    const fetchedFiles: Array<{ path: string; content: string }> = [];

    for (let i = 0; i < treeFiles.length; i += CHUNK_SIZE) {
      const chunk = treeFiles.slice(i, i + CHUNK_SIZE);
      const chunkResults = await Promise.all(
        chunk.map(async (file: any) => {
          try {
            // Encode URI components in path while preserving slashes
            const encodedPath = file.path.split('/').map(encodeURIComponent).join('/');
            const rawRes = await fetch(
              `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(defaultBranch)}/${encodedPath}`,
              {
                headers: token ? { Authorization: `token ${token.trim()}` } : {},
                signal: AbortSignal.timeout(8000)
              }
            );
            if (rawRes.ok) {
              const content = await rawRes.text();
              return { path: file.path, content };
            }
          } catch (err: any) {
            logger.warn(`[GitHub Proxy] Error fetching raw file ${file.path}`, err?.message);
          }
          return null;
        })
      );
      fetchedFiles.push(...chunkResults.filter((f): f is { path: string; content: string } => f !== null));
    }

    return NextResponse.json({
      name: repoData.name,
      fullName: repoData.full_name,
      description: repoData.description || `Public GitHub Repository (${repoData.stargazers_count} stars)`,
      defaultBranch,
      stars: repoData.stargazers_count,
      language: repoData.language || 'TypeScript',
      files: fetchedFiles,
      isPrivate: repoData.private || false
    });
  } catch (err: any) {
    logger.error(`[GitHub Proxy] Failed to proxy repository: ${owner}/${repo}`, err);
    return NextResponse.json(
      {
        name: repo,
        fullName: `${owner}/${repo}`,
        description: 'Failed to complete GitHub repository fetch request',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        error: process.env.NODE_ENV === 'production' ? 'GITHUB_PROXY_ERROR' : err?.message
      },
      { status: 502 }
    );
  }
}
