import { NextRequest, NextResponse } from 'next/server';
import { parseGithubUrl } from '@/lib/github-api';
import { checkRateLimit, createRateLimitResponse } from '@/lib/rate-limiter';
import { GithubProxyQuerySchema, validateQueryParams } from '@/lib/validations/api-schemas';
import { logger } from '@/lib/logger';

const GITHUB_RATE_LIMIT_MESSAGE =
  'GitHub API rate limit reached (60 req/hr). Add a GitHub Personal Access Token (PAT) in Settings to unlock 5,000 req/hr.';

/**
 * Checks whether a GitHub API response indicates a primary or secondary rate limit.
 */
function isGitHubRateLimited(status: number, headers: Headers, bodyText: string = '', hasToken: boolean = false): boolean {
  if (status === 429) return true;
  if (headers.get('x-ratelimit-remaining') === '0') return true;
  if (headers.has('retry-after')) return true;
  if (status === 403) {
    if (headers.get('x-ratelimit-remaining') === '0') return true;
    if (/rate limit|secondary rate|abuse detection/i.test(bodyText)) return true;
    if (!hasToken) return true;
  }
  return false;
}

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

  // 2. Prohibit credential transmission via URL query string (CWE-598)
  if (req.nextUrl.searchParams.has('token')) {
    return NextResponse.json(
      {
        error: 'Insecure Credential Transmission (CWE-598)',
        message: 'Passing GitHub tokens in URL query string is prohibited due to CWE-598. Pass via Authorization: Bearer header.'
      },
      { status: 400 }
    );
  }

  // 3. Strict Zod Query Parameter Validation
  const validation = validateQueryParams(GithubProxyQuerySchema, req.nextUrl.searchParams);
  if (!validation.success) {
    return validation.response;
  }

  const { repoUrl } = validation.data;
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

  // 4. Secure Token Extraction: Read from Authorization header or server environment fallback
  const authHeader = req.headers.get('authorization');
  const userToken = authHeader?.replace(/^Bearer\s+/i, '').trim() || undefined;
  const serverToken = process.env.GITHUB_TOKEN || process.env.GITHUB_PAT || undefined;
  const token = userToken || serverToken;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Zelsis-Release-Gate-Scanner/4.0'
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    logger.info(`Fetching GitHub repository metadata: ${owner}/${repo}`);
    const repoRes = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
      headers,
      signal: AbortSignal.timeout(10000)
    });

    if (!repoRes.ok) {
      let bodyText = '';
      try {
        bodyText = await repoRes.text();
      } catch {
        bodyText = '';
      }

      const isRateLimit = isGitHubRateLimited(repoRes.status, repoRes.headers, bodyText, Boolean(token));

      return NextResponse.json({
        name: repo,
        fullName: `${owner}/${repo}`,
        description: isRateLimit
          ? GITHUB_RATE_LIMIT_MESSAGE
          : 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        message: isRateLimit
          ? GITHUB_RATE_LIMIT_MESSAGE
          : 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [],
        error: isRateLimit ? 'RATE_LIMIT_EXCEEDED' : 'PRIVATE_OR_UNAUTHENTICATED'
      });
    }

    const repoData = await repoRes.json();
    const detectedBranch = typeof repoData.default_branch === 'string' && repoData.default_branch
      ? repoData.default_branch
      : 'main';

    // Handle empty repository immediately if size is 0
    if (typeof repoData.size === 'number' && repoData.size === 0) {
      return NextResponse.json({
        name: repoData.name || repo,
        fullName: repoData.full_name || `${owner}/${repo}`,
        description: repoData.description || 'Empty GitHub Repository (0 commits)',
        defaultBranch: detectedBranch,
        stars: repoData.stargazers_count || 0,
        language: repoData.language || 'None',
        files: [
          {
            path: 'README.md',
            content: `# ${repoData.name || repo}\n\nEmpty repository. No source files committed yet.`
          }
        ],
        isEmpty: true
      });
    }

    // Default branch detection with fallback checks for main, master, and develop
    const candidateBranches = Array.from(
      new Set([detectedBranch, 'main', 'master', 'develop'].filter(Boolean))
    );
    let treeRes: Response | null = null;
    let activeBranch = detectedBranch;

    for (const branch of candidateBranches) {
      try {
        const res = await fetch(
          `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
          { headers, signal: AbortSignal.timeout(12000) }
        );
        if (res.ok) {
          treeRes = res;
          activeBranch = branch;
          break;
        } else if (res.status === 409) {
          // GitHub returns 409 Conflict when repository is empty
          treeRes = res;
          activeBranch = branch;
          break;
        } else if (res.status === 403 || res.status === 429 || res.headers.get('x-ratelimit-remaining') === '0') {
          treeRes = res;
          break;
        }
      } catch {
        // Fallback to next branch candidate
      }
    }

    if (!treeRes || !treeRes.ok) {
      // Empty repository handling (409 Conflict)
      if (treeRes && treeRes.status === 409) {
        return NextResponse.json({
          name: repoData.name || repo,
          fullName: repoData.full_name || `${owner}/${repo}`,
          description: repoData.description || 'Empty GitHub Repository (0 commits)',
          defaultBranch: activeBranch,
          stars: repoData.stargazers_count || 0,
          language: repoData.language || 'None',
          files: [
            {
              path: 'README.md',
              content: `# ${repoData.name || repo}\n\nEmpty repository. No source files committed yet.`
            }
          ],
          isEmpty: true
        });
      }

      // Check if rate limited during tree fetch
      let treeBody = '';
      try {
        if (treeRes) treeBody = await treeRes.text();
      } catch {
        treeBody = '';
      }
      const isTreeRateLimit = treeRes ? isGitHubRateLimited(treeRes.status, treeRes.headers, treeBody, Boolean(token)) : false;

      if (isTreeRateLimit) {
        return NextResponse.json({
          name: repoData.name || repo,
          fullName: repoData.full_name || `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          message: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: activeBranch,
          stars: repoData.stargazers_count || 0,
          language: repoData.language || 'TypeScript',
          files: [],
          error: 'RATE_LIMIT_EXCEEDED'
        });
      }

      return NextResponse.json({
        name: repoData.name,
        fullName: repoData.full_name,
        description: `GitHub Tree Fetch Failed (HTTP ${treeRes ? treeRes.status : 'Unknown'})`,
        defaultBranch: activeBranch,
        stars: repoData.stargazers_count,
        language: repoData.language,
        files: [],
        error: 'TREE_FETCH_FAILED'
      });
    }

    let treeData: { tree?: Array<{ type: string; path: string; size?: number }> } = {};
    try {
      treeData = await treeRes.json();
    } catch {
      treeData = { tree: [] };
    }

    const treeFiles = (treeData.tree || [])
      .filter(
        (item: any) =>
          item.type === 'blob' &&
          typeof item.path === 'string' &&
          (!item.size || item.size <= 2000000) &&
          (/(\.(ts|tsx|js|jsx|json|css|sql|html|py|yml|yaml|toml|sh|ps1|c|cpp|cc|cxx|h|hpp|java|kt|kts|go|rs|php|cs|rb|swift|xml|plist|gradle|md|mdx|zelsisignore|shipguardignore)$)|(\.env(\.[a-zA-Z0-9_\-]+)?$)|((?:^|\/)(?:dockerfile|makefile|podfile)$)/i.test(item.path)) &&
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
      .slice(0, 150);

    if (treeFiles.length === 0) {
      return NextResponse.json({
        name: repoData.name,
        fullName: repoData.full_name,
        description: repoData.description || 'Empty GitHub Repository (0 scannable files)',
        defaultBranch: activeBranch,
        stars: repoData.stargazers_count,
        language: repoData.language || 'TypeScript',
        files: [
          {
            path: 'README.md',
            content: `# ${repoData.name}\n\nEmpty repository. No scannable source files found on branch ${activeBranch}.`
          }
        ],
        isEmpty: true
      });
    }

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
              `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(activeBranch)}/${encodedPath}`,
              {
                headers: token ? { Authorization: `token ${token.trim()}` } : {},
                signal: AbortSignal.timeout(8000)
              }
            );
            if (rawRes.ok) {
              let content = await rawRes.text();
              // File size guard: cap at 200KB per-file limit to avoid ReDoS or memory exhaustion across rules
              if (content.length > 200000) {
                content = content.slice(0, 200000);
              }
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
      defaultBranch: activeBranch,
      stars: repoData.stargazers_count,
      language: repoData.language || 'TypeScript',
      files: fetchedFiles.length > 0 ? fetchedFiles : [
        {
          path: 'README.md',
          content: `# ${repoData.name}\n\nEmpty repository. No source files could be fetched.`
        }
      ],
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
