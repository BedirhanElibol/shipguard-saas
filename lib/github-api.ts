import { CodeFile } from './scanner-engine';

export interface GithubRepoInfo {
  name: string;
  fullName: string;
  description: string;
  defaultBranch: string;
  stars: number;
  language: string;
  files: CodeFile[];
}

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

export function sanitizeTargetUrl(url: string): string {
  if (!url || typeof url !== 'string') return '';
  let clean = url.trim();

  if (clean.startsWith('git@github.com:')) {
    clean = `https://github.com/${clean.replace('git@github.com:', '')}`;
  }

  clean = clean.replace(/\.git$/i, '');
  clean = clean.replace(/\/tree\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/blob\/[^\/]+.*$/i, '');
  clean = clean.replace(/\/+$/, '');

  return clean;
}

export function parseGithubUrl(url: string): { owner: string; repo: string } | null {
  if (!url || typeof url !== 'string' || url.trim().length === 0) return null;
  const clean = sanitizeTargetUrl(url);

  try {
    const match = clean.match(/github\.com\/([^\/]+)\/([^\/?#]+)/i);
    if (match && match[1] && match[2]) {
      return { owner: match[1].trim(), repo: match[2].replace(/\.git$/i, '').trim() };
    }

    // Support owner/repo format without domain (e.g. "facebook/react" or "leerob/site")
    const shortMatch = clean.match(/^([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)$/);
    if (shortMatch && shortMatch[1] && shortMatch[2]) {
      return { owner: shortMatch[1].trim(), repo: shortMatch[2].replace(/\.git$/i, '').trim() };
    }

    return null;
  } catch (e: any) {
    return null;
  }
}

export function isValidGithubUrl(url: string): boolean {
  if (!url || typeof url !== 'string' || url.trim().length === 0) return false;
  const clean = sanitizeTargetUrl(url);
  return /^(?:https?:\/\/github\.com\/)?([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+)(?:\.git)?(?:\/.*)?$/.test(clean);
}

/**
 * Live GitHub Repository Fetcher
 * Verifies that the GitHub repository exists and fetches its real file tree & source contents via GitHub REST API.
 */
export async function fetchGithubRepositoryData(
  repoUrl: string,
  token?: string,
  signal?: AbortSignal
): Promise<GithubRepoInfo | null> {
  const parsed = parseGithubUrl(repoUrl);
  if (!parsed) return null;

  // 1. Browser Client Proxy Attempt (Runs only in browser where relative URLs resolve)
  const isBrowser = typeof window !== 'undefined';
  if (isBrowser) {
    try {
      const proxyEndpoint = `/api/v1/github-proxy?repoUrl=${encodeURIComponent(repoUrl)}`;
      const proxyHeaders: Record<string, string> = {};
      if (token) {
        proxyHeaders['Authorization'] = `Bearer ${token.trim()}`;
      }
      const proxyRes = await fetch(proxyEndpoint, { headers: proxyHeaders, signal });
      if (proxyRes.ok) {
        const data = await proxyRes.json();
        if (data) {
          // Handle rate limit response from proxy
          if (data.error === 'RATE_LIMIT_EXCEEDED' || data.description?.includes('rate limit') || data.description?.includes('60 req/hr')) {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: GITHUB_RATE_LIMIT_MESSAGE,
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files: [
                {
                  path: 'RATE_LIMIT_NOTICE.md',
                  content: `# GitHub API Rate Limit Reached\n\n${GITHUB_RATE_LIMIT_MESSAGE}\n`
                }
              ]
            };
          }

          // Handle private or unauthenticated from proxy
          if (data.error === 'PRIVATE_OR_UNAUTHENTICATED') {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files: [
                {
                  path: 'repository-manifest.json',
                  content: JSON.stringify(
                    {
                      repository: `${parsed.owner}/${parsed.repo}`,
                      status: 'PRIVATE_OR_UNAUTHENTICATED',
                      notice: 'This repository is private or unauthenticated. Provide a GitHub Personal Access Token (PAT) in Settings to enable full source file AST scanning.'
                    },
                    null,
                    2
                  )
                }
              ]
            };
          }

          // Handle empty repository gracefully
          if (data.isEmpty || (Array.isArray(data.files) && data.files.length === 0 && !data.error)) {
            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'Empty GitHub repository (no commits or files yet)',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'None',
              files: [
                {
                  path: 'README.md',
                  content: `# ${data.name || parsed.repo}\n\nEmpty repository. No source files committed yet.`
                }
              ]
            };
          }

          if (Array.isArray(data.files) && data.files.length > 0) {
            // Apply 200KB per-file cap to prevent ReDoS or memory exhaustion across rules
            const files: CodeFile[] = data.files.map((f: { path: string; content?: string }) => {
              let content = typeof f.content === 'string' ? f.content : '';
              if (content.length > 200000) {
                content = content.slice(0, 200000);
              }
              return { path: f.path, content };
            });

            return {
              name: data.name || parsed.repo,
              fullName: data.fullName || `${parsed.owner}/${parsed.repo}`,
              description: data.description || 'GitHub Application Repository',
              defaultBranch: data.defaultBranch || 'main',
              stars: data.stars || 0,
              language: data.language || 'TypeScript',
              files
            };
          }
        }
      }
    } catch (err: any) {
      if (signal?.aborted || err?.name === 'AbortError') return null;
    }
  }

  // 2. Direct GitHub API Fetch (Server routes or client fallback)
  const { owner, repo } = parsed;
  const serverToken = typeof process !== 'undefined' ? (process.env.GITHUB_TOKEN || process.env.GITHUB_PAT) : undefined;
  const effectiveToken = token || serverToken;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Zelsis-AI-Release-Gate'
  };

  if (effectiveToken) {
    headers['Authorization'] = `Bearer ${effectiveToken.trim()}`;
  }

  try {
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      signal: signal || AbortSignal.timeout(8000)
    });

    if (!repoRes.ok) {
      let bodyText = '';
      try {
        bodyText = await repoRes.text();
      } catch {
        bodyText = '';
      }

      const isRateLimit = isGitHubRateLimited(repoRes.status, repoRes.headers, bodyText, Boolean(effectiveToken));

      if (isRateLimit) {
        return {
          name: repo,
          fullName: `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: 'main',
          stars: 0,
          language: 'TypeScript',
          files: [
            {
              path: 'RATE_LIMIT_NOTICE.md',
              content: `# GitHub API Rate Limit Reached\n\n${GITHUB_RATE_LIMIT_MESSAGE}\n`
            }
          ]
        };
      }

      return {
        name: repo,
        fullName: `${owner}/${repo}`,
        description: 'Private or Unauthenticated GitHub Repository. Provide a GitHub PAT token in Settings to access private repos.',
        defaultBranch: 'main',
        stars: 0,
        language: 'TypeScript',
        files: [
          {
            path: 'repository-manifest.json',
            content: JSON.stringify(
              {
                repository: `${owner}/${repo}`,
                status: 'PRIVATE_OR_UNAUTHENTICATED',
                notice: 'This repository is private or unauthenticated. Provide a GitHub Personal Access Token (PAT) in Settings to enable full source file AST scanning.'
              },
              null,
              2
            )
          }
        ]
      };
    }

    const repoData = (await repoRes.json()) as Record<string, unknown>;
    const detectedBranch = typeof repoData?.default_branch === 'string' && repoData.default_branch ? repoData.default_branch : 'main';

    // Handle empty repository immediately if size is 0
    if (typeof repoData?.size === 'number' && repoData.size === 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'Empty GitHub repository (no commits or files yet)',
        defaultBranch: detectedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'None',
        files: [
          {
            path: 'README.md',
            content: `# ${(repoData?.name as string) || repo}\n\nEmpty repository. No source files committed yet.`
          }
        ]
      };
    }

    if (signal?.aborted) return null;

    // Default branch detection with fallback checks for main, master, and develop
    const candidateBranches = Array.from(
      new Set([detectedBranch, 'main', 'master', 'develop'].filter(Boolean))
    );
    let treeRes: Response | null = null;
    let resolvedBranch = detectedBranch;

    for (const branch of candidateBranches) {
      if (signal?.aborted) return null;
      try {
        const res = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
          { headers, signal: signal || AbortSignal.timeout(10000) }
        );
        if (res.ok) {
          treeRes = res;
          resolvedBranch = branch;
          break;
        } else if (res.status === 409) {
          // GitHub returns 409 Conflict when repository is empty
          treeRes = res;
          resolvedBranch = branch;
          break;
        } else if (res.status === 403 || res.status === 429 || res.headers.get('x-ratelimit-remaining') === '0') {
          treeRes = res;
          break;
        }
      } catch (err: unknown) {
        const errObj = err as { name?: string; message?: string };
        if (errObj?.name === 'AbortError' || signal?.aborted) return null;
      }
    }

    if (signal?.aborted) return null;

    // Handle tree fetch failure or empty repo or rate limit
    if (!treeRes || !treeRes.ok) {
      if (treeRes && treeRes.status === 409) {
        return {
          name: (repoData?.name as string) || repo,
          fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
          description: (repoData?.description as string) || 'Empty GitHub repository (no commits or files yet)',
          defaultBranch: resolvedBranch,
          stars: (repoData?.stargazers_count as number) || 0,
          language: (repoData?.language as string) || 'None',
          files: [
            {
              path: 'README.md',
              content: `# ${(repoData?.name as string) || repo}\n\nEmpty repository. No source files committed yet.`
            }
          ]
        };
      }

      let treeBody = '';
      try {
        if (treeRes) treeBody = await treeRes.text();
      } catch {
        treeBody = '';
      }

      const isTreeRateLimit =
        treeRes && (
          treeRes.status === 429 ||
          treeRes.headers.get('x-ratelimit-remaining') === '0' ||
          treeRes.headers.has('retry-after') ||
          (treeRes.status === 403 && (/rate limit|secondary rate|abuse detection/i.test(treeBody) || !effectiveToken))
        );

      if (isTreeRateLimit) {
        return {
          name: (repoData?.name as string) || repo,
          fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
          description: GITHUB_RATE_LIMIT_MESSAGE,
          defaultBranch: resolvedBranch,
          stars: (repoData?.stargazers_count as number) || 0,
          language: (repoData?.language as string) || 'TypeScript',
          files: [
            {
              path: 'RATE_LIMIT_NOTICE.md',
              content: `# GitHub API Rate Limit Reached\n\n${GITHUB_RATE_LIMIT_MESSAGE}\n`
            }
          ]
        };
      }

      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'GitHub repository files could not be retrieved',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'TypeScript',
        files: [
          {
            path: 'EMPTY_REPO_NOTICE.md',
            content: `# ${(repoData?.name as string) || repo}\n\nNo branch trees could be loaded. Ensure the repository has committed files.`
          }
        ]
      };
    }

    let treeData: { tree?: Array<{ type: string; path: string; size?: number }> } = {};
    try {
      treeData = (await treeRes.json()) as { tree?: Array<{ type: string; path: string; size?: number }> };
    } catch {
      treeData = { tree: [] };
    }

    const treeFiles = (treeData.tree || [])
      .filter(
        (item) =>
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

    if (signal?.aborted) return null;

    if (treeFiles.length === 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'Empty GitHub repository (0 scannable files)',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'None',
        files: [
          {
            path: 'README.md',
            content: `# ${(repoData?.name as string) || repo}\n\nEmpty repository. No scannable source files found on branch ${resolvedBranch}.`
          }
        ]
      };
    }

    const CHUNK_SIZE = 15;
    const fetchedFiles: (CodeFile | null)[] = [];

    for (let i = 0; i < treeFiles.length; i += CHUNK_SIZE) {
      if (signal?.aborted) return null;
      const chunk = treeFiles.slice(i, i + CHUNK_SIZE);
      const chunkResults = await Promise.all(
        chunk.map(async (file) => {
          try {
            const encodedPath = file.path.split('/').map(encodeURIComponent).join('/');
            const rawRes = await fetch(
              `https://raw.githubusercontent.com/${owner}/${repo}/${resolvedBranch}/${encodedPath}`,
              {
                headers: effectiveToken ? { Authorization: `token ${effectiveToken.trim()}` } : {},
                signal: signal || AbortSignal.timeout(6000)
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
          } catch (err: unknown) {
            const errObj = err as { name?: string; message?: string };
            if (errObj?.name !== 'AbortError' && !signal?.aborted) {
              console.warn(`[GitHub API Chunking] Failed to fetch raw file ${file.path}:`, errObj?.message || err);
            }
          }
          return null;
        })
      );
      fetchedFiles.push(...chunkResults);
    }

    const codeFiles: CodeFile[] = fetchedFiles.filter((f): f is CodeFile => f !== null);

    if (codeFiles.length > 0) {
      return {
        name: (repoData?.name as string) || repo,
        fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
        description: (repoData?.description as string) || 'GitHub Application Repository',
        defaultBranch: resolvedBranch,
        stars: (repoData?.stargazers_count as number) || 0,
        language: (repoData?.language as string) || 'TypeScript',
        files: codeFiles
      };
    }

    return {
      name: (repoData?.name as string) || repo,
      fullName: (repoData?.full_name as string) || `${owner}/${repo}`,
      description: (repoData?.description as string) || 'GitHub repository with no downloadable source files',
      defaultBranch: resolvedBranch,
      stars: (repoData?.stargazers_count as number) || 0,
      language: (repoData?.language as string) || 'TypeScript',
      files: [
        {
          path: 'EMPTY_REPO_NOTICE.md',
          content: `# ${(repoData?.name as string) || repo}\n\nRaw source file content could not be retrieved.`
        }
      ]
    };
  } catch (err: unknown) {
    const errObj = err as { name?: string; message?: string };
    if (errObj?.name !== 'AbortError' && !signal?.aborted) {
      console.warn('Live GitHub API Fetch notice:', errObj?.message || err);
    }
    return null;
  }
}
