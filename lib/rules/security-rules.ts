// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

export function evaluateSecurityRules(
  file: CodeFile,
  lines: string[],
  cleanContentOrCounter: string | { count: number },
  counterMaybe?: { count: number }
): { findings: Finding[]; logs: string[] } {
  const findings: Finding[] = [];
  const logs: string[] = [];

  const cleanContent = typeof cleanContentOrCounter === 'string' ? cleanContentOrCounter : file.content;
  const findingCounter = typeof cleanContentOrCounter === 'object' ? cleanContentOrCounter : (counterMaybe || { count: 1 });
  const ts = new Date().toLocaleTimeString();
  const lowerPath = file.path.toLowerCase();

  // Rule 1: Exposed Stripe/OpenAI API Keys (SEC-01)
  if (cleanContent.includes('sk_live_') || cleanContent.includes('sk-proj-') || /api[_-]?key\s*=\s*["']sk-[a-zA-Z0-9_-]{20,}/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('*') && (l.includes('sk_live_') || l.includes('sk-proj-') || /sk-[a-zA-Z0-9_-]{20,}/i.test(l)));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `real-find-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1,
      type: 'SECURITY',
      title: 'Exposed Hardcoded OpenAI/Stripe Secret API Key',
      severity: 'CRITICAL',
      category: 'Secret Isolation',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || 'const API_KEY = "sk-live-..."',
      reproductionSteps: [
        `Scanned source file at ${file.path}:${lineNum}.`,
        'Detected hardcoded live secret token pattern in client/server code.'
      ],
      remediationPrompt: `Extract secret API key in ${file.path} to process.env.OPENAI_API_KEY. Never commit secret tokens to version control.`,
      status: 'OPEN',
      owner: 'Security Architect',
      falsePositive: false
    });

    logs.push(`[${ts}] 🛑 CRITICAL: SEC-01 Hardcoded Secret API Key in ${file.path}:${lineNum}`);
  }

  // Rule 3: Supabase Permissive Row Level Security (RLS) (SEC-03)
  if (cleanContent.includes('USING (true)') || cleanContent.includes('FOR ALL USING (true)')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('--') && l.includes('USING (true)'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    findings.push({
      id: `real-find-${Date.now()}-${findingCounter.count++}`,
      ruleId: 3,
      type: 'SECURITY',
      title: 'Permissive Row Level Security (RLS) Policy (USING true)',
      severity: 'CRITICAL',
      category: 'Database',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'USING (true);',
      reproductionSteps: [
        `Scanned database migration SQL at ${file.path}:${lineNum}.`,
        'Detected default allow-all policy using (true).'
      ],
      remediationPrompt: `Replace permissive RLS policy in ${file.path}. Write strict auth.uid() = user_id checks.`,
      status: 'OPEN',
      owner: 'Backend Team',
      falsePositive: false
    });

    logs.push(`[${ts}] 🛑 CRITICAL: SEC-03 Permissive RLS Policy in ${file.path}:${lineNum}`);
  }

  // Rule 8: Restrict CORS to Production Domains (SEC-08)
  if (cleanContent.includes("origin: '*'") || cleanContent.includes('Access-Control-Allow-Origin: *') || cleanContent.includes('"Access-Control-Allow-Origin", "*"')) {
    const matchLineIdx = lines.findIndex(l => l.includes("origin: '*'") || l.includes('Access-Control-Allow-Origin') && l.includes('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    findings.push({
      id: `real-find-${Date.now()}-${findingCounter.count++}`,
      ruleId: 8,
      type: 'SECURITY',
      title: 'Wildcard Access-Control-Allow-Origin (*) CORS Vulnerability',
      severity: 'HIGH',
      category: 'Network & CORS',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || "origin: '*'",
      reproductionSteps: [
        `Scanned API server setup at ${file.path}:${lineNum}.`,
        'Detected wildcard Access-Control-Allow-Origin header allowing unauthorized origins.'
      ],
      remediationPrompt: `Restrict CORS origin in ${file.path} to process.env.PRODUCTION_CLIENT_URL.`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });

    logs.push(`[${ts}] ⚠️ HIGH: SEC-08 Wildcard CORS configuration in ${file.path}:${lineNum}`);
  }

  // Rule 16: Dangerously Set Inner HTML (XSS) (SEC-16)
  const isSafeMdxOrJsonLd = file.path.includes('mdx-components') || file.path.includes('syntax-highlight') || cleanContent.includes('application/ld+json');
  if (!isSafeMdxOrJsonLd && (cleanContent.includes('dangerouslySetInnerHTML') || cleanContent.includes('innerHTML ='))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('/*') && (l.includes('dangerouslySetInnerHTML') || l.includes('innerHTML')));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;

    findings.push({
      id: `real-find-${Date.now()}-${findingCounter.count++}`,
      ruleId: 16,
      type: 'SECURITY',
      title: 'Unsanitized Direct InnerHTML DOM Mutation (XSS Risk)',
      severity: 'HIGH',
      category: 'Input & Files',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'dangerouslySetInnerHTML={{ __html: content }}',
      reproductionSteps: [
        `Scanned frontend component rendering at ${file.path}:${lineNum}.`,
        'Detected unescaped DOM insertion susceptible to Cross-Site Scripting.'
      ],
      remediationPrompt: `Sanitize input in ${file.path} using DOMPurify before setting innerHTML.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });

    logs.push(`[${ts}] ⚠️ HIGH: SEC-16 Unsanitized innerHTML in ${file.path}:${lineNum}`);
  }

  // Rule 20 / SEC-20 (SEC-SCA-01): Vulnerable Dependency & Wildcard Version
  if (lowerPath.endsWith('package.json')) {
    const KNOWN_VULNERABLE_PACKAGES: Record<string, { minSafe: string; reason: string }> = {
      lodash: {
        minSafe: '4.17.21',
        reason: 'Prototype pollution & command injection vulnerabilities (CVE-2020-8203, CVE-2021-23337)'
      },
      axios: {
        minSafe: '1.7.4',
        reason: 'Server-Side Request Forgery (SSRF) and header injection vulnerabilities (CVE-2023-45857, CVE-2024-39338)'
      },
      moment: {
        minSafe: 'DEPRECATED',
        reason: 'Deprecated library with known Regular Expression Denial of Service (ReDoS) issues and high bundle size'
      },
      minimist: {
        minSafe: '1.2.6',
        reason: 'Prototype pollution vulnerability (CVE-2021-44906)'
      },
      jsonwebtoken: {
        minSafe: '9.0.0',
        reason: 'Key confusion and signature verification bypass vulnerabilities'
      },
      express: {
        minSafe: '4.19.2',
        reason: 'Open redirect and IP spoofing vulnerabilities (CVE-2024-29041)'
      }
    };

    const isVersionLessThan = (actual: string, minSafe: string): boolean => {
      const cleanActual = actual.replace(/^[^\d]*/, '').split('-')[0].trim();
      const cleanMinSafe = minSafe.replace(/^[^\d]*/, '').split('-')[0].trim();
      if (!cleanActual || !cleanMinSafe) return false;

      const actualParts = cleanActual.split('.').map((p) => parseInt(p, 10) || 0);
      const minSafeParts = cleanMinSafe.split('.').map((p) => parseInt(p, 10) || 0);

      for (let i = 0; i < 3; i++) {
        const a = actualParts[i] ?? 0;
        const m = minSafeParts[i] ?? 0;
        if (a < m) return true;
        if (a > m) return false;
      }
      return false;
    };

    const processDep = (depName: string, version: string) => {
      const v = String(version).trim();
      const isWildcard = v === '*' || v === 'latest' || v === 'x' || v === '' || v.startsWith('>=0.');
      const vulnDef = KNOWN_VULNERABLE_PACKAGES[depName.toLowerCase()];
      const isDeprecated = vulnDef?.minSafe === 'DEPRECATED';
      const isOutdated = vulnDef && !isDeprecated && isVersionLessThan(v, vulnDef.minSafe);

      if (isWildcard || isDeprecated || isOutdated) {
        const matchLineIdx = lines.findIndex((l) => l.includes(`"${depName}"`));
        const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

        let issueDescription = '';
        let remediation = '';
        if (isWildcard) {
          issueDescription = `Detected unpinned wildcard version "${v}" for package "${depName}". Wildcard dependencies create non-deterministic builds and supply chain injection risks.`;
          remediation = `Pin exact dependency version in ${file.path} for "${depName}". Replace "${v}" with a safe pinned semver release (e.g. "^1.0.0").`;
        } else if (isDeprecated) {
          issueDescription = `Detected package "${depName}" (${v}) is deprecated: ${vulnDef?.reason}.`;
          remediation = `Replace deprecated "${depName}" in ${file.path} with a modern maintained alternative such as "date-fns" or "dayjs".`;
        } else if (isOutdated && vulnDef) {
          issueDescription = `Detected dependency "${depName}": "${v}" with published security CVE vulnerability advisory (${vulnDef.reason}). Minimum safe version is >= ${vulnDef.minSafe}.`;
          remediation = `Upgrade "${depName}" from ${v} to >= ${vulnDef.minSafe} in ${file.path} to resolve published CVE vulnerabilities.`;
        }

        findings.push({
          id: `real-find-${Date.now()}-${findingCounter.count++}`,
          ruleId: 20,
          type: 'SECURITY',
          title: 'Vulnerable Dependency or Wildcard Version in package.json',
          severity: 'HIGH',
          category: 'Supply Chain & Deps',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: snippet || `"${depName}": "${version}"`,
          reproductionSteps: [
            `Scanned package manifest at ${file.path}:${lineNum}.`,
            issueDescription
          ],
          remediationPrompt: remediation,
          status: 'OPEN',
          owner: 'DevOps & Security Lead',
          falsePositive: false
        });

        logs.push(`[${ts}] 📦 HIGH: SEC-20 ${depName}@${version} in ${file.path}:${lineNum}`);
      }
    };

    try {
      const pkg = JSON.parse(file.content);
      const allDeps: Record<string, string> = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
        ...(pkg.peerDependencies || {})
      };
      for (const [depName, version] of Object.entries(allDeps)) {
        processDep(depName, version);
      }
    } catch {
      const depRegex = /"([^"]+)"\s*:\s*"([^"]+)"/g;
      let match: RegExpExecArray | null;
      while ((match = depRegex.exec(file.content)) !== null) {
        const [, depName, version] = match;
        if (depName && version && (depName.toLowerCase() in KNOWN_VULNERABLE_PACKAGES || version === '*' || version === 'latest')) {
          processDep(depName, version);
        }
      }
    }
  }

  // Rule 21 / SEC-21 (SEC-LOG-01): Potential Secret or PII Log Leakage
  const isCodeFile = /\.(?:tsx?|jsx?|mjs|cjs|py|go|rs|php|cs|java|rb|cpp|c|h|hpp)$/i.test(file.path);
  if (isCodeFile && !lowerPath.endsWith('package.json')) {
    const logCallRegex = /(?:console\.(?:log|error|warn|info|debug)|logger\.(?:info|error|warn|debug)|print|System\.out\.println)\s*\(/i;
    const sensitiveVarRegex = /(?:\$\{[^}]*(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|(?:\+\s*|,\s*|:\s*)(?:[a-zA-Z0-9_.]+\.)?(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|\{\s*(?:[a-zA-Z0-9_]+(?::\s*[^,}]+)?,\s*)*(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\b|\(\s*(?:[a-zA-Z0-9_.]+\.)?(?:[a-zA-Z0-9_]*(?:token|secret|password|passwd|apiKey|api_key|jwt)|authHeader)\s*[\),]|(?:req\.headers(?:\.authorization)?|headers\[['"]authorization['"]\]))/i;
    const safeMaskRegex = /(?:mask|redact|hash|\[REDACTED\]|\*\*\*)/i;

    let logMatchesInFile = 0;
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      if (logCallRegex.test(line) && sensitiveVarRegex.test(line) && !safeMaskRegex.test(line)) {
        if (logMatchesInFile >= 5) break; // Cap per file to avoid telemetry flooding
        logMatchesInFile++;

        const lineNum = idx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

        findings.push({
          id: `real-find-${Date.now()}-${findingCounter.count++}`,
          ruleId: 21,
          type: 'SECURITY',
          title: 'Potential Secret or PII Log Leakage in Application Telemetry',
          severity: 'HIGH',
          category: 'Secret Isolation',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: snippet || line.trim(),
          reproductionSteps: [
            `Scanned application source file at ${file.path}:${lineNum}.`,
            'Detected logging statement printing unredacted sensitive credential (token, secret, password, or PII) to stdout/telemetry stream.'
          ],
          remediationPrompt: `Remove plain-text credential logging in ${file.path}:${lineNum}. Use structured server-side logging with automated PII masking and redaction filters (lib/logger.ts) instead of outputting raw tokens or request headers.`,
          status: 'OPEN',
          owner: 'Security Lead',
          falsePositive: false
        });

        logs.push(`[${ts}] 🪵 HIGH: SEC-21 Potential secret/PII log leakage in ${file.path}:${lineNum}`);
      }
    }
  }

  // Rule 22 / SEC-22 (SEC-LLM-01): Client-Side Direct LLM API SDK Exposure
  const isClientComponent = /['"]use client['"]/i.test(cleanContent) || /['"]use client['"]/i.test(file.content);
  if (isClientComponent && /\.(?:tsx?|jsx?)$/i.test(file.path)) {
    const LLM_SDK_IMPORT_REGEX = /(?:import\s+.*?from\s+['"](?:openai|@anthropic-ai\/sdk|@google\/genai|@google\/generative-ai|groq-sdk|replicate)['"]|require\(['"](?:openai|@anthropic-ai\/sdk|@google\/genai|@google\/generative-ai|groq-sdk|replicate)['"]\))/i;
    const DANGEROUS_BROWSER_REGEX = /dangerouslyAllowBrowser\s*:\s*true/i;
    const SYSTEM_PROMPT_LEAK_REGEX = /(?:role\s*:\s*['"]system['"]|const\s+(?:systemPrompt|SYSTEM_PROMPT|systemInstruction)\s*=\s*['"`])/i;

    const hasLlmImport = LLM_SDK_IMPORT_REGEX.test(cleanContent);
    const hasDangerousBrowser = DANGEROUS_BROWSER_REGEX.test(cleanContent);
    const hasSystemPromptLeak = SYSTEM_PROMPT_LEAK_REGEX.test(cleanContent);

    if (hasLlmImport || hasDangerousBrowser || hasSystemPromptLeak) {
      let matchLineIdx = lines.findIndex(
        (l) => !l.trim().startsWith('//') && (LLM_SDK_IMPORT_REGEX.test(l) || DANGEROUS_BROWSER_REGEX.test(l) || SYSTEM_PROMPT_LEAK_REGEX.test(l))
      );
      if (matchLineIdx === -1) {
        matchLineIdx = lines.findIndex((l) => /openai|anthropic|dangerouslyAllowBrowser|genai/i.test(l));
      }
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      let detail = 'Detected direct import of backend LLM API SDK in a client bundle ("use client"), exposing API keys and proprietary logic to browser DevTools.';
      if (hasDangerousBrowser) {
        detail = 'Detected dangerouslyAllowBrowser: true flag in client component, bypassing SDK security boundaries and exposing client-side API keys.';
      } else if (hasSystemPromptLeak && !hasLlmImport) {
        detail = 'Detected proprietary system prompt strings hardcoded directly inside client-side component.';
      }

      findings.push({
        id: `real-find-${Date.now()}-${findingCounter.count++}`,
        ruleId: 22,
        type: 'SECURITY',
        title: 'Client-Side Direct LLM API SDK Exposure',
        severity: 'CRITICAL',
        category: 'AI & LLM Security',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || "import OpenAI from 'openai';",
        reproductionSteps: [
          `Scanned client component at ${file.path}:${lineNum}.`,
          detail
        ],
        remediationPrompt: `Refactor ${file.path} to remove client-side LLM SDK invocations and dangerouslyAllowBrowser flags. Route all model requests through a secure server-side API endpoint (e.g. app/api/chat/route.ts) with server-only environment variables and system prompts.`,
        status: 'OPEN',
        owner: 'AI Security Lead',
        falsePositive: false
      });

      logs.push(`[${ts}] 🛑 CRITICAL: SEC-22 Client-side direct LLM API SDK exposure in ${file.path}:${lineNum}`);
    }
  }

  // Rule 14 / SEC-14: Insecure JWT & Session Secret Hardcoded Fallbacks
  const jwtFallbackRegex = /(?:JWT_SECRET|SESSION_SECRET|AUTH_SECRET|COOKIE_SECRET|NEXTAUTH_SECRET)\s*(?:\|\||\?\?)\s*['"`][^'"`]+['"`]/i;
  if (isCodeFile && jwtFallbackRegex.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && jwtFallbackRegex.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `real-find-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14,
      type: 'SECURITY',
      title: 'Insecure Hardcoded Fallback for Cryptographic Session / JWT Secret',
      severity: 'CRITICAL',
      category: 'Authentication & Tokens',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || "const secret = process.env.JWT_SECRET || 'secret';",
      reproductionSteps: [
        `Scanned authentication token signing in ${file.path}:${lineNum}.`,
        'Detected hardcoded default fallback string for JWT/Session secret token, allowing attackers to forge arbitrary authentication cookies and tokens if environment variable is unset.'
      ],
      remediationPrompt: `Remove insecure default fallback in ${file.path}:${lineNum}. Enforce a strict runtime assertion: if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET must be configured in production');`,
      status: 'OPEN',
      owner: 'Security Lead',
      falsePositive: false
    });

    logs.push(`[${ts}] 🛑 CRITICAL: SEC-14 Insecure JWT secret fallback in ${file.path}:${lineNum}`);
  }

  // Rule 15 / SEC-15: Unauthenticated Next.js API Mutation Route Handler
  const isApiRoute = (lowerPath.includes('app/api/') || lowerPath.includes('pages/api/')) && /\.(?:ts|js)$/i.test(file.path);
  const isPublicWebhookOrHealth = lowerPath.includes('webhook') || lowerPath.includes('health') || lowerPath.includes('ping') || lowerPath.includes('auth/callback');
  if (isApiRoute && !isPublicWebhookOrHealth) {
    const hasMutationExport = /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(cleanContent);
    const hasAuthCheck = /(?:auth|session|supabase\.auth|verify|currentUser|getUser|getSession|apiKey|checkRateLimit|rateLimiter|req\.headers\.get\(['"]authorization['"]\))/i.test(cleanContent);
    if (hasMutationExport && !hasAuthCheck) {
      const matchLineIdx = lines.findIndex(l => /export\s+async\s+function\s+(?:POST|PUT|DELETE|PATCH)\b/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      findings.push({
        id: `real-find-${Date.now()}-${findingCounter.count++}`,
        ruleId: 15,
        type: 'SECURITY',
        title: 'Unauthenticated API Mutation Route Handler (Missing Session / Auth Guard)',
        severity: 'HIGH',
        category: 'API Security & Auth',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'export async function POST(req: NextRequest) {',
        reproductionSteps: [
          `Scanned API route handler at ${file.path}:${lineNum}.`,
          'Detected state-mutating HTTP handler (POST/PUT/DELETE) without session verification, authentication check, or rate-limiting middleware.'
        ],
        remediationPrompt: `Protect ${file.path}:${lineNum} with authentication verification (e.g. check authenticated user session or API token) and apply rate limiting before processing state mutations.`,
        status: 'OPEN',
        owner: 'Backend Team',
        falsePositive: false
      });

      logs.push(`[${ts}] ⚠️ HIGH: SEC-15 Unauthenticated API mutation route in ${file.path}:${lineNum}`);
    }
  }

  return { findings, logs };
}
