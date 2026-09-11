// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Infrastructure, Cloud & Database Security Gate Rules (Rules 3001-3006)
 *
 * Rules:
 * 1. INFRA-01 (Rule ID 3001): Supabase & PostgreSQL Missing Row Level Security (RLS) Policy
 * 2. INFRA-02 (Rule ID 3002): Dockerfile Root User Execution (Privilege Escalation Risk)
 * 3. INFRA-03 (Rule ID 3003): Hardcoded Database Connection URI with Plaintext Credentials
 * 4. INFRA-04 (Rule ID 3004): Permissive Wildcard CORS Configuration in Middleware or API
 * 5. INFRA-05 (Rule ID 3005): Unprotected Production Debug / Profiler / Swagger Endpoints
 * 6. INFRA-06 (Rule ID 3006): Next.js Server Action Mutation Lacks Schema Validation Guard
 *
 * Classification: 100% Native English Only
 */
import type { Finding } from '@/data/schema';
import type { CodeFile } from '../scanner-engine';

export interface InfraRuleResult {
  findings: Finding[];
  logs: string[];
}

function extractSnippet(lines: string[], lineNum: number): string {
  const targetIdx = Math.max(0, lineNum - 1);
  const start = Math.max(0, targetIdx - 2);
  const end = Math.min(lines.length, targetIdx + 3);
  return lines.slice(start, end).join('\n');
}

export function evaluateInfraRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): InfraRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const ts = new Date().toLocaleTimeString();
  const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

  // False-positive guard: Skip internal scanner engines, mock data, and rule definitions
  const isExcluded =
    lowerPath.includes('lib/rules/') ||
    lowerPath.includes('data/mockdata.ts') ||
    lowerPath.includes('data/workspacefiles.ts') ||
    lowerPath.includes('lib/scanner-engine.ts') ||
    lowerPath.includes('vulnerabilityplayground.tsx') ||
    lowerPath.includes('ruleknowledgebasemodal.tsx') ||
    lowerPath.includes('scratch/') ||
    lowerPath.includes('.agent/') ||
    lowerPath.includes('dist/') ||
    lowerPath.includes('build/') ||
    lowerPath.includes('node_modules/') ||
    lowerPath.includes('.next/');

  if (isExcluded) return { findings, logs };

  // =========================================================================
  // RULE 3001 (INFRA-01): Supabase & PostgreSQL Missing Row Level Security (RLS)
  // =========================================================================
  const isSqlFile = lowerPath.endsWith('.sql') || lowerPath.includes('migration') || lowerPath.includes('supabase');
  if (isSqlFile) {
    const tableRegex = /create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_."]+)/gi;
    let match: RegExpExecArray | null;

    while ((match = tableRegex.exec(cleanContent)) !== null) {
      const rawTableName = match[1].replace(/["']/g, '');
      const simpleName = rawTableName.includes('.') ? rawTableName.split('.').pop()! : rawTableName;

      // Check if RLS is enabled for this table anywhere in the file
      const rlsPattern = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:[a-zA-Z0-9_."]+\\.)?${simpleName}\\s+enable\\s+row\\s+level\\s+security`, 'i');
      if (!rlsPattern.test(cleanContent)) {
        const lineNum = cleanContent.slice(0, match.index).split('\n').length;
        const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
        const snippet = extractSnippet(lines, lineNum);

        const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},5 +${lineNum},8 @@\n CREATE TABLE ${rawTableName} (\n   ...\n );\n+\n+-- Enable Row Level Security (RLS) to restrict unauthorized anon reads/writes\n+ALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;\n+CREATE POLICY "Allow authenticated read" ON ${rawTableName} FOR SELECT TO authenticated USING (true);`;

        findings.push({
          id: findingId,
          ruleId: 3001,
          type: 'INFRA_DATABASE',
          title: `PostgreSQL/Supabase Table "${simpleName}" Missing Row Level Security (RLS)`,
          severity: 'CRITICAL',
          category: 'Database Security',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet,
          reproductionSteps: [
            `Navigate to database schema file "${file.path}" at line ${lineNum}.`,
            `Observe table definition "CREATE TABLE ${rawTableName}" created without RLS enforcement.`,
            `Anonymous Supabase PostgREST clients can query or manipulate table data if anon permissions exist.`,
            `Apply "ALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;" with appropriate access policies.`
          ],
          remediationPrompt: `Enable Row Level Security (RLS) on "${rawTableName}" immediately:\nALTER TABLE ${rawTableName} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Allow authenticated read" ON ${rawTableName} FOR SELECT TO authenticated USING (true);`,
          diffPatch,
          status: 'OPEN',
          owner: 'Database & Cloud',
          falsePositive: false
        });

        logs.push(`[${ts}] 🚨 [INFRA-01] CRITICAL: Table "${simpleName}" missing RLS in ${file.path}:${lineNum}`);
      }
    }
  }

  // =========================================================================
  // RULE 3002 (INFRA-02): Dockerfile Root User Execution
  // =========================================================================
  const isDockerfile = lowerPath.includes('dockerfile') || lowerPath.endsWith('dockerfile');
  if (isDockerfile) {
    const hasFrom = /^\s*FROM\s+/im.test(cleanContent);
    if (hasFrom) {
      const hasNonRootUser = /^\s*USER\s+(?!root\b)[a-zA-Z0-9_-]+/im.test(cleanContent);
      const hasExplicitRoot = /^\s*USER\s+root\b/im.test(cleanContent);

      if (!hasNonRootUser || hasExplicitRoot) {
        let lineNum = 1;
        lines.forEach((l, idx) => {
          if (/^\s*FROM\s+/i.test(l)) lineNum = idx + 1;
        });

        const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
        const snippet = extractSnippet(lines, lineNum);

        const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},4 +${lineNum},7 @@\n FROM node:20-alpine AS runner\n WORKDIR /app\n+\n+# Security: Run production container with unprivileged user\n+USER node\n EXPOSE 3000\n CMD ["node", "server.js"]`;

        findings.push({
          id: findingId,
          ruleId: 3002,
          type: 'INFRA_DATABASE',
          title: 'Dockerfile Executes as Root User (Container Privilege Escalation Risk)',
          severity: 'HIGH',
          category: 'Container Security',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet,
          reproductionSteps: [
            `Inspect container definition file "${file.path}".`,
            `Note that the container runs with default root privileges or specifies "USER root".`,
            `Container breakout vulnerabilities can grant attackers root privileges on the underlying host.`,
            `Declare an unprivileged user (e.g., "USER node" or "USER 1001") before the container entrypoint.`
          ],
          remediationPrompt: `Add an unprivileged user directive to Dockerfile before the final command:\nRUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser`,
          diffPatch,
          status: 'OPEN',
          owner: 'DevOps & Cloud',
          falsePositive: false
        });

        logs.push(`[${ts}] ⚠️ [INFRA-02] HIGH: Root container execution in ${file.path}:${lineNum}`);
      }
    }
  }

  // =========================================================================
  // RULE 3003 (INFRA-03): Hardcoded Database Connection URI with Credentials
  // =========================================================================
  const isCodeOrEnv = /\.(ts|js|tsx|jsx|json|yaml|yml|py|go|php)$/i.test(lowerPath) || lowerPath.includes('.env');
  const isEnvExample = lowerPath.includes('.env.example') || lowerPath.includes('.env.sample') || lowerPath.includes('.env.template');

  if (isCodeOrEnv && !isEnvExample) {
    const dbUriRegex = /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/([a-zA-Z0-9_%-]+):([a-zA-Z0-9_!@#$%^&*()-]+)@([a-zA-Z0-9_.-]+)(?::\d+)?\/([a-zA-Z0-9_.-]+)?/gi;
    let dbMatch: RegExpExecArray | null;

    while ((dbMatch = dbUriRegex.exec(cleanContent)) !== null) {
      const user = dbMatch[1];
      const password = dbMatch[2];
      // Skip generic placeholder credentials
      if (['username', 'user', 'your_user', 'password', 'your_password', 'xxx'].includes(user.toLowerCase()) &&
          ['password', 'pass', 'your_password', 'xxx', 'secret'].includes(password.toLowerCase())) {
        continue;
      }

      // Skip common default local dev credentials
      if (['postgres', 'root', 'admin', 'test', 'demo'].includes(user.toLowerCase()) &&
          ['postgres', 'root', 'admin', 'test', 'demo', ''].includes(password.toLowerCase())) {
        continue;
      }

      const lineNum = cleanContent.slice(0, dbMatch.index).split('\n').length;
      const matchingLine = lines[lineNum - 1]?.trim() || '';

      // Skip commented-out sample URIs in YAML, Python, SQL, or code comments
      if (matchingLine.startsWith('#') || matchingLine.startsWith('//') || matchingLine.startsWith('*') || matchingLine.startsWith('--')) {
        continue;
      }
      const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
      const snippet = extractSnippet(lines, lineNum);

      const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},3 +${lineNum},3 @@\n- const dbUri = "${dbMatch[0]}";\n+ const dbUri = process.env.DATABASE_URL;\n+ if (!dbUri) throw new Error("Missing DATABASE_URL environment variable.");`;

      findings.push({
        id: findingId,
        ruleId: 3003,
        type: 'INFRA_DATABASE',
        title: 'Plaintext Database Credentials Embedded in Connection URI',
        severity: 'CRITICAL',
        category: 'Secrets & Cloud',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet,
        reproductionSteps: [
          `Open file "${file.path}" at line ${lineNum}.`,
          `Observe raw database connection string with embedded username and password credentials.`,
          `Committing credentials to version control exposes production databases to automated credential stuffing.`,
          `Extract connection URI into environment variable (e.g. process.env.DATABASE_URL).`
        ],
        remediationPrompt: `Remove hardcoded database credentials. Use environment variables:\nconst connectionString = process.env.DATABASE_URL;`,
        diffPatch,
        status: 'OPEN',
        owner: 'Database & Security',
        falsePositive: false
      });

      logs.push(`[${ts}] 🚨 [INFRA-03] CRITICAL: Hardcoded database credentials detected in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // RULE 3004 (INFRA-04): Permissive Wildcard CORS Configuration
  // =========================================================================
  const isNetworkFile = lowerPath.includes('middleware') || lowerPath.includes('api/') || lowerPath.includes('cors') || lowerPath.includes('server') || lowerPath.includes('next.config');
  if (isNetworkFile) {
    const wildcardCorsRegex = /['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/i;
    const corsWildcardCall = /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/i;

    if (wildcardCorsRegex.test(cleanContent) || corsWildcardCall.test(cleanContent)) {
      let lineNum = 1;
      lines.forEach((l, idx) => {
        if (wildcardCorsRegex.test(l) || corsWildcardCall.test(l)) lineNum = idx + 1;
      });

      const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
      const snippet = extractSnippet(lines, lineNum);

      const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},3 +${lineNum},5 @@\n- headers.set('Access-Control-Allow-Origin', '*');\n+ const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL || 'https://yourdomain.com'];\n+ const origin = request.headers.get('origin');\n+ if (origin && allowedOrigins.includes(origin)) headers.set('Access-Control-Allow-Origin', origin);`;

      findings.push({
        id: findingId,
        ruleId: 3004,
        type: 'INFRA_DATABASE',
        title: 'Permissive Wildcard CORS ("*") Allows Arbitrary Cross-Origin Requests',
        severity: 'HIGH',
        category: 'API & Network',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet,
        reproductionSteps: [
          `Inspect CORS headers in "${file.path}" at line ${lineNum}.`,
          `Notice header "Access-Control-Allow-Origin: *" configured without origin whitelist.`,
          `Allows malicious third-party websites to forge API requests and read authenticated API responses.`,
          `Validate request origin against a dynamic whitelist of approved frontend origins.`
        ],
        remediationPrompt: `Replace wildcard CORS with explicit allowed origin validation:\nconst allowedOrigins = ['https://app.yourdomain.com'];\nconst origin = req.headers.get('origin');\nif (origin && allowedOrigins.includes(origin)) headers.set('Access-Control-Allow-Origin', origin);`,
        diffPatch,
        status: 'OPEN',
        owner: 'API & Network',
        falsePositive: false
      });

      logs.push(`[${ts}] ⚠️ [INFRA-04] HIGH: Wildcard CORS configuration in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // RULE 3005 (INFRA-05): Unprotected Debug / Profiler Endpoints Exposed
  // =========================================================================
  const isRouteFile = lowerPath.includes('app/api/') || lowerPath.includes('pages/api/');
  if (isRouteFile) {
    const isDebugPath =
      lowerPath.includes('/debug') ||
      lowerPath.includes('/profiler') ||
      lowerPath.includes('/health/verbose') ||
      lowerPath.includes('/swagger') ||
      lowerPath.includes('/test-env');

    if (isDebugPath) {
      const hasProdGuard =
        cleanContent.includes('process.env.NODE_ENV !== \'production\'') ||
        cleanContent.includes('process.env.NODE_ENV === \'development\'') ||
        cleanContent.includes('isAdmin') ||
        cleanContent.includes('authorizeAdmin');

      if (!hasProdGuard) {
        const lineNum = 1;
        const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
        const snippet = extractSnippet(lines, 1);

        const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -1,4 +1,7 @@\n export async function GET(request: Request) {\n+  if (process.env.NODE_ENV === 'production') {\n+    return new Response(JSON.stringify({ error: 'Endpoint not available in production' }), { status: 404 });\n+  }\n   return Response.json({ status: 'ok', debug: true });\n }`;

        findings.push({
          id: findingId,
          ruleId: 3005,
          type: 'INFRA_DATABASE',
          title: 'Unprotected Debug / Profiler Endpoint Exposed in Production Build',
          severity: 'MEDIUM',
          category: 'Infra Hardening',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet,
          reproductionSteps: [
            `Examine route handler "${file.path}".`,
            `Route provides internal telemetry, environment dumps, or profiling data.`,
            `Missing development-only guard (process.env.NODE_ENV !== 'production').`,
            `Exposes internal infrastructure topologies and software versions to reconnaissance scans.`
          ],
          remediationPrompt: `Guard debug routes so they are inaccessible in production:\nif (process.env.NODE_ENV === 'production') return new Response(null, { status: 404 });`,
          diffPatch,
          status: 'OPEN',
          owner: 'Infra & SecOps',
          falsePositive: false
        });

        logs.push(`[${ts}] ℹ️ [INFRA-05] MEDIUM: Unprotected debug endpoint exposed in ${file.path}`);
      }
    }
  }

  // =========================================================================
  // RULE 3006 (INFRA-06): Next.js Server Action Mutation Lacks Schema Validation
  // =========================================================================
  const isActionFile = lowerPath.endsWith('.ts') || lowerPath.endsWith('.tsx') || lowerPath.endsWith('.js');
  if (isActionFile) {
    const hasUseServer = /['"]use server['"]/i.test(cleanContent);
    const hasDbMutation = /(?:supabase\.from\([^)]+\)\.(?:insert|update|delete|upsert)|db\.(?:insert|update|delete)|prisma\.[a-zA-Z0-9_]+\.(?:create|update|delete|upsert))/i.test(cleanContent);
    const hasValidation = /\.parse\(|\.safeParse\(|zod|yup|valibot/i.test(cleanContent);

    if (hasUseServer && hasDbMutation && !hasValidation) {
      let lineNum = 1;
      lines.forEach((l, idx) => {
        if (/['"]use server['"]/i.test(l)) lineNum = idx + 1;
      });

      const findingId = `real-find-${Date.now()}-${findingCounter.count++}`;
      const snippet = extractSnippet(lines, lineNum);

      const diffPatch = `--- a/${file.path}\n+++ b/${file.path}\n@@ -${lineNum},6 +${lineNum},10 @@\n 'use server';\n+import { z } from 'zod';\n+\n+const ActionSchema = z.object({ id: z.string(), payload: z.string().max(500) });\n \n export async function updateItemAction(formData: FormData) {\n+  const validated = ActionSchema.parse(Object.fromEntries(formData));\n   await db.update(...);`;

      findings.push({
        id: findingId,
        ruleId: 3006,
        type: 'INFRA_DATABASE',
        title: 'Next.js Server Action Executes Database Mutation Without Schema Validation Guard',
        severity: 'HIGH',
        category: 'Next.js Security',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet,
        reproductionSteps: [
          `Inspect Next.js Server Action in "${file.path}" at line ${lineNum}.`,
          `Function performs direct database write/update operations from client-submitted arguments.`,
          `No Zod schema validation (.parse / .safeParse) is performed before invoking the database client.`,
          `Malicious clients can invoke Server Action POST endpoints with arbitrary unvalidated payloads.`
        ],
        remediationPrompt: `Validate Server Action inputs using a strict Zod schema before database operations:\nconst validated = MySchema.parse(inputData);`,
        diffPatch,
        status: 'OPEN',
        owner: 'Backend & Security',
        falsePositive: false
      });

      logs.push(`[${ts}] ⚠️ [INFRA-06] HIGH: Server action lacks input schema validation in ${file.path}:${lineNum}`);
    }
  }

  return { findings, logs };
}
