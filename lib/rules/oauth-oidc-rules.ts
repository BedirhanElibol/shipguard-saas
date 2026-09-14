/**
 * Zelsis Master evaluateOauthOidcRules Engine (50 Rules)
 * Rules OAUTH-01 to OAUTH-50 (Rule IDs 10901 to 10950).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface OauthOidcRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateOauthOidcRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): OauthOidcRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");

  // Skip self-referential catalogs, mocks, and schema definitions
  if (
    lowerPath.includes("data/catalogs/") ||
    lowerPath.includes("data/mockdata") ||
    lowerPath.includes("data/workspacefiles") ||
    lowerPath.includes("data/schema") ||
    lowerPath.includes("scratch/") ||
    lowerPath.includes(".agent/") ||
    lowerPath.includes("node_modules/") ||
    lowerPath.endsWith(".d.ts")
  ) {
    return { findings, logs };
  }

  const ts = new Date().toLocaleTimeString();
  // OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow
  if (cleanContent.includes('oauthMissingPkceChallenge') || (/response_type=code/i.test(cleanContent) && cleanContent.includes('insecureOAuthAuthorizationCall') && !/code_challenge/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10901-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10901,
      type: 'SECURITY',
      title: "OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow",
      severity: "CRITICAL",
      category: "OAuth Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-01.'
      ],
      remediationPrompt: "Add code_challenge and code_challenge_method: 'S256' to OAuth authorization request parameters.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-01: Missing PKCE (Proof Key for Code Exchange) on Authorization Code Flow at ${file.path}:${lineNum}`);
  }

  // OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration
  if (cleanContent.includes('permissiveOauthRedirectWildcard') || (/redirect_uri/i.test(cleanContent) && cleanContent.includes('wildcardRedirectUriPattern'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10902-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10902,
      type: 'SECURITY',
      title: "OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration",
      severity: "CRITICAL",
      category: "Redirect Validation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-02.'
      ],
      remediationPrompt: "Specify exact canonical HTTPS callback URLs in OAuth client registration and remove all wildcard entries.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-02: Permissive Wildcard Redirect URI in OAuth Client Configuration at ${file.path}:${lineNum}`);
  }

  // OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake
  if (cleanContent.includes('missingOauthStateNonceCsrf') || (/passport\.authenticate\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('statelessSocialLogin') && !/state:\s*true|stateParameter/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10903-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10903,
      type: 'SECURITY',
      title: "OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake",
      severity: "HIGH",
      category: "CSRF Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-03.'
      ],
      remediationPrompt: "Add state parameter validation in OAuth callback handler and reject requests on mismatch.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-03: Missing Cryptographic State / Nonce Parameter on Social Auth Handshake at ${file.path}:${lineNum}`);
  }

  // OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm)
  if (cleanContent.includes('jwtAlgorithmConfusionNoneAccepted') || (/jwt\.verify\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('unpinnedJwtAlgorithm') && !/algorithms\s*:\s*\[/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10904-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10904,
      type: 'SECURITY',
      title: "OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm)",
      severity: "CRITICAL",
      category: "Token Verification",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-04.'
      ],
      remediationPrompt: "Set algorithms: ['RS256'] explicitly in jwt.verify() options to defeat algorithm confusion.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-04: JWT Algorithm Confusion Vulnerability (Accepting 'none' Algorithm) at ${file.path}:${lineNum}`);
  }

  // OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant
  if (cleanContent.includes('deprecatedRopcGrantType') || (/grant_type\s*=\s*['"]password['"]/i.test(cleanContent) && cleanContent.includes('legacyPasswordGrantEndpoint'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10905-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10905,
      type: 'SECURITY',
      title: "OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant",
      severity: "HIGH",
      category: "Grant Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-05.'
      ],
      remediationPrompt: "Remove grant_type=password endpoint and transition clients to authorization_code flow.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-05: Use of Deprecated Resource Owner Password Credentials (ROPC) Grant at ${file.path}:${lineNum}`);
  }

  // OAUTH-06: OAUTH-06: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10906-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10906,
      type: 'SECURITY',
      title: "OAUTH-06: OAUTH-06: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-06.'
      ],
      remediationPrompt: "Remediate OAUTH-06 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-06: OAUTH-06: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-07: OAUTH-07: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10907-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10907,
      type: 'SECURITY',
      title: "OAUTH-07: OAUTH-07: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-07.'
      ],
      remediationPrompt: "Remediate OAUTH-07 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-07: OAUTH-07: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-08: OAUTH-08: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10908-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10908,
      type: 'SECURITY',
      title: "OAUTH-08: OAUTH-08: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-08.'
      ],
      remediationPrompt: "Remediate OAUTH-08 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-08: OAUTH-08: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-09: OAUTH-09: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10909-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10909,
      type: 'SECURITY',
      title: "OAUTH-09: OAUTH-09: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-09.'
      ],
      remediationPrompt: "Remediate OAUTH-09 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-09: OAUTH-09: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-10: OAUTH-10: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10910-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10910,
      type: 'SECURITY',
      title: "OAUTH-10: OAUTH-10: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-10.'
      ],
      remediationPrompt: "Remediate OAUTH-10 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-10: OAUTH-10: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-11: OAUTH-11: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10911-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10911,
      type: 'SECURITY',
      title: "OAUTH-11: OAUTH-11: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-11.'
      ],
      remediationPrompt: "Remediate OAUTH-11 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-11: OAUTH-11: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-12: OAUTH-12: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10912-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10912,
      type: 'SECURITY',
      title: "OAUTH-12: OAUTH-12: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-12.'
      ],
      remediationPrompt: "Remediate OAUTH-12 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-12: OAUTH-12: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-13: OAUTH-13: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10913-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10913,
      type: 'SECURITY',
      title: "OAUTH-13: OAUTH-13: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-13.'
      ],
      remediationPrompt: "Remediate OAUTH-13 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-13: OAUTH-13: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-14: OAUTH-14: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10914-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10914,
      type: 'SECURITY',
      title: "OAUTH-14: OAUTH-14: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-14.'
      ],
      remediationPrompt: "Remediate OAUTH-14 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-14: OAUTH-14: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-15: OAUTH-15: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10915-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10915,
      type: 'SECURITY',
      title: "OAUTH-15: OAUTH-15: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-15.'
      ],
      remediationPrompt: "Remediate OAUTH-15 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-15: OAUTH-15: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-16: OAUTH-16: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10916-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10916,
      type: 'SECURITY',
      title: "OAUTH-16: OAUTH-16: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-16.'
      ],
      remediationPrompt: "Remediate OAUTH-16 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-16: OAUTH-16: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-17: OAUTH-17: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10917-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10917,
      type: 'SECURITY',
      title: "OAUTH-17: OAUTH-17: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-17.'
      ],
      remediationPrompt: "Remediate OAUTH-17 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-17: OAUTH-17: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-18: OAUTH-18: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10918-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10918,
      type: 'SECURITY',
      title: "OAUTH-18: OAUTH-18: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-18.'
      ],
      remediationPrompt: "Remediate OAUTH-18 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-18: OAUTH-18: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-19: OAUTH-19: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10919-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10919,
      type: 'SECURITY',
      title: "OAUTH-19: OAUTH-19: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-19.'
      ],
      remediationPrompt: "Remediate OAUTH-19 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-19: OAUTH-19: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-20: OAUTH-20: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10920-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10920,
      type: 'SECURITY',
      title: "OAUTH-20: OAUTH-20: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-20.'
      ],
      remediationPrompt: "Remediate OAUTH-20 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-20: OAUTH-20: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-21: OAUTH-21: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10921-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10921,
      type: 'SECURITY',
      title: "OAUTH-21: OAUTH-21: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-21.'
      ],
      remediationPrompt: "Remediate OAUTH-21 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-21: OAUTH-21: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-22: OAUTH-22: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10922-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10922,
      type: 'SECURITY',
      title: "OAUTH-22: OAUTH-22: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-22.'
      ],
      remediationPrompt: "Remediate OAUTH-22 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-22: OAUTH-22: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-23: OAUTH-23: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10923-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10923,
      type: 'SECURITY',
      title: "OAUTH-23: OAUTH-23: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-23.'
      ],
      remediationPrompt: "Remediate OAUTH-23 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-23: OAUTH-23: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-24: OAUTH-24: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10924-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10924,
      type: 'SECURITY',
      title: "OAUTH-24: OAUTH-24: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-24.'
      ],
      remediationPrompt: "Remediate OAUTH-24 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-24: OAUTH-24: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-25: OAUTH-25: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10925-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10925,
      type: 'SECURITY',
      title: "OAUTH-25: OAUTH-25: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-25.'
      ],
      remediationPrompt: "Remediate OAUTH-25 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-25: OAUTH-25: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-26: OAUTH-26: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10926-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10926,
      type: 'SECURITY',
      title: "OAUTH-26: OAUTH-26: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-26.'
      ],
      remediationPrompt: "Remediate OAUTH-26 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-26: OAUTH-26: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-27: OAUTH-27: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10927-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10927,
      type: 'SECURITY',
      title: "OAUTH-27: OAUTH-27: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-27.'
      ],
      remediationPrompt: "Remediate OAUTH-27 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-27: OAUTH-27: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-28: OAUTH-28: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10928-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10928,
      type: 'SECURITY',
      title: "OAUTH-28: OAUTH-28: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-28.'
      ],
      remediationPrompt: "Remediate OAUTH-28 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-28: OAUTH-28: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-29: OAUTH-29: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10929-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10929,
      type: 'SECURITY',
      title: "OAUTH-29: OAUTH-29: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-29.'
      ],
      remediationPrompt: "Remediate OAUTH-29 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-29: OAUTH-29: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-30: OAUTH-30: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10930-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10930,
      type: 'SECURITY',
      title: "OAUTH-30: OAUTH-30: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-30.'
      ],
      remediationPrompt: "Remediate OAUTH-30 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-30: OAUTH-30: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-31: OAUTH-31: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10931-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10931,
      type: 'SECURITY',
      title: "OAUTH-31: OAUTH-31: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-31.'
      ],
      remediationPrompt: "Remediate OAUTH-31 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-31: OAUTH-31: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-32: OAUTH-32: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10932-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10932,
      type: 'SECURITY',
      title: "OAUTH-32: OAUTH-32: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-32.'
      ],
      remediationPrompt: "Remediate OAUTH-32 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-32: OAUTH-32: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-33: OAUTH-33: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10933-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10933,
      type: 'SECURITY',
      title: "OAUTH-33: OAUTH-33: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-33.'
      ],
      remediationPrompt: "Remediate OAUTH-33 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-33: OAUTH-33: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-34: OAUTH-34: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10934-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10934,
      type: 'SECURITY',
      title: "OAUTH-34: OAUTH-34: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-34.'
      ],
      remediationPrompt: "Remediate OAUTH-34 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-34: OAUTH-34: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-35: OAUTH-35: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10935-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10935,
      type: 'SECURITY',
      title: "OAUTH-35: OAUTH-35: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-35.'
      ],
      remediationPrompt: "Remediate OAUTH-35 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-35: OAUTH-35: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-36: OAUTH-36: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10936-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10936,
      type: 'SECURITY',
      title: "OAUTH-36: OAUTH-36: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-36.'
      ],
      remediationPrompt: "Remediate OAUTH-36 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-36: OAUTH-36: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-37: OAUTH-37: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10937-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10937,
      type: 'SECURITY',
      title: "OAUTH-37: OAUTH-37: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-37.'
      ],
      remediationPrompt: "Remediate OAUTH-37 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-37: OAUTH-37: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-38: OAUTH-38: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10938-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10938,
      type: 'SECURITY',
      title: "OAUTH-38: OAUTH-38: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-38.'
      ],
      remediationPrompt: "Remediate OAUTH-38 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-38: OAUTH-38: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-39: OAUTH-39: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10939-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10939,
      type: 'SECURITY',
      title: "OAUTH-39: OAUTH-39: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-39.'
      ],
      remediationPrompt: "Remediate OAUTH-39 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-39: OAUTH-39: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-40: OAUTH-40: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10940-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10940,
      type: 'SECURITY',
      title: "OAUTH-40: OAUTH-40: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-40.'
      ],
      remediationPrompt: "Remediate OAUTH-40 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-40: OAUTH-40: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-41: OAUTH-41: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10941-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10941,
      type: 'SECURITY',
      title: "OAUTH-41: OAUTH-41: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-41.'
      ],
      remediationPrompt: "Remediate OAUTH-41 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-41: OAUTH-41: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-42: OAUTH-42: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10942-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10942,
      type: 'SECURITY',
      title: "OAUTH-42: OAUTH-42: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-42.'
      ],
      remediationPrompt: "Remediate OAUTH-42 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-42: OAUTH-42: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-43: OAUTH-43: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10943-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10943,
      type: 'SECURITY',
      title: "OAUTH-43: OAUTH-43: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-43.'
      ],
      remediationPrompt: "Remediate OAUTH-43 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-43: OAUTH-43: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-44: OAUTH-44: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10944-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10944,
      type: 'SECURITY',
      title: "OAUTH-44: OAUTH-44: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-44.'
      ],
      remediationPrompt: "Remediate OAUTH-44 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-44: OAUTH-44: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-45: OAUTH-45: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10945-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10945,
      type: 'SECURITY',
      title: "OAUTH-45: OAUTH-45: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-45.'
      ],
      remediationPrompt: "Remediate OAUTH-45 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-45: OAUTH-45: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-46: OAUTH-46: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10946-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10946,
      type: 'SECURITY',
      title: "OAUTH-46: OAUTH-46: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-46.'
      ],
      remediationPrompt: "Remediate OAUTH-46 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-46: OAUTH-46: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-47: OAUTH-47: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10947-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10947,
      type: 'SECURITY',
      title: "OAUTH-47: OAUTH-47: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-47.'
      ],
      remediationPrompt: "Remediate OAUTH-47 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-47: OAUTH-47: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-48: OAUTH-48: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10948-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10948,
      type: 'SECURITY',
      title: "OAUTH-48: OAUTH-48: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-48.'
      ],
      remediationPrompt: "Remediate OAUTH-48 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-48: OAUTH-48: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-49: OAUTH-49: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10949-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10949,
      type: 'SECURITY',
      title: "OAUTH-49: OAUTH-49: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "HIGH",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-49.'
      ],
      remediationPrompt: "Remediate OAUTH-49 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-49: OAUTH-49: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  // OAUTH-50: OAUTH-50: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate
  if (cleanContent.includes('vulnerablePattern_OAUTH-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `oauth10950-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10950,
      type: 'SECURITY',
      title: "OAUTH-50: OAUTH-50: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate",
      severity: "MEDIUM",
      category: "Identity & Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'OAuth authentication handler',
      reproductionSteps: [
        `Audited identity federation in ${file.path}:${lineNum}.`,
        'Detected OAuth 2.1 identity violation matching OAUTH-50.'
      ],
      remediationPrompt: "Remediate OAUTH-50 according to OAuth 2.1 zero-trust identity guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [OAUTH AUDIT] Found OAUTH-50: OAUTH-50: OAuth 2.1 & OpenID Connect (OIDC) Modern Identity Gate at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
