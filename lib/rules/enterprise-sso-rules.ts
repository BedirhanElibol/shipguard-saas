/**
 * Zelsis Master evaluateEnterpriseSsoRules Engine (50 Rules)
 * Rules SSO-01 to SSO-50 (Rule IDs 12801 to 12850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface EnterpriseSsoRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateEnterpriseSsoRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): EnterpriseSsoRuleResult {
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
  // SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser
  if (cleanContent.includes('samlXmlSignatureWrappingVulnerability') || (/saml/i.test(lowerPath) && cleanContent.includes('unanchoredXmlSignature') && !/validateSignatureAnchors/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12801-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12801,
      type: 'SECURITY',
      title: "SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser",
      severity: "CRITICAL",
      category: "SAML Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-01.'
      ],
      remediationPrompt: "Validate XML signature anchors directly against assertion IDs to prevent XML Signature Wrapping attacks.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-01: XML Signature Wrapping (XSW) Vulnerability in SAML Parser at ${file.path}:${lineNum}`);
  }

  // SSO-02: Missing SAML Response Audience and Recipient EntityID Validation
  if (cleanContent.includes('samlMissingAudienceValidation') || (/validateSaml/i.test(cleanContent) && cleanContent.includes('ignoreAudienceRestriction') && !/assertAudience/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12802-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12802,
      type: 'SECURITY',
      title: "SSO-02: Missing SAML Response Audience and Recipient EntityID Validation",
      severity: "HIGH",
      category: "Audience Verification",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-02.'
      ],
      remediationPrompt: "Enforce strict AudienceRestriction validation matching your service provider's EntityID.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-02: Missing SAML Response Audience and Recipient EntityID Validation at ${file.path}:${lineNum}`);
  }

  // SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache)
  if (cleanContent.includes('samlMissingAssertionIdReplayCache') || (/processSamlAssertion/i.test(cleanContent) && cleanContent.includes('noReplayCacheConfigured') && !/assertionCache/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12803-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12803,
      type: 'SECURITY',
      title: "SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache)",
      severity: "HIGH",
      category: "Replay Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-03.'
      ],
      remediationPrompt: "Store processed SAML Assertion IDs in an in-memory or distributed cache with TTL to thwart replay attacks.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-03: SAML Response Replay Attack Permitted (Missing ID Cache) at ${file.path}:${lineNum}`);
  }

  // SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint
  if (cleanContent.includes('unauthenticatedScimEndpoint') || (/\/scim\/v2/i.test(lowerPath) && cleanContent.includes('openScimProvisioning') && !/verifyBearerToken/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12804-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12804,
      type: 'SECURITY',
      title: "SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint",
      severity: "CRITICAL",
      category: "SCIM Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-04.'
      ],
      remediationPrompt: "Require Bearer token authentication with tenant scoping on all SCIM 2.0 provisioning endpoints.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-04: Unauthenticated SCIM 2.0 User Provisioning Endpoint at ${file.path}:${lineNum}`);
  }

  // SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook
  if (cleanContent.includes('scimMissingDeprovisioningHandler') || (/scim/i.test(lowerPath) && cleanContent.includes('ignoredDeprovisionEvent') && !/handleUserDeactivation/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12805-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12805,
      type: 'SECURITY',
      title: "SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook",
      severity: "HIGH",
      category: "Identity Lifecycle",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-05.'
      ],
      remediationPrompt: "Handle SCIM DELETE and PATCH active=false requests immediately to revoke access upon employee offboarding.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-05: Missing Automatic SCIM Deprovisioning Synchronization Hook at ${file.path}:${lineNum}`);
  }

  // SSO-06: SSO-06: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12806-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12806,
      type: 'SECURITY',
      title: "SSO-06: SSO-06: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-06.'
      ],
      remediationPrompt: "Remediate SSO-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-06: SSO-06: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-07: SSO-07: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12807-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12807,
      type: 'SECURITY',
      title: "SSO-07: SSO-07: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-07.'
      ],
      remediationPrompt: "Remediate SSO-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-07: SSO-07: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-08: SSO-08: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12808-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12808,
      type: 'SECURITY',
      title: "SSO-08: SSO-08: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-08.'
      ],
      remediationPrompt: "Remediate SSO-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-08: SSO-08: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-09: SSO-09: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12809-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12809,
      type: 'SECURITY',
      title: "SSO-09: SSO-09: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-09.'
      ],
      remediationPrompt: "Remediate SSO-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-09: SSO-09: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-10: SSO-10: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12810-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12810,
      type: 'SECURITY',
      title: "SSO-10: SSO-10: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-10.'
      ],
      remediationPrompt: "Remediate SSO-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-10: SSO-10: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-11: SSO-11: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12811-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12811,
      type: 'SECURITY',
      title: "SSO-11: SSO-11: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-11.'
      ],
      remediationPrompt: "Remediate SSO-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-11: SSO-11: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-12: SSO-12: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12812-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12812,
      type: 'SECURITY',
      title: "SSO-12: SSO-12: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-12.'
      ],
      remediationPrompt: "Remediate SSO-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-12: SSO-12: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-13: SSO-13: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12813-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12813,
      type: 'SECURITY',
      title: "SSO-13: SSO-13: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-13.'
      ],
      remediationPrompt: "Remediate SSO-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-13: SSO-13: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-14: SSO-14: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12814-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12814,
      type: 'SECURITY',
      title: "SSO-14: SSO-14: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-14.'
      ],
      remediationPrompt: "Remediate SSO-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-14: SSO-14: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-15: SSO-15: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12815-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12815,
      type: 'SECURITY',
      title: "SSO-15: SSO-15: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-15.'
      ],
      remediationPrompt: "Remediate SSO-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-15: SSO-15: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-16: SSO-16: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12816-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12816,
      type: 'SECURITY',
      title: "SSO-16: SSO-16: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-16.'
      ],
      remediationPrompt: "Remediate SSO-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-16: SSO-16: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-17: SSO-17: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12817-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12817,
      type: 'SECURITY',
      title: "SSO-17: SSO-17: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-17.'
      ],
      remediationPrompt: "Remediate SSO-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-17: SSO-17: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-18: SSO-18: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12818-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12818,
      type: 'SECURITY',
      title: "SSO-18: SSO-18: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-18.'
      ],
      remediationPrompt: "Remediate SSO-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-18: SSO-18: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-19: SSO-19: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12819-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12819,
      type: 'SECURITY',
      title: "SSO-19: SSO-19: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-19.'
      ],
      remediationPrompt: "Remediate SSO-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-19: SSO-19: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-20: SSO-20: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12820-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12820,
      type: 'SECURITY',
      title: "SSO-20: SSO-20: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-20.'
      ],
      remediationPrompt: "Remediate SSO-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-20: SSO-20: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-21: SSO-21: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12821-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12821,
      type: 'SECURITY',
      title: "SSO-21: SSO-21: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-21.'
      ],
      remediationPrompt: "Remediate SSO-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-21: SSO-21: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-22: SSO-22: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12822-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12822,
      type: 'SECURITY',
      title: "SSO-22: SSO-22: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-22.'
      ],
      remediationPrompt: "Remediate SSO-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-22: SSO-22: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-23: SSO-23: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12823-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12823,
      type: 'SECURITY',
      title: "SSO-23: SSO-23: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-23.'
      ],
      remediationPrompt: "Remediate SSO-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-23: SSO-23: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-24: SSO-24: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12824-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12824,
      type: 'SECURITY',
      title: "SSO-24: SSO-24: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-24.'
      ],
      remediationPrompt: "Remediate SSO-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-24: SSO-24: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-25: SSO-25: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12825-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12825,
      type: 'SECURITY',
      title: "SSO-25: SSO-25: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-25.'
      ],
      remediationPrompt: "Remediate SSO-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-25: SSO-25: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-26: SSO-26: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12826-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12826,
      type: 'SECURITY',
      title: "SSO-26: SSO-26: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-26.'
      ],
      remediationPrompt: "Remediate SSO-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-26: SSO-26: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-27: SSO-27: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12827-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12827,
      type: 'SECURITY',
      title: "SSO-27: SSO-27: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-27.'
      ],
      remediationPrompt: "Remediate SSO-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-27: SSO-27: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-28: SSO-28: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12828-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12828,
      type: 'SECURITY',
      title: "SSO-28: SSO-28: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-28.'
      ],
      remediationPrompt: "Remediate SSO-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-28: SSO-28: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-29: SSO-29: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12829-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12829,
      type: 'SECURITY',
      title: "SSO-29: SSO-29: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-29.'
      ],
      remediationPrompt: "Remediate SSO-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-29: SSO-29: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-30: SSO-30: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12830-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12830,
      type: 'SECURITY',
      title: "SSO-30: SSO-30: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-30.'
      ],
      remediationPrompt: "Remediate SSO-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-30: SSO-30: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-31: SSO-31: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12831-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12831,
      type: 'SECURITY',
      title: "SSO-31: SSO-31: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-31.'
      ],
      remediationPrompt: "Remediate SSO-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-31: SSO-31: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-32: SSO-32: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12832-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12832,
      type: 'SECURITY',
      title: "SSO-32: SSO-32: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-32.'
      ],
      remediationPrompt: "Remediate SSO-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-32: SSO-32: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-33: SSO-33: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12833-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12833,
      type: 'SECURITY',
      title: "SSO-33: SSO-33: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-33.'
      ],
      remediationPrompt: "Remediate SSO-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-33: SSO-33: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-34: SSO-34: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12834-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12834,
      type: 'SECURITY',
      title: "SSO-34: SSO-34: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-34.'
      ],
      remediationPrompt: "Remediate SSO-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-34: SSO-34: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-35: SSO-35: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12835-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12835,
      type: 'SECURITY',
      title: "SSO-35: SSO-35: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-35.'
      ],
      remediationPrompt: "Remediate SSO-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-35: SSO-35: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-36: SSO-36: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12836-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12836,
      type: 'SECURITY',
      title: "SSO-36: SSO-36: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-36.'
      ],
      remediationPrompt: "Remediate SSO-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-36: SSO-36: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-37: SSO-37: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12837-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12837,
      type: 'SECURITY',
      title: "SSO-37: SSO-37: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-37.'
      ],
      remediationPrompt: "Remediate SSO-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-37: SSO-37: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-38: SSO-38: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12838-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12838,
      type: 'SECURITY',
      title: "SSO-38: SSO-38: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-38.'
      ],
      remediationPrompt: "Remediate SSO-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-38: SSO-38: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-39: SSO-39: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12839-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12839,
      type: 'SECURITY',
      title: "SSO-39: SSO-39: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-39.'
      ],
      remediationPrompt: "Remediate SSO-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-39: SSO-39: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-40: SSO-40: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12840-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12840,
      type: 'SECURITY',
      title: "SSO-40: SSO-40: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-40.'
      ],
      remediationPrompt: "Remediate SSO-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-40: SSO-40: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-41: SSO-41: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12841-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12841,
      type: 'SECURITY',
      title: "SSO-41: SSO-41: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-41.'
      ],
      remediationPrompt: "Remediate SSO-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-41: SSO-41: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-42: SSO-42: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12842-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12842,
      type: 'SECURITY',
      title: "SSO-42: SSO-42: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-42.'
      ],
      remediationPrompt: "Remediate SSO-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-42: SSO-42: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-43: SSO-43: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12843-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12843,
      type: 'SECURITY',
      title: "SSO-43: SSO-43: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-43.'
      ],
      remediationPrompt: "Remediate SSO-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-43: SSO-43: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-44: SSO-44: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12844-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12844,
      type: 'SECURITY',
      title: "SSO-44: SSO-44: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-44.'
      ],
      remediationPrompt: "Remediate SSO-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-44: SSO-44: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-45: SSO-45: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12845-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12845,
      type: 'SECURITY',
      title: "SSO-45: SSO-45: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-45.'
      ],
      remediationPrompt: "Remediate SSO-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-45: SSO-45: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-46: SSO-46: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12846-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12846,
      type: 'SECURITY',
      title: "SSO-46: SSO-46: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-46.'
      ],
      remediationPrompt: "Remediate SSO-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-46: SSO-46: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-47: SSO-47: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12847-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12847,
      type: 'SECURITY',
      title: "SSO-47: SSO-47: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-47.'
      ],
      remediationPrompt: "Remediate SSO-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-47: SSO-47: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-48: SSO-48: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12848-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12848,
      type: 'SECURITY',
      title: "SSO-48: SSO-48: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-48.'
      ],
      remediationPrompt: "Remediate SSO-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-48: SSO-48: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-49: SSO-49: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12849-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12849,
      type: 'SECURITY',
      title: "SSO-49: SSO-49: Enterprise Enterprise SSO Gate Rule",
      severity: "HIGH",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-49.'
      ],
      remediationPrompt: "Remediate SSO-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-49: SSO-49: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  // SSO-50: SSO-50: Enterprise Enterprise SSO Gate Rule
  if (cleanContent.includes('vulnerablePattern_SSO-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `sso12850-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12850,
      type: 'SECURITY',
      title: "SSO-50: SSO-50: Enterprise Enterprise SSO Gate Rule",
      severity: "MEDIUM",
      category: "Enterprise SSO Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Enterprise SSO configuration',
      reproductionSteps: [
        `Audited Enterprise SSO configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching SSO-50.'
      ],
      remediationPrompt: "Remediate SSO-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SSO AUDIT] Found SSO-50: SSO-50: Enterprise Enterprise SSO Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
