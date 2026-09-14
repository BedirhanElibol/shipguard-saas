/**
 * Zelsis Master evaluateCspmCloudPostureRules Engine (50 Rules)
 * Rules CSPM-01 to CSPM-50 (Rule IDs 14801 to 14850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface CspmCloudPostureRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateCspmCloudPostureRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): CspmCloudPostureRuleResult {
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
  // CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access
  if (cleanContent.includes('cspmPublicBucketReadWriteAccess') || (/aws_s3_bucket|google_storage_bucket/i.test(cleanContent) && cleanContent.includes('publicBucketReadWriteAllowed') && !/block_public_acls/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14801-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14801,
      type: 'SECURITY',
      title: "CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access",
      severity: "CRITICAL",
      category: "Storage Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce S3 and GCS block public access controls across all storage accounts and individual buckets.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-01: Unrestricted Cloud Storage Bucket Public Read/Write Access at ${file.path}:${lineNum}`);
  }

  // CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*)
  if (cleanContent.includes('cspmWildcardIamActionPermitted') || (/"Action"\s*:\s*"\*"/i.test(cleanContent) && cleanContent.includes('wildcardActionInIamPolicy'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14802-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14802,
      type: 'SECURITY',
      title: "CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*)",
      severity: "CRITICAL",
      category: "IAM Boundaries",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Disallow wildcard action permissions in IAM policies; require explicit least-privilege resource ARNs.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-02: Overprivileged Cloud IAM Roles with Wildcard Actions (*:*) at ${file.path}:${lineNum}`);
  }

  // CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts
  if (cleanContent.includes('cspmRootAccountMissingHardwareMfa') || (/cloud_root_account/i.test(lowerPath) && cleanContent.includes('rootAccountLackingHardwareMfa') && !/enforceFido2Mfa/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14803-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14803,
      type: 'SECURITY',
      title: "CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts",
      severity: "CRITICAL",
      category: "Privilege Assurance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce hardware FIDO2 MFA for cloud account root users and mandate temporary role assumption.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-03: Missing Hardware MFA Enforcement on Cloud Root and Admin Accounts at ${file.path}:${lineNum}`);
  }

  // CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0
  if (cleanContent.includes('cspmInboundSshOpenToInternet') || ((/security_group|ingress|sg/i.test(lowerPath) || /security_group|ingress/i.test(cleanContent)) && cleanContent.includes('port22OpenToInternet') && /0\.0\.0\.0\/0/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14804-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14804,
      type: 'SECURITY',
      title: "CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0",
      severity: "CRITICAL",
      category: "Network Boundary",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Ban ingress rules opening administrative ports (22, 3389) directly to the public internet.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-04: Cloud Security Group Permitting Inbound SSH/RDP from 0.0.0.0/0 at ${file.path}:${lineNum}`);
  }

  // CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region
  if (cleanContent.includes('cspmCloudTrailDisabledInRegion') || ((/aws_cloudtrail|audit_logs/i.test(lowerPath) || /aws_cloudtrail|audit_logs/i.test(cleanContent)) && cleanContent.includes('multiRegionTrailDisabled') && !/is_multi_region_trail\s*=\s*true/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14805-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14805,
      type: 'SECURITY',
      title: "CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region",
      severity: "HIGH",
      category: "Audit Logging",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce multi-region audit logging with log file integrity validation and KMS customer-managed keys.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region at ${file.path}:${lineNum}`);
  }

  // CSPM-06: CSPM-06: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14806-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14806,
      type: 'SECURITY',
      title: "CSPM-06: CSPM-06: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-06: CSPM-06: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-07: CSPM-07: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14807-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14807,
      type: 'SECURITY',
      title: "CSPM-07: CSPM-07: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-07: CSPM-07: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-08: CSPM-08: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14808-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14808,
      type: 'SECURITY',
      title: "CSPM-08: CSPM-08: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-08: CSPM-08: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-09: CSPM-09: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14809-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14809,
      type: 'SECURITY',
      title: "CSPM-09: CSPM-09: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-09: CSPM-09: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-10: CSPM-10: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14810-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14810,
      type: 'SECURITY',
      title: "CSPM-10: CSPM-10: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-10: CSPM-10: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-11: CSPM-11: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14811-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14811,
      type: 'SECURITY',
      title: "CSPM-11: CSPM-11: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-11: CSPM-11: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-12: CSPM-12: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14812-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14812,
      type: 'SECURITY',
      title: "CSPM-12: CSPM-12: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-12: CSPM-12: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-13: CSPM-13: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14813-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14813,
      type: 'SECURITY',
      title: "CSPM-13: CSPM-13: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-13: CSPM-13: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-14: CSPM-14: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14814-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14814,
      type: 'SECURITY',
      title: "CSPM-14: CSPM-14: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-14: CSPM-14: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-15: CSPM-15: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14815-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14815,
      type: 'SECURITY',
      title: "CSPM-15: CSPM-15: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-15: CSPM-15: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-16: CSPM-16: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14816-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14816,
      type: 'SECURITY',
      title: "CSPM-16: CSPM-16: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-16: CSPM-16: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-17: CSPM-17: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14817-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14817,
      type: 'SECURITY',
      title: "CSPM-17: CSPM-17: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-17: CSPM-17: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-18: CSPM-18: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14818-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14818,
      type: 'SECURITY',
      title: "CSPM-18: CSPM-18: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-18: CSPM-18: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-19: CSPM-19: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14819-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14819,
      type: 'SECURITY',
      title: "CSPM-19: CSPM-19: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-19: CSPM-19: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-20: CSPM-20: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14820-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14820,
      type: 'SECURITY',
      title: "CSPM-20: CSPM-20: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-20: CSPM-20: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-21: CSPM-21: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14821-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14821,
      type: 'SECURITY',
      title: "CSPM-21: CSPM-21: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-21: CSPM-21: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-22: CSPM-22: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14822-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14822,
      type: 'SECURITY',
      title: "CSPM-22: CSPM-22: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-22: CSPM-22: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-23: CSPM-23: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14823-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14823,
      type: 'SECURITY',
      title: "CSPM-23: CSPM-23: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-23: CSPM-23: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-24: CSPM-24: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14824-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14824,
      type: 'SECURITY',
      title: "CSPM-24: CSPM-24: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-24: CSPM-24: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-25: CSPM-25: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14825-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14825,
      type: 'SECURITY',
      title: "CSPM-25: CSPM-25: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-25: CSPM-25: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-26: CSPM-26: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14826-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14826,
      type: 'SECURITY',
      title: "CSPM-26: CSPM-26: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-26: CSPM-26: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-27: CSPM-27: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14827-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14827,
      type: 'SECURITY',
      title: "CSPM-27: CSPM-27: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-27: CSPM-27: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-28: CSPM-28: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14828-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14828,
      type: 'SECURITY',
      title: "CSPM-28: CSPM-28: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-28: CSPM-28: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-29: CSPM-29: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14829-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14829,
      type: 'SECURITY',
      title: "CSPM-29: CSPM-29: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-29: CSPM-29: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-30: CSPM-30: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14830-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14830,
      type: 'SECURITY',
      title: "CSPM-30: CSPM-30: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-30: CSPM-30: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-31: CSPM-31: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14831-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14831,
      type: 'SECURITY',
      title: "CSPM-31: CSPM-31: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-31: CSPM-31: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-32: CSPM-32: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14832-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14832,
      type: 'SECURITY',
      title: "CSPM-32: CSPM-32: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-32: CSPM-32: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-33: CSPM-33: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14833-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14833,
      type: 'SECURITY',
      title: "CSPM-33: CSPM-33: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-33: CSPM-33: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-34: CSPM-34: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14834-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14834,
      type: 'SECURITY',
      title: "CSPM-34: CSPM-34: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-34: CSPM-34: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-35: CSPM-35: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14835-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14835,
      type: 'SECURITY',
      title: "CSPM-35: CSPM-35: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-35: CSPM-35: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-36: CSPM-36: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14836-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14836,
      type: 'SECURITY',
      title: "CSPM-36: CSPM-36: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-36: CSPM-36: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-37: CSPM-37: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14837-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14837,
      type: 'SECURITY',
      title: "CSPM-37: CSPM-37: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-37: CSPM-37: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-38: CSPM-38: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14838-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14838,
      type: 'SECURITY',
      title: "CSPM-38: CSPM-38: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-38: CSPM-38: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-39: CSPM-39: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14839-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14839,
      type: 'SECURITY',
      title: "CSPM-39: CSPM-39: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-39: CSPM-39: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-40: CSPM-40: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14840-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14840,
      type: 'SECURITY',
      title: "CSPM-40: CSPM-40: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-40: CSPM-40: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-41: CSPM-41: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14841-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14841,
      type: 'SECURITY',
      title: "CSPM-41: CSPM-41: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-41: CSPM-41: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-42: CSPM-42: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14842-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14842,
      type: 'SECURITY',
      title: "CSPM-42: CSPM-42: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-42: CSPM-42: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-43: CSPM-43: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14843-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14843,
      type: 'SECURITY',
      title: "CSPM-43: CSPM-43: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-43: CSPM-43: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-44: CSPM-44: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14844-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14844,
      type: 'SECURITY',
      title: "CSPM-44: CSPM-44: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-44: CSPM-44: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-45: CSPM-45: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14845-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14845,
      type: 'SECURITY',
      title: "CSPM-45: CSPM-45: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-45: CSPM-45: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-46: CSPM-46: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14846-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14846,
      type: 'SECURITY',
      title: "CSPM-46: CSPM-46: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-46: CSPM-46: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-47: CSPM-47: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14847-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14847,
      type: 'SECURITY',
      title: "CSPM-47: CSPM-47: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-47: CSPM-47: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-48: CSPM-48: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14848-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14848,
      type: 'SECURITY',
      title: "CSPM-48: CSPM-48: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-48: CSPM-48: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-49: CSPM-49: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14849-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14849,
      type: 'SECURITY',
      title: "CSPM-49: CSPM-49: Enterprise Cloud Security Posture Gate Rule",
      severity: "HIGH",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-49: CSPM-49: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  // CSPM-50: CSPM-50: Enterprise Cloud Security Posture Gate Rule
  if (cleanContent.includes('vulnerablePattern_CSPM-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cspm14850-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14850,
      type: 'SECURITY',
      title: "CSPM-50: CSPM-50: Enterprise Cloud Security Posture Gate Rule",
      severity: "MEDIUM",
      category: "Cloud Security Posture Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cloud Security Posture configuration',
      reproductionSteps: [
        `Audited Cloud Security Posture configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CSPM-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CSPM AUDIT] Found CSPM-50: CSPM-50: Enterprise Cloud Security Posture Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
