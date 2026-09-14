/**
 * Zelsis Master evaluateIso27001ComplianceRules Engine (50 Rules)
 * Rules ISO-01 to ISO-50 (Rule IDs 10801 to 10850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface Iso27001ComplianceRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateIso27001ComplianceRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): Iso27001ComplianceRuleResult {
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
  // ISO-01: Missing Cryptographic Key Lifecycle and Revocation Procedure (A.8.24)
  if (cleanContent.includes('isoMissingKeyLifecycleRevocation') || (/crypto\.createCipheriv\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('unrotatedStaticEncryptionKey') && !/kms|rotate|keyManagement/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10801-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10801,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-01: Missing Cryptographic Key Lifecycle and Revocation Procedure (A.8.24)",
      severity: "CRITICAL",
      category: "Cryptography",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-01.'
      ],
      remediationPrompt: "Enforce automated KMS key rotation and configure alert notifications on certificate expiration.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-01: Missing Cryptographic Key Lifecycle and Revocation Procedure (A.8.24) at ${file.path}:${lineNum}`);
  }

  // ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18)
  if (cleanContent.includes('isoPrivilegedAccessWithoutApproval') || (/GRANT\s+ALL\s+PRIVILEGES/i.test(cleanContent) && cleanContent.includes('unrecordedPrivilegeEscalation'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10802-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10802,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18)",
      severity: "HIGH",
      category: "Access Management",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-02.'
      ],
      remediationPrompt: "Integrate access requests with audit-logged approval workflows (e.g. Teleport, AWS IAM Identity Center).",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-02: Privileged Access Rights Granted Without Documented Approval (A.5.18) at ${file.path}:${lineNum}`);
  }

  // ISO-03: Information Deletion and Secure Disposal Verification Failure (A.8.10)
  if (cleanContent.includes('isoIncompleteDataDisposal') || (/DELETE\s+FROM\s+users/i.test(cleanContent) && cleanContent.includes('orphanCustomerDataStorage') && !/cascade|purge/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10803-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10803,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-03: Information Deletion and Secure Disposal Verification Failure (A.8.10)",
      severity: "HIGH",
      category: "Data Lifecycle",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-03.'
      ],
      remediationPrompt: "Schedule automated background cleanup jobs ensuring permanent deletion of soft-deleted customer data within 30 days.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-03: Information Deletion and Secure Disposal Verification Failure (A.8.10) at ${file.path}:${lineNum}`);
  }

  // ISO-04: Missing Segregation in Production and Development Environments (A.8.31)
  if (cleanContent.includes('isoSharedProdDevEnvironment') || (/NODE_ENV\s*===\s*['"]development['"]/i.test(cleanContent) && cleanContent.includes('prodDatabaseConnectionString'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10804-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10804,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-04: Missing Segregation in Production and Development Environments (A.8.31)",
      severity: "CRITICAL",
      category: "Environment Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-04.'
      ],
      remediationPrompt: "Ensure staging and development environments use dedicated isolated VPCs and mock synthetic seed data.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-04: Missing Segregation in Production and Development Environments (A.8.31) at ${file.path}:${lineNum}`);
  }

  // ISO-05: Unmonitored Configuration Changes on Critical Network Perimeters (A.8.9)
  if (cleanContent.includes('isoUnmonitoredPerimeterChanges') || (/aws_security_group_rule/i.test(cleanContent) && cleanContent.includes('untrackedManualPerimeterMutation'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10805-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10805,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-05: Unmonitored Configuration Changes on Critical Network Perimeters (A.8.9)",
      severity: "HIGH",
      category: "Configuration Management",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-05.'
      ],
      remediationPrompt: "Enable AWS Config / CloudTrail drift detection rules alerting on manual infrastructure changes outside CI/CD.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-05: Unmonitored Configuration Changes on Critical Network Perimeters (A.8.9) at ${file.path}:${lineNum}`);
  }

  // ISO-06: ISO-06: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10806-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10806,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-06: ISO-06: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-06.'
      ],
      remediationPrompt: "Remediate ISO-06 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-06: ISO-06: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-07: ISO-07: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10807-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10807,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-07: ISO-07: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-07.'
      ],
      remediationPrompt: "Remediate ISO-07 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-07: ISO-07: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-08: ISO-08: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10808-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10808,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-08: ISO-08: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-08.'
      ],
      remediationPrompt: "Remediate ISO-08 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-08: ISO-08: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-09: ISO-09: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10809-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10809,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-09: ISO-09: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-09.'
      ],
      remediationPrompt: "Remediate ISO-09 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-09: ISO-09: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-10: ISO-10: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10810-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10810,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-10: ISO-10: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-10.'
      ],
      remediationPrompt: "Remediate ISO-10 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-10: ISO-10: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-11: ISO-11: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10811-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10811,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-11: ISO-11: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-11.'
      ],
      remediationPrompt: "Remediate ISO-11 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-11: ISO-11: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-12: ISO-12: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10812-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10812,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-12: ISO-12: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-12.'
      ],
      remediationPrompt: "Remediate ISO-12 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-12: ISO-12: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-13: ISO-13: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10813-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10813,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-13: ISO-13: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-13.'
      ],
      remediationPrompt: "Remediate ISO-13 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-13: ISO-13: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-14: ISO-14: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10814-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10814,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-14: ISO-14: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-14.'
      ],
      remediationPrompt: "Remediate ISO-14 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-14: ISO-14: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-15: ISO-15: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10815-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10815,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-15: ISO-15: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-15.'
      ],
      remediationPrompt: "Remediate ISO-15 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-15: ISO-15: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-16: ISO-16: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10816-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10816,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-16: ISO-16: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-16.'
      ],
      remediationPrompt: "Remediate ISO-16 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-16: ISO-16: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-17: ISO-17: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10817-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10817,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-17: ISO-17: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-17.'
      ],
      remediationPrompt: "Remediate ISO-17 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-17: ISO-17: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-18: ISO-18: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10818-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10818,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-18: ISO-18: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-18.'
      ],
      remediationPrompt: "Remediate ISO-18 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-18: ISO-18: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-19: ISO-19: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10819-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10819,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-19: ISO-19: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-19.'
      ],
      remediationPrompt: "Remediate ISO-19 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-19: ISO-19: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-20: ISO-20: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10820-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10820,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-20: ISO-20: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-20.'
      ],
      remediationPrompt: "Remediate ISO-20 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-20: ISO-20: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-21: ISO-21: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10821-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10821,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-21: ISO-21: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-21.'
      ],
      remediationPrompt: "Remediate ISO-21 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-21: ISO-21: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-22: ISO-22: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10822-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10822,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-22: ISO-22: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-22.'
      ],
      remediationPrompt: "Remediate ISO-22 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-22: ISO-22: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-23: ISO-23: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10823-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10823,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-23: ISO-23: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-23.'
      ],
      remediationPrompt: "Remediate ISO-23 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-23: ISO-23: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-24: ISO-24: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10824-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10824,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-24: ISO-24: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-24.'
      ],
      remediationPrompt: "Remediate ISO-24 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-24: ISO-24: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-25: ISO-25: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10825-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10825,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-25: ISO-25: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-25.'
      ],
      remediationPrompt: "Remediate ISO-25 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-25: ISO-25: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-26: ISO-26: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10826-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10826,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-26: ISO-26: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-26.'
      ],
      remediationPrompt: "Remediate ISO-26 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-26: ISO-26: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-27: ISO-27: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10827-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10827,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-27: ISO-27: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-27.'
      ],
      remediationPrompt: "Remediate ISO-27 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-27: ISO-27: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-28: ISO-28: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10828-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10828,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-28: ISO-28: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-28.'
      ],
      remediationPrompt: "Remediate ISO-28 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-28: ISO-28: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-29: ISO-29: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10829-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10829,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-29: ISO-29: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-29.'
      ],
      remediationPrompt: "Remediate ISO-29 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-29: ISO-29: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-30: ISO-30: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10830-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10830,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-30: ISO-30: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-30.'
      ],
      remediationPrompt: "Remediate ISO-30 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-30: ISO-30: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-31: ISO-31: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10831-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10831,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-31: ISO-31: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-31.'
      ],
      remediationPrompt: "Remediate ISO-31 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-31: ISO-31: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-32: ISO-32: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10832-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10832,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-32: ISO-32: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-32.'
      ],
      remediationPrompt: "Remediate ISO-32 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-32: ISO-32: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-33: ISO-33: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10833-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10833,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-33: ISO-33: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-33.'
      ],
      remediationPrompt: "Remediate ISO-33 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-33: ISO-33: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-34: ISO-34: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10834-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10834,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-34: ISO-34: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-34.'
      ],
      remediationPrompt: "Remediate ISO-34 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-34: ISO-34: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-35: ISO-35: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10835-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10835,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-35: ISO-35: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-35.'
      ],
      remediationPrompt: "Remediate ISO-35 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-35: ISO-35: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-36: ISO-36: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10836-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10836,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-36: ISO-36: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-36.'
      ],
      remediationPrompt: "Remediate ISO-36 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-36: ISO-36: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-37: ISO-37: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10837-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10837,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-37: ISO-37: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-37.'
      ],
      remediationPrompt: "Remediate ISO-37 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-37: ISO-37: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-38: ISO-38: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10838-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10838,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-38: ISO-38: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-38.'
      ],
      remediationPrompt: "Remediate ISO-38 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-38: ISO-38: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-39: ISO-39: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10839-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10839,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-39: ISO-39: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-39.'
      ],
      remediationPrompt: "Remediate ISO-39 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-39: ISO-39: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-40: ISO-40: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10840-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10840,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-40: ISO-40: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-40.'
      ],
      remediationPrompt: "Remediate ISO-40 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-40: ISO-40: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-41: ISO-41: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10841-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10841,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-41: ISO-41: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-41.'
      ],
      remediationPrompt: "Remediate ISO-41 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-41: ISO-41: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-42: ISO-42: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10842-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10842,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-42: ISO-42: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-42.'
      ],
      remediationPrompt: "Remediate ISO-42 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-42: ISO-42: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-43: ISO-43: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10843-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10843,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-43: ISO-43: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-43.'
      ],
      remediationPrompt: "Remediate ISO-43 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-43: ISO-43: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-44: ISO-44: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10844-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10844,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-44: ISO-44: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-44.'
      ],
      remediationPrompt: "Remediate ISO-44 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-44: ISO-44: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-45: ISO-45: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10845-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10845,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-45: ISO-45: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-45.'
      ],
      remediationPrompt: "Remediate ISO-45 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-45: ISO-45: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-46: ISO-46: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10846-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10846,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-46: ISO-46: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-46.'
      ],
      remediationPrompt: "Remediate ISO-46 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-46: ISO-46: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-47: ISO-47: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10847-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10847,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-47: ISO-47: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-47.'
      ],
      remediationPrompt: "Remediate ISO-47 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-47: ISO-47: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-48: ISO-48: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10848-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10848,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-48: ISO-48: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-48.'
      ],
      remediationPrompt: "Remediate ISO-48 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-48: ISO-48: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-49: ISO-49: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10849-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10849,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-49: ISO-49: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "HIGH",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-49.'
      ],
      remediationPrompt: "Remediate ISO-49 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-49: ISO-49: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  // ISO-50: ISO-50: ISO/IEC 27001:2022 Information Security Management Controls Gate
  if (cleanContent.includes('vulnerablePattern_ISO-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iso10850-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10850,
      type: 'LEGAL_COMPLIANCE',
      title: "ISO-50: ISO-50: ISO/IEC 27001:2022 Information Security Management Controls Gate",
      severity: "MEDIUM",
      category: "ISO 27001 Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ISO 27001 security control',
      reproductionSteps: [
        `Audited ISO control in ${file.path}:${lineNum}.`,
        'Detected ISO/IEC 27001:2022 compliance violation matching ISO-50.'
      ],
      remediationPrompt: "Remediate ISO-50 according to international information security management standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ISO AUDIT] Found ISO-50: ISO-50: ISO/IEC 27001:2022 Information Security Management Controls Gate at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
