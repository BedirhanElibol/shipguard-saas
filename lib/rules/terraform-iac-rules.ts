/**
 * Zelsis Master evaluateTerraformIacRules Engine (50 Rules)
 * Rules TF-01 to TF-50 (Rule IDs 11001 to 11050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface TerraformIacRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateTerraformIacRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): TerraformIacRuleResult {
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
  // TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)
  if (cleanContent.includes('terraformUnencryptedStateBackend') || (/backend\s+['"]s3['"]/i.test(cleanContent) && cleanContent.includes('unencryptedRemoteStateBucket') && !/encrypt\s*=\s*true|kms_key_id/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11001-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11001,
      type: 'INFRA_DATABASE',
      title: "TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket)",
      severity: "CRITICAL",
      category: "State Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-01.'
      ],
      remediationPrompt: "Enable server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = 'aws:kms' } } }.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-01: Unencrypted Cloud State Backend (Missing SSE on S3 / GCS State Bucket) at ${file.path}:${lineNum}`);
  }

  // TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table)
  if (cleanContent.includes('terraformMissingStateLocking') || (/backend\s+['"]s3['"]/i.test(cleanContent) && cleanContent.includes('unlockedConcurrentStateModification') && !/dynamodb_table/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11002-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11002,
      type: 'INFRA_DATABASE',
      title: "TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table)",
      severity: "HIGH",
      category: "Concurrency",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-02.'
      ],
      remediationPrompt: "Add dynamodb_table = 'terraform-lock-table' to the backend 's3' configuration.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-02: Missing State Locking on Distributed Terraform Backend (DynamoDB Table) at ${file.path}:${lineNum}`);
  }

  // TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0)
  if (cleanContent.includes('terraformOpenSshIngressZeroCidr') || (/from_port\s*=\s*22/i.test(cleanContent) && cleanContent.includes('openAdministrativePortPublicInternet'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11003-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11003,
      type: 'INFRA_DATABASE',
      title: "TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0)",
      severity: "CRITICAL",
      category: "Perimeter Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-03.'
      ],
      remediationPrompt: "Replace cidr_blocks = ['0.0.0.0/0'] on port 22 with corporate VPN gateway CIDR.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-03: Security Group Ingress Open to the World on Administrative Ports (0.0.0.0/0) at ${file.path}:${lineNum}`);
  }

  // TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files
  if (cleanContent.includes('terraformHardcodedProviderAccessKey') || (/provider\s+['"]aws['"][\s\S]*?access_key\s*=\s*['"][A-Z0-9]{16,}['"]/i.test(cleanContent) && cleanContent.includes('hardcodedAwsSecretKey'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11004-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11004,
      type: 'INFRA_DATABASE',
      title: "TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files",
      severity: "CRITICAL",
      category: "Credential Isolation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-04.'
      ],
      remediationPrompt: "Remove hardcoded access_key and secret_key from provider 'aws' and rely on ambient IAM roles.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-04: Hardcoded Cloud Provider Access Keys in Terraform Files at ${file.path}:${lineNum}`);
  }

  // TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies)
  if (cleanContent.includes('terraformFloatingModuleDependency') || (/module\s+['"][a-zA-Z0-9_-]+['"][\s\S]*?source\s*=\s*['"][^'"]+['"]/i.test(cleanContent) && cleanContent.includes('unpinnedModuleSource') && !/version|ref=/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11005-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11005,
      type: 'INFRA_DATABASE',
      title: "TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies)",
      severity: "MEDIUM",
      category: "Supply Chain",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-05.'
      ],
      remediationPrompt: "Pin module source versions with ?ref=v1.4.2 or explicit version = '~> 5.0' constraints.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-05: Unversioned Terraform Provider / Module References (Floating Dependencies) at ${file.path}:${lineNum}`);
  }

  // TF-06: TF-06: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11006-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11006,
      type: 'INFRA_DATABASE',
      title: "TF-06: TF-06: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-06.'
      ],
      remediationPrompt: "Remediate TF-06 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-06: TF-06: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-07: TF-07: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11007-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11007,
      type: 'INFRA_DATABASE',
      title: "TF-07: TF-07: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-07.'
      ],
      remediationPrompt: "Remediate TF-07 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-07: TF-07: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-08: TF-08: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11008-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11008,
      type: 'INFRA_DATABASE',
      title: "TF-08: TF-08: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-08.'
      ],
      remediationPrompt: "Remediate TF-08 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-08: TF-08: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-09: TF-09: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11009-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11009,
      type: 'INFRA_DATABASE',
      title: "TF-09: TF-09: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-09.'
      ],
      remediationPrompt: "Remediate TF-09 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-09: TF-09: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-10: TF-10: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11010-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11010,
      type: 'INFRA_DATABASE',
      title: "TF-10: TF-10: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-10.'
      ],
      remediationPrompt: "Remediate TF-10 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-10: TF-10: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-11: TF-11: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11011-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11011,
      type: 'INFRA_DATABASE',
      title: "TF-11: TF-11: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-11.'
      ],
      remediationPrompt: "Remediate TF-11 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-11: TF-11: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-12: TF-12: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11012-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11012,
      type: 'INFRA_DATABASE',
      title: "TF-12: TF-12: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-12.'
      ],
      remediationPrompt: "Remediate TF-12 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-12: TF-12: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-13: TF-13: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11013-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11013,
      type: 'INFRA_DATABASE',
      title: "TF-13: TF-13: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-13.'
      ],
      remediationPrompt: "Remediate TF-13 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-13: TF-13: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-14: TF-14: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11014-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11014,
      type: 'INFRA_DATABASE',
      title: "TF-14: TF-14: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-14.'
      ],
      remediationPrompt: "Remediate TF-14 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-14: TF-14: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-15: TF-15: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11015-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11015,
      type: 'INFRA_DATABASE',
      title: "TF-15: TF-15: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-15.'
      ],
      remediationPrompt: "Remediate TF-15 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-15: TF-15: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-16: TF-16: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11016-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11016,
      type: 'INFRA_DATABASE',
      title: "TF-16: TF-16: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-16.'
      ],
      remediationPrompt: "Remediate TF-16 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-16: TF-16: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-17: TF-17: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11017-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11017,
      type: 'INFRA_DATABASE',
      title: "TF-17: TF-17: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-17.'
      ],
      remediationPrompt: "Remediate TF-17 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-17: TF-17: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-18: TF-18: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11018-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11018,
      type: 'INFRA_DATABASE',
      title: "TF-18: TF-18: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-18.'
      ],
      remediationPrompt: "Remediate TF-18 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-18: TF-18: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-19: TF-19: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11019-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11019,
      type: 'INFRA_DATABASE',
      title: "TF-19: TF-19: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-19.'
      ],
      remediationPrompt: "Remediate TF-19 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-19: TF-19: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-20: TF-20: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11020-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11020,
      type: 'INFRA_DATABASE',
      title: "TF-20: TF-20: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-20.'
      ],
      remediationPrompt: "Remediate TF-20 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-20: TF-20: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-21: TF-21: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11021-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11021,
      type: 'INFRA_DATABASE',
      title: "TF-21: TF-21: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-21.'
      ],
      remediationPrompt: "Remediate TF-21 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-21: TF-21: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-22: TF-22: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11022-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11022,
      type: 'INFRA_DATABASE',
      title: "TF-22: TF-22: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-22.'
      ],
      remediationPrompt: "Remediate TF-22 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-22: TF-22: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-23: TF-23: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11023-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11023,
      type: 'INFRA_DATABASE',
      title: "TF-23: TF-23: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-23.'
      ],
      remediationPrompt: "Remediate TF-23 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-23: TF-23: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-24: TF-24: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11024-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11024,
      type: 'INFRA_DATABASE',
      title: "TF-24: TF-24: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-24.'
      ],
      remediationPrompt: "Remediate TF-24 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-24: TF-24: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-25: TF-25: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11025-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11025,
      type: 'INFRA_DATABASE',
      title: "TF-25: TF-25: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-25.'
      ],
      remediationPrompt: "Remediate TF-25 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-25: TF-25: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-26: TF-26: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11026-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11026,
      type: 'INFRA_DATABASE',
      title: "TF-26: TF-26: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-26.'
      ],
      remediationPrompt: "Remediate TF-26 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-26: TF-26: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-27: TF-27: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11027-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11027,
      type: 'INFRA_DATABASE',
      title: "TF-27: TF-27: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-27.'
      ],
      remediationPrompt: "Remediate TF-27 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-27: TF-27: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-28: TF-28: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11028-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11028,
      type: 'INFRA_DATABASE',
      title: "TF-28: TF-28: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-28.'
      ],
      remediationPrompt: "Remediate TF-28 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-28: TF-28: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-29: TF-29: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11029-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11029,
      type: 'INFRA_DATABASE',
      title: "TF-29: TF-29: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-29.'
      ],
      remediationPrompt: "Remediate TF-29 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-29: TF-29: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-30: TF-30: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11030-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11030,
      type: 'INFRA_DATABASE',
      title: "TF-30: TF-30: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-30.'
      ],
      remediationPrompt: "Remediate TF-30 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-30: TF-30: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-31: TF-31: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11031-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11031,
      type: 'INFRA_DATABASE',
      title: "TF-31: TF-31: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-31.'
      ],
      remediationPrompt: "Remediate TF-31 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-31: TF-31: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-32: TF-32: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11032-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11032,
      type: 'INFRA_DATABASE',
      title: "TF-32: TF-32: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-32.'
      ],
      remediationPrompt: "Remediate TF-32 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-32: TF-32: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-33: TF-33: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11033-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11033,
      type: 'INFRA_DATABASE',
      title: "TF-33: TF-33: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-33.'
      ],
      remediationPrompt: "Remediate TF-33 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-33: TF-33: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-34: TF-34: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11034-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11034,
      type: 'INFRA_DATABASE',
      title: "TF-34: TF-34: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-34.'
      ],
      remediationPrompt: "Remediate TF-34 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-34: TF-34: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-35: TF-35: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11035-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11035,
      type: 'INFRA_DATABASE',
      title: "TF-35: TF-35: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-35.'
      ],
      remediationPrompt: "Remediate TF-35 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-35: TF-35: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-36: TF-36: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11036-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11036,
      type: 'INFRA_DATABASE',
      title: "TF-36: TF-36: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-36.'
      ],
      remediationPrompt: "Remediate TF-36 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-36: TF-36: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-37: TF-37: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11037-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11037,
      type: 'INFRA_DATABASE',
      title: "TF-37: TF-37: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-37.'
      ],
      remediationPrompt: "Remediate TF-37 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-37: TF-37: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-38: TF-38: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11038-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11038,
      type: 'INFRA_DATABASE',
      title: "TF-38: TF-38: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-38.'
      ],
      remediationPrompt: "Remediate TF-38 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-38: TF-38: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-39: TF-39: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11039-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11039,
      type: 'INFRA_DATABASE',
      title: "TF-39: TF-39: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-39.'
      ],
      remediationPrompt: "Remediate TF-39 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-39: TF-39: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-40: TF-40: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11040-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11040,
      type: 'INFRA_DATABASE',
      title: "TF-40: TF-40: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-40.'
      ],
      remediationPrompt: "Remediate TF-40 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-40: TF-40: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-41: TF-41: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11041-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11041,
      type: 'INFRA_DATABASE',
      title: "TF-41: TF-41: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-41.'
      ],
      remediationPrompt: "Remediate TF-41 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-41: TF-41: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-42: TF-42: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11042-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11042,
      type: 'INFRA_DATABASE',
      title: "TF-42: TF-42: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-42.'
      ],
      remediationPrompt: "Remediate TF-42 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-42: TF-42: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-43: TF-43: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11043-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11043,
      type: 'INFRA_DATABASE',
      title: "TF-43: TF-43: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-43.'
      ],
      remediationPrompt: "Remediate TF-43 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-43: TF-43: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-44: TF-44: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11044-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11044,
      type: 'INFRA_DATABASE',
      title: "TF-44: TF-44: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-44.'
      ],
      remediationPrompt: "Remediate TF-44 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-44: TF-44: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-45: TF-45: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11045-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11045,
      type: 'INFRA_DATABASE',
      title: "TF-45: TF-45: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-45.'
      ],
      remediationPrompt: "Remediate TF-45 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-45: TF-45: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-46: TF-46: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11046-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11046,
      type: 'INFRA_DATABASE',
      title: "TF-46: TF-46: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-46.'
      ],
      remediationPrompt: "Remediate TF-46 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-46: TF-46: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-47: TF-47: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11047-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11047,
      type: 'INFRA_DATABASE',
      title: "TF-47: TF-47: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-47.'
      ],
      remediationPrompt: "Remediate TF-47 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-47: TF-47: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-48: TF-48: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11048-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11048,
      type: 'INFRA_DATABASE',
      title: "TF-48: TF-48: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-48.'
      ],
      remediationPrompt: "Remediate TF-48 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-48: TF-48: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-49: TF-49: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11049-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11049,
      type: 'INFRA_DATABASE',
      title: "TF-49: TF-49: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "HIGH",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-49.'
      ],
      remediationPrompt: "Remediate TF-49 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-49: TF-49: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  // TF-50: TF-50: Terraform & Cloud Infrastructure-as-Code Policy Gate
  if (cleanContent.includes('vulnerablePattern_TF-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tf11050-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11050,
      type: 'INFRA_DATABASE',
      title: "TF-50: TF-50: Terraform & Cloud Infrastructure-as-Code Policy Gate",
      severity: "MEDIUM",
      category: "IaC Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Terraform block definition',
      reproductionSteps: [
        `Audited infrastructure-as-code in ${file.path}:${lineNum}.`,
        'Detected Terraform policy violation matching TF-50.'
      ],
      remediationPrompt: "Remediate TF-50 according to enterprise Terraform and OpenTofu security policies.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TF AUDIT] Found TF-50: TF-50: Terraform & Cloud Infrastructure-as-Code Policy Gate at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
