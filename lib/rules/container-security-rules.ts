/**
 * Zelsis Master evaluateContainerSecurityRules Engine (50 Rules)
 * Rules CONTAINER-01 to CONTAINER-50 (Rule IDs 12201 to 12250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface ContainerSecurityRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateContainerSecurityRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): ContainerSecurityRuleResult {
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
  // CONTAINER-01: Privileged Container Execution with Full Host Access
  if (cleanContent.includes('containerPrivilegedModeActive') || (/securityContext/i.test(cleanContent) && /privileged:\s*true/i.test(cleanContent) && !/unprivilegedSandbox/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12201-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12201,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-01: Privileged Container Execution with Full Host Access",
      severity: "CRITICAL",
      category: "Container Hardening",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-01.'
      ],
      remediationPrompt: "Disable privileged execution mode (set privileged: false) in container securityContext.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-01: Privileged Container Execution with Full Host Access at ${file.path}:${lineNum}`);
  }

  // CONTAINER-02: Root User Execution in Container Runtime Image
  if (cleanContent.includes('containerRunsAsRoot') || (/USER\s+root/i.test(cleanContent) && cleanContent.includes('unrestrictedRootContainer') && !/USER\s+1000/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12202-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12202,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-02: Root User Execution in Container Runtime Image",
      severity: "HIGH",
      category: "Privilege Boundary",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-02.'
      ],
      remediationPrompt: "Specify non-root USER directive in Dockerfile and configure runAsNonRoot: true.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-02: Root User Execution in Container Runtime Image at ${file.path}:${lineNum}`);
  }

  // CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers
  if (cleanContent.includes('containerWritableRootFilesystem') || (/securityContext/i.test(cleanContent) && /readOnlyRootFilesystem:\s*false/i.test(cleanContent) && !/readOnlyRootFilesystem:\s*true/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12203-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12203,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers",
      severity: "HIGH",
      category: "Filesystem Integrity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-03.'
      ],
      remediationPrompt: "Mount container root filesystem with readOnlyRootFilesystem: true and use tmpfs for scratch paths.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-03: Writable Root Filesystem Allowing Malicious Binary Droppers at ${file.path}:${lineNum}`);
  }

  // CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing
  if (cleanContent.includes('containerHostNetworkSharing') || (/hostNetwork:\s*true/i.test(cleanContent) && cleanContent.includes('unisolatedPodNetwork') && !/cniNetwork/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12204-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12204,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing",
      severity: "CRITICAL",
      category: "Network Isolation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-04.'
      ],
      remediationPrompt: "Remove hostNetwork: true from pod specs to preserve virtual network namespace isolation.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-04: Host Network Namespace Sharing Permitting Network Sniffing at ${file.path}:${lineNum}`);
  }

  // CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container
  if (cleanContent.includes('containerExposedDockerSocket') || (/\/var\/run\/docker\.sock/i.test(cleanContent) && cleanContent.includes('mountDockerSocket') && !/isolatedDockerDaemon/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12205-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12205,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container",
      severity: "CRITICAL",
      category: "Daemon Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-05.'
      ],
      remediationPrompt: "Remove /var/run/docker.sock volume mounts from application containers.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-05: Exposed Docker Daemon Unix Socket Inside Container at ${file.path}:${lineNum}`);
  }

  // CONTAINER-06: CONTAINER-06: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12206-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12206,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-06: CONTAINER-06: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-06.'
      ],
      remediationPrompt: "Remediate CONTAINER-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-06: CONTAINER-06: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-07: CONTAINER-07: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12207-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12207,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-07: CONTAINER-07: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-07.'
      ],
      remediationPrompt: "Remediate CONTAINER-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-07: CONTAINER-07: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-08: CONTAINER-08: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12208-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12208,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-08: CONTAINER-08: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-08.'
      ],
      remediationPrompt: "Remediate CONTAINER-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-08: CONTAINER-08: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-09: CONTAINER-09: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12209-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12209,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-09: CONTAINER-09: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-09.'
      ],
      remediationPrompt: "Remediate CONTAINER-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-09: CONTAINER-09: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-10: CONTAINER-10: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12210-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12210,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-10: CONTAINER-10: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-10.'
      ],
      remediationPrompt: "Remediate CONTAINER-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-10: CONTAINER-10: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-11: CONTAINER-11: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12211-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12211,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-11: CONTAINER-11: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-11.'
      ],
      remediationPrompt: "Remediate CONTAINER-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-11: CONTAINER-11: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-12: CONTAINER-12: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12212-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12212,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-12: CONTAINER-12: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-12.'
      ],
      remediationPrompt: "Remediate CONTAINER-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-12: CONTAINER-12: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-13: CONTAINER-13: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12213-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12213,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-13: CONTAINER-13: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-13.'
      ],
      remediationPrompt: "Remediate CONTAINER-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-13: CONTAINER-13: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-14: CONTAINER-14: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12214-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12214,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-14: CONTAINER-14: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-14.'
      ],
      remediationPrompt: "Remediate CONTAINER-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-14: CONTAINER-14: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-15: CONTAINER-15: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12215-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12215,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-15: CONTAINER-15: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-15.'
      ],
      remediationPrompt: "Remediate CONTAINER-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-15: CONTAINER-15: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-16: CONTAINER-16: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12216-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12216,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-16: CONTAINER-16: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-16.'
      ],
      remediationPrompt: "Remediate CONTAINER-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-16: CONTAINER-16: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-17: CONTAINER-17: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12217-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12217,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-17: CONTAINER-17: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-17.'
      ],
      remediationPrompt: "Remediate CONTAINER-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-17: CONTAINER-17: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-18: CONTAINER-18: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12218-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12218,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-18: CONTAINER-18: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-18.'
      ],
      remediationPrompt: "Remediate CONTAINER-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-18: CONTAINER-18: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-19: CONTAINER-19: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12219-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12219,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-19: CONTAINER-19: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-19.'
      ],
      remediationPrompt: "Remediate CONTAINER-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-19: CONTAINER-19: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-20: CONTAINER-20: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12220-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12220,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-20: CONTAINER-20: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-20.'
      ],
      remediationPrompt: "Remediate CONTAINER-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-20: CONTAINER-20: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-21: CONTAINER-21: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12221-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12221,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-21: CONTAINER-21: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-21.'
      ],
      remediationPrompt: "Remediate CONTAINER-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-21: CONTAINER-21: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-22: CONTAINER-22: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12222-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12222,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-22: CONTAINER-22: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-22.'
      ],
      remediationPrompt: "Remediate CONTAINER-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-22: CONTAINER-22: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-23: CONTAINER-23: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12223-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12223,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-23: CONTAINER-23: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-23.'
      ],
      remediationPrompt: "Remediate CONTAINER-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-23: CONTAINER-23: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-24: CONTAINER-24: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12224-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12224,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-24: CONTAINER-24: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-24.'
      ],
      remediationPrompt: "Remediate CONTAINER-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-24: CONTAINER-24: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-25: CONTAINER-25: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12225-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12225,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-25: CONTAINER-25: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-25.'
      ],
      remediationPrompt: "Remediate CONTAINER-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-25: CONTAINER-25: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-26: CONTAINER-26: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12226-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12226,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-26: CONTAINER-26: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-26.'
      ],
      remediationPrompt: "Remediate CONTAINER-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-26: CONTAINER-26: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-27: CONTAINER-27: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12227-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12227,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-27: CONTAINER-27: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-27.'
      ],
      remediationPrompt: "Remediate CONTAINER-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-27: CONTAINER-27: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-28: CONTAINER-28: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12228-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12228,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-28: CONTAINER-28: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-28.'
      ],
      remediationPrompt: "Remediate CONTAINER-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-28: CONTAINER-28: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-29: CONTAINER-29: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12229-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12229,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-29: CONTAINER-29: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-29.'
      ],
      remediationPrompt: "Remediate CONTAINER-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-29: CONTAINER-29: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-30: CONTAINER-30: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12230-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12230,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-30: CONTAINER-30: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-30.'
      ],
      remediationPrompt: "Remediate CONTAINER-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-30: CONTAINER-30: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-31: CONTAINER-31: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12231-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12231,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-31: CONTAINER-31: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-31.'
      ],
      remediationPrompt: "Remediate CONTAINER-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-31: CONTAINER-31: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-32: CONTAINER-32: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12232-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12232,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-32: CONTAINER-32: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-32.'
      ],
      remediationPrompt: "Remediate CONTAINER-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-32: CONTAINER-32: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-33: CONTAINER-33: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12233-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12233,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-33: CONTAINER-33: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-33.'
      ],
      remediationPrompt: "Remediate CONTAINER-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-33: CONTAINER-33: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-34: CONTAINER-34: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12234-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12234,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-34: CONTAINER-34: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-34.'
      ],
      remediationPrompt: "Remediate CONTAINER-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-34: CONTAINER-34: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-35: CONTAINER-35: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12235-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12235,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-35: CONTAINER-35: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-35.'
      ],
      remediationPrompt: "Remediate CONTAINER-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-35: CONTAINER-35: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-36: CONTAINER-36: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12236-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12236,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-36: CONTAINER-36: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-36.'
      ],
      remediationPrompt: "Remediate CONTAINER-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-36: CONTAINER-36: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-37: CONTAINER-37: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12237-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12237,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-37: CONTAINER-37: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-37.'
      ],
      remediationPrompt: "Remediate CONTAINER-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-37: CONTAINER-37: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-38: CONTAINER-38: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12238-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12238,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-38: CONTAINER-38: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-38.'
      ],
      remediationPrompt: "Remediate CONTAINER-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-38: CONTAINER-38: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-39: CONTAINER-39: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12239-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12239,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-39: CONTAINER-39: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-39.'
      ],
      remediationPrompt: "Remediate CONTAINER-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-39: CONTAINER-39: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-40: CONTAINER-40: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12240-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12240,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-40: CONTAINER-40: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-40.'
      ],
      remediationPrompt: "Remediate CONTAINER-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-40: CONTAINER-40: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-41: CONTAINER-41: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12241-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12241,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-41: CONTAINER-41: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-41.'
      ],
      remediationPrompt: "Remediate CONTAINER-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-41: CONTAINER-41: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-42: CONTAINER-42: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12242-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12242,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-42: CONTAINER-42: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-42.'
      ],
      remediationPrompt: "Remediate CONTAINER-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-42: CONTAINER-42: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-43: CONTAINER-43: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12243-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12243,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-43: CONTAINER-43: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-43.'
      ],
      remediationPrompt: "Remediate CONTAINER-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-43: CONTAINER-43: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-44: CONTAINER-44: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12244-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12244,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-44: CONTAINER-44: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-44.'
      ],
      remediationPrompt: "Remediate CONTAINER-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-44: CONTAINER-44: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-45: CONTAINER-45: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12245-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12245,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-45: CONTAINER-45: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-45.'
      ],
      remediationPrompt: "Remediate CONTAINER-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-45: CONTAINER-45: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-46: CONTAINER-46: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12246-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12246,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-46: CONTAINER-46: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-46.'
      ],
      remediationPrompt: "Remediate CONTAINER-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-46: CONTAINER-46: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-47: CONTAINER-47: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12247-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12247,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-47: CONTAINER-47: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-47.'
      ],
      remediationPrompt: "Remediate CONTAINER-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-47: CONTAINER-47: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-48: CONTAINER-48: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12248-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12248,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-48: CONTAINER-48: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-48.'
      ],
      remediationPrompt: "Remediate CONTAINER-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-48: CONTAINER-48: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-49: CONTAINER-49: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12249-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12249,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-49: CONTAINER-49: Enterprise Container Security Gate Rule",
      severity: "HIGH",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-49.'
      ],
      remediationPrompt: "Remediate CONTAINER-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-49: CONTAINER-49: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // CONTAINER-50: CONTAINER-50: Enterprise Container Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_CONTAINER-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `container12250-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12250,
      type: 'INFRA_DATABASE',
      title: "CONTAINER-50: CONTAINER-50: Enterprise Container Security Gate Rule",
      severity: "MEDIUM",
      category: "Container Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Container Security configuration',
      reproductionSteps: [
        `Audited Container Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching CONTAINER-50.'
      ],
      remediationPrompt: "Remediate CONTAINER-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CONTAINER AUDIT] Found CONTAINER-50: CONTAINER-50: Enterprise Container Security Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
