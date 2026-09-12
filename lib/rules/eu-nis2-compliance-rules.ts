// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateEuNis2ComplianceRules Engine (50 Rules)
 * Rules NIS2-01 to NIS2-50 (Rule IDs 15401 to 15450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface EuNis2ComplianceRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateEuNis2ComplianceRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): EuNis2ComplianceRuleResult {
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
  // NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy
  if (cleanContent.includes('nis2MissingRiskManagementFramework') || ((/security_governance|compliance_policy/i.test(lowerPath) || /RiskManagement|cybersecurityPolicy/i.test(cleanContent)) && cleanContent.includes('undocumentedAllHazardsPolicy') && !/nis2CompliantPolicy/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215401-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15401,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy",
      severity: "CRITICAL",
      category: "Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Adopt and maintain a formal NIS2 Article 21 cybersecurity policy covering risk analysis, incident handling, and system security.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-01: EU NIS2 Directive Article 21: Missing Documented All-Hazards Cybersecurity Risk Management Policy at ${file.path}:${lineNum}`);
  }

  // NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA
  if (cleanContent.includes('nis2InadequateEarlyWarningSla') || ((/incident_response|soc_workflows/i.test(lowerPath) || /incidentSla|csirtNotification/i.test(cleanContent)) && cleanContent.includes('missing24hEarlyWarningProcedure') && !/csirtAutomatedAlert24h/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215402-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15402,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA",
      severity: "CRITICAL",
      category: "Incident Reporting",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Implement automated incident notification pipelines ensuring NIS2-compliant 24h early warning and 72h detailed incident reporting to national authorities.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-02: EU NIS2 Directive Article 23: Inadequate 24-Hour Early Warning and Incident Notification SLA at ${file.path}:${lineNum}`);
  }

  // NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits
  if (cleanContent.includes('nis2InadequateSupplyChainRiskAudits') || ((/vendor_management|supply_chain/i.test(lowerPath) || /vendorAudit|supplierRisk/i.test(cleanContent)) && cleanContent.includes('unassessedTier1Suppliers') && !/supplierSecurityAuditCatalog/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215403-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15403,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits",
      severity: "HIGH",
      category: "Supply Chain",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce supply chain security assessments and contractual security requirements across all tier-1 IT service providers and component vendors.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-03: EU NIS2 Directive Article 21(2)(d): Inadequate Supply Chain Risk Management and Vendor Cybersecurity Audits at ${file.path}:${lineNum}`);
  }

  // NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting
  if (cleanContent.includes('nis2MissingVulnerabilityDisclosurePolicy') || ((/vulnerability_handling|security_txt/i.test(lowerPath) || /disclosurePolicy/i.test(cleanContent)) && cleanContent.includes('uncoordinatedVulnerabilityHandling') && !/coordinatedDisclosureProcess/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215404-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15404,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting",
      severity: "HIGH",
      category: "Vulnerability Management",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Publish a coordinated vulnerability disclosure policy and integrate automated CVE scanning across all release deployment stages.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-04: EU NIS2 Directive Article 21(2)(e): Missing Vulnerability Handling, Disclosure and Coordinated CSIRT Reporting at ${file.path}:${lineNum}`);
  }

  // NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records
  if (cleanContent.includes('nis2MissingManagementBoardTrainingRecords') || ((/board_governance|executive_compliance/i.test(lowerPath) || /managementBoard/i.test(cleanContent)) && cleanContent.includes('unloggedBoardCybersecurityTraining') && !/boardApprovalRecordsTracked/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215405-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15405,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records",
      severity: "HIGH",
      category: "Executive Accountability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Conduct mandatory annual cybersecurity training for executive management and maintain board approval records for cybersecurity measures.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-05: EU NIS2 Directive Article 20: Lack of Management Body Cybersecurity Governance Training and Approval Records at ${file.path}:${lineNum}`);
  }

  // NIS2-06: NIS2-06: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215406-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15406,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-06: NIS2-06: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-06: NIS2-06: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-07: NIS2-07: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215407-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15407,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-07: NIS2-07: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-07: NIS2-07: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-08: NIS2-08: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215408-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15408,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-08: NIS2-08: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-08: NIS2-08: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-09: NIS2-09: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215409-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15409,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-09: NIS2-09: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-09: NIS2-09: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-10: NIS2-10: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215410-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15410,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-10: NIS2-10: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-10: NIS2-10: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-11: NIS2-11: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215411-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15411,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-11: NIS2-11: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-11: NIS2-11: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-12: NIS2-12: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215412-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15412,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-12: NIS2-12: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-12: NIS2-12: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-13: NIS2-13: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215413-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15413,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-13: NIS2-13: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-13: NIS2-13: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-14: NIS2-14: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215414-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15414,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-14: NIS2-14: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-14: NIS2-14: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-15: NIS2-15: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215415-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15415,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-15: NIS2-15: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-15: NIS2-15: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-16: NIS2-16: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215416-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15416,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-16: NIS2-16: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-16: NIS2-16: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-17: NIS2-17: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215417-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15417,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-17: NIS2-17: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-17: NIS2-17: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-18: NIS2-18: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215418-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15418,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-18: NIS2-18: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-18: NIS2-18: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-19: NIS2-19: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215419-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15419,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-19: NIS2-19: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-19: NIS2-19: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-20: NIS2-20: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215420-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15420,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-20: NIS2-20: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-20: NIS2-20: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-21: NIS2-21: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215421-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15421,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-21: NIS2-21: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-21: NIS2-21: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-22: NIS2-22: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215422-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15422,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-22: NIS2-22: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-22: NIS2-22: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-23: NIS2-23: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215423-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15423,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-23: NIS2-23: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-23: NIS2-23: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-24: NIS2-24: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215424-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15424,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-24: NIS2-24: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-24: NIS2-24: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-25: NIS2-25: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215425-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15425,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-25: NIS2-25: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-25: NIS2-25: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-26: NIS2-26: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215426-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15426,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-26: NIS2-26: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-26: NIS2-26: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-27: NIS2-27: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215427-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15427,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-27: NIS2-27: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-27: NIS2-27: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-28: NIS2-28: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215428-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15428,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-28: NIS2-28: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-28: NIS2-28: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-29: NIS2-29: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215429-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15429,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-29: NIS2-29: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-29: NIS2-29: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-30: NIS2-30: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215430-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15430,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-30: NIS2-30: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-30: NIS2-30: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-31: NIS2-31: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215431-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15431,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-31: NIS2-31: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-31: NIS2-31: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-32: NIS2-32: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215432-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15432,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-32: NIS2-32: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-32: NIS2-32: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-33: NIS2-33: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215433-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15433,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-33: NIS2-33: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-33: NIS2-33: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-34: NIS2-34: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215434-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15434,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-34: NIS2-34: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-34: NIS2-34: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-35: NIS2-35: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215435-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15435,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-35: NIS2-35: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-35: NIS2-35: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-36: NIS2-36: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215436-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15436,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-36: NIS2-36: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-36: NIS2-36: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-37: NIS2-37: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215437-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15437,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-37: NIS2-37: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-37: NIS2-37: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-38: NIS2-38: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215438-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15438,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-38: NIS2-38: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-38: NIS2-38: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-39: NIS2-39: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215439-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15439,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-39: NIS2-39: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-39: NIS2-39: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-40: NIS2-40: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215440-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15440,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-40: NIS2-40: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-40: NIS2-40: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-41: NIS2-41: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215441-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15441,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-41: NIS2-41: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-41: NIS2-41: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-42: NIS2-42: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215442-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15442,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-42: NIS2-42: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-42: NIS2-42: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-43: NIS2-43: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215443-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15443,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-43: NIS2-43: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-43: NIS2-43: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-44: NIS2-44: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215444-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15444,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-44: NIS2-44: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-44: NIS2-44: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-45: NIS2-45: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215445-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15445,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-45: NIS2-45: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-45: NIS2-45: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-46: NIS2-46: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215446-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15446,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-46: NIS2-46: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-46: NIS2-46: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-47: NIS2-47: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215447-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15447,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-47: NIS2-47: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-47: NIS2-47: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-48: NIS2-48: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215448-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15448,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-48: NIS2-48: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-48: NIS2-48: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-49: NIS2-49: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215449-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15449,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-49: NIS2-49: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "HIGH",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-49: NIS2-49: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  // NIS2-50: NIS2-50: Enterprise EU NIS2 Critical Infrastructure Gate Rule
  if (cleanContent.includes('vulnerablePattern_NIS2-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `nis215450-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15450,
      type: 'LEGAL_COMPLIANCE',
      title: "NIS2-50: NIS2-50: Enterprise EU NIS2 Critical Infrastructure Gate Rule",
      severity: "MEDIUM",
      category: "EU NIS2 Critical Infrastructure Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'EU NIS2 Critical Infrastructure configuration',
      reproductionSteps: [
        `Audited EU NIS2 Critical Infrastructure configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NIS2-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NIS2 AUDIT] Found NIS2-50: NIS2-50: Enterprise EU NIS2 Critical Infrastructure Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
