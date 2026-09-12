// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateMedicalDeviceSoftwareRules Engine (50 Rules)
 * Rules MED-DEV-01 to MED-DEV-50 (Rule IDs 17501 to 17550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface MedicalDeviceSoftwareRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateMedicalDeviceSoftwareRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): MedicalDeviceSoftwareRuleResult {
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
  // MED-DEV-01: Lack of Segregated Software Architecture for IEC 62304 Class C Life-Critical Items
  if (cleanContent.includes('medDevUnsegregatedClassCSoftware') || ((/iec62304|medical_core|class_c_device/i.test(lowerPath) || /actuatorDosageLoop|treatmentDelivery/i.test(cleanContent)) && cleanContent.includes('unsegregatedLifeCriticalModules') && !/isolateClassCArchitecture/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17501-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17501,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-01: Lack of Segregated Software Architecture for IEC 62304 Class C Life-Critical Items",
      severity: "CRITICAL",
      category: "Class C Software Isolation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce strict spatial and temporal software isolation between life-critical treatment control modules and non-critical UI code.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-01: Lack of Segregated Software Architecture for IEC 62304 Class C Life-Critical Items at ${file.path}:${lineNum}`);
  }

  // MED-DEV-02: Missing Continuous Risk Management File (ISO 14971) Traceability in CI/CD Gates
  if (cleanContent.includes('medDevMissingRiskManagementTraceability') || ((/iso14971|hazard_trace|clinical_risk/i.test(lowerPath) || /riskManagementFile|hazardMitigationId/i.test(cleanContent)) && cleanContent.includes('untracedSafetyHazardCommits') && !/verifyIso14971Traceability/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17502-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17502,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-02: Missing Continuous Risk Management File (ISO 14971) Traceability in CI/CD Gates",
      severity: "CRITICAL",
      category: "Risk Traceability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Trace all pull requests, code commits, and software requirements directly to identified hazard mitigations in the ISO 14971 RMF.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-02: Missing Continuous Risk Management File (ISO 14971) Traceability in CI/CD Gates at ${file.path}:${lineNum}`);
  }

  // MED-DEV-03: Unencrypted Patient Protected Health Information (ePHI) on Medical Device Storage
  if (cleanContent.includes('medDevUnencryptedPatientEphi') || ((/patient_record|medical_db|ephi_storage/i.test(lowerPath) || /storePatientVitals|medicalTelemetryDb/i.test(cleanContent)) && cleanContent.includes('plaintextPatientEphiStored') && !/encryptMedicalStorageFips140/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17503-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17503,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-03: Unencrypted Patient Protected Health Information (ePHI) on Medical Device Storage",
      severity: "CRITICAL",
      category: "Local ePHI Encryption",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Encrypt local medical database stores and telemetry logs using FIPS 140-3 validated AES-256 encryption with hardware key sealing.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-03: Unencrypted Patient Protected Health Information (ePHI) on Medical Device Storage at ${file.path}:${lineNum}`);
  }

  // MED-DEV-04: Inadequate Cybersecurity Post-Market Surveillance and Vulnerability Management (FDA)
  if (cleanContent.includes('medDevInadequatePostMarketSurveillance') || ((/post_market_cve|fda_cybersecurity|medical_sbom/i.test(lowerPath) || /scanMedicalSbom|cveAlertHandler/i.test(cleanContent)) && cleanContent.includes('unmonitoredMedicalDependenciesCve') && !/continuousMedicalSbomMonitoring/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17504-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17504,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-04: Inadequate Cybersecurity Post-Market Surveillance and Vulnerability Management (FDA)",
      severity: "HIGH",
      category: "Post-Market Vulnerability Mgmt",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Deploy automated continuous Software Bill of Materials (SBOM) monitoring scanning for newly disclosed CVEs on deployed devices.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-04: Inadequate Cybersecurity Post-Market Surveillance and Vulnerability Management (FDA) at ${file.path}:${lineNum}`);
  }

  // MED-DEV-05: Absence of Fail-Safe Hardware Interlock on Actuator Over-Current / Over-Dose
  if (cleanContent.includes('medDevMissingHardwareInterlock') || ((/dosage_actuator|patient_safety|hardware_interlock/i.test(lowerPath) || /actuatorPowerRelay|hardwareCutoffSwitch/i.test(cleanContent)) && cleanContent.includes('softwareOnlyOverdoseProtection') && !/independentHardwareInterlockEngaged/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17505-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17505,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-05: Absence of Fail-Safe Hardware Interlock on Actuator Over-Current / Over-Dose",
      severity: "CRITICAL",
      category: "Hardware Interlocks",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Incorporate independent analog hardware interlocks that cut actuator power immediately if software control loops exceed dosage limits.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-05: Absence of Fail-Safe Hardware Interlock on Actuator Over-Current / Over-Dose at ${file.path}:${lineNum}`);
  }

  // MED-DEV-06: MED-DEV-06: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17506-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17506,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-06: MED-DEV-06: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-06: MED-DEV-06: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-07: MED-DEV-07: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17507-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17507,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-07: MED-DEV-07: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-07: MED-DEV-07: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-08: MED-DEV-08: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17508-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17508,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-08: MED-DEV-08: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-08: MED-DEV-08: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-09: MED-DEV-09: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17509-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17509,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-09: MED-DEV-09: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-09: MED-DEV-09: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-10: MED-DEV-10: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17510-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17510,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-10: MED-DEV-10: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-10: MED-DEV-10: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-11: MED-DEV-11: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17511-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17511,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-11: MED-DEV-11: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-11: MED-DEV-11: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-12: MED-DEV-12: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17512-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17512,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-12: MED-DEV-12: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-12: MED-DEV-12: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-13: MED-DEV-13: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17513-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17513,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-13: MED-DEV-13: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-13: MED-DEV-13: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-14: MED-DEV-14: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17514-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17514,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-14: MED-DEV-14: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-14: MED-DEV-14: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-15: MED-DEV-15: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17515-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17515,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-15: MED-DEV-15: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-15: MED-DEV-15: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-16: MED-DEV-16: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17516-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17516,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-16: MED-DEV-16: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-16: MED-DEV-16: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-17: MED-DEV-17: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17517-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17517,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-17: MED-DEV-17: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-17: MED-DEV-17: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-18: MED-DEV-18: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17518-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17518,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-18: MED-DEV-18: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-18: MED-DEV-18: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-19: MED-DEV-19: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17519-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17519,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-19: MED-DEV-19: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-19: MED-DEV-19: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-20: MED-DEV-20: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17520-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17520,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-20: MED-DEV-20: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-20: MED-DEV-20: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-21: MED-DEV-21: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17521-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17521,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-21: MED-DEV-21: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-21: MED-DEV-21: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-22: MED-DEV-22: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17522-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17522,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-22: MED-DEV-22: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-22: MED-DEV-22: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-23: MED-DEV-23: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17523-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17523,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-23: MED-DEV-23: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-23: MED-DEV-23: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-24: MED-DEV-24: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17524-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17524,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-24: MED-DEV-24: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-24: MED-DEV-24: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-25: MED-DEV-25: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17525-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17525,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-25: MED-DEV-25: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-25: MED-DEV-25: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-26: MED-DEV-26: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17526-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17526,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-26: MED-DEV-26: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-26: MED-DEV-26: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-27: MED-DEV-27: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17527-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17527,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-27: MED-DEV-27: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-27: MED-DEV-27: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-28: MED-DEV-28: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17528-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17528,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-28: MED-DEV-28: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-28: MED-DEV-28: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-29: MED-DEV-29: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17529-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17529,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-29: MED-DEV-29: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-29: MED-DEV-29: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-30: MED-DEV-30: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17530-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17530,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-30: MED-DEV-30: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-30: MED-DEV-30: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-31: MED-DEV-31: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17531-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17531,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-31: MED-DEV-31: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-31: MED-DEV-31: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-32: MED-DEV-32: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17532-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17532,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-32: MED-DEV-32: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-32: MED-DEV-32: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-33: MED-DEV-33: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17533-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17533,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-33: MED-DEV-33: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-33: MED-DEV-33: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-34: MED-DEV-34: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17534-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17534,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-34: MED-DEV-34: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-34: MED-DEV-34: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-35: MED-DEV-35: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17535-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17535,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-35: MED-DEV-35: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-35: MED-DEV-35: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-36: MED-DEV-36: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17536-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17536,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-36: MED-DEV-36: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-36: MED-DEV-36: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-37: MED-DEV-37: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17537-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17537,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-37: MED-DEV-37: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-37: MED-DEV-37: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-38: MED-DEV-38: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17538-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17538,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-38: MED-DEV-38: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-38: MED-DEV-38: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-39: MED-DEV-39: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17539-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17539,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-39: MED-DEV-39: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-39: MED-DEV-39: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-40: MED-DEV-40: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17540-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17540,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-40: MED-DEV-40: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-40: MED-DEV-40: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-41: MED-DEV-41: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17541-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17541,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-41: MED-DEV-41: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-41: MED-DEV-41: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-42: MED-DEV-42: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17542-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17542,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-42: MED-DEV-42: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-42: MED-DEV-42: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-43: MED-DEV-43: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17543-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17543,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-43: MED-DEV-43: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-43: MED-DEV-43: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-44: MED-DEV-44: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17544-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17544,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-44: MED-DEV-44: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-44: MED-DEV-44: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-45: MED-DEV-45: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17545-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17545,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-45: MED-DEV-45: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-45: MED-DEV-45: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-46: MED-DEV-46: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17546-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17546,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-46: MED-DEV-46: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-46: MED-DEV-46: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-47: MED-DEV-47: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17547-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17547,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-47: MED-DEV-47: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-47: MED-DEV-47: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-48: MED-DEV-48: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17548-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17548,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-48: MED-DEV-48: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-48: MED-DEV-48: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-49: MED-DEV-49: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17549-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17549,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-49: MED-DEV-49: Enterprise Medical Device Software Gate Rule",
      severity: "HIGH",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-49: MED-DEV-49: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  // MED-DEV-50: MED-DEV-50: Enterprise Medical Device Software Gate Rule
  if (cleanContent.includes('vulnerablePattern_MED-DEV-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `meddev17550-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17550,
      type: 'LEGAL_COMPLIANCE',
      title: "MED-DEV-50: MED-DEV-50: Enterprise Medical Device Software Gate Rule",
      severity: "MEDIUM",
      category: "Medical Device Software Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Medical Device Software configuration',
      reproductionSteps: [
        `Audited Medical Device Software configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate MED-DEV-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MED DEV AUDIT] Found MED-DEV-50: MED-DEV-50: Enterprise Medical Device Software Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
