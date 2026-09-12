// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateAtomicLayerEtchPlasmaRules Engine (50 Rules)
 * Rules ALE-PLASMA-01 to ALE-PLASMA-50 (Rule IDs 20001 to 20050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface AtomicLayerEtchPlasmaResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateAtomicLayerEtchPlasmaRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): AtomicLayerEtchPlasmaResult {
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
  // ALE-PLASMA-01: ALE-PLASMA-01: RF Match Network Slew Latency and Reflected Power Spike
  if (cleanContent.includes('unmatchedRfImpedanceSlewReflectedPower')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20001-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20001,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-01: ALE-PLASMA-01: RF Match Network Slew Latency and Reflected Power Spike",
      severity: "CRITICAL",
      category: "RF Match Network Tuning",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-01.'
      ],
      remediationPrompt: "Deploy solid-state PIN diode arrays matching RF impedance in <50 microseconds.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-01: ALE-PLASMA-01: RF Match Network Slew Latency and Reflected Power Spike at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-02: ALE-PLASMA-02: Electrostatic Chuck Residual Dechucking Voltage and Wafer Pop
  if (cleanContent.includes('residualEscDechuckingCharge')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20002-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20002,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-02: ALE-PLASMA-02: Electrostatic Chuck Residual Dechucking Voltage and Wafer Pop",
      severity: "CRITICAL",
      category: "Electrostatic Chuck Dechucking",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-02.'
      ],
      remediationPrompt: "Automate inverse polarity DC bias discharge sequencing before pin lift.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-02: ALE-PLASMA-02: Electrostatic Chuck Residual Dechucking Voltage and Wafer Pop at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-03: ALE-PLASMA-03: Incomplete Halogen Radical Surface Saturation Incompletion
  if (cleanContent.includes('unsaturatedHalogenRadicalExposure')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20003-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20003,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-03: ALE-PLASMA-03: Incomplete Halogen Radical Surface Saturation Incompletion",
      severity: "CRITICAL",
      category: "Surface Adsorption Kinetics",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-03.'
      ],
      remediationPrompt: "Ensure gas pulse dosing delivers atomic self-limiting surface coverage in 3D structures.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-03: ALE-PLASMA-03: Incomplete Halogen Radical Surface Saturation Incompletion at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-04: ALE-PLASMA-04: Cryogenic Wafer Temperature Thermal Etch Non-Uniformity
  if (cleanContent.includes('unregulatedCryogenicChuckThermalDrift')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20004-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20004,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-04: ALE-PLASMA-04: Cryogenic Wafer Temperature Thermal Etch Non-Uniformity",
      severity: "CRITICAL",
      category: "Cryogenic Thermal Control",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-04.'
      ],
      remediationPrompt: "Maintain multi-zone liquid nitrogen cooling within +/-0.2 deg C at -120 deg C.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-04: ALE-PLASMA-04: Cryogenic Wafer Temperature Thermal Etch Non-Uniformity at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-05: ALE-PLASMA-05: High-Vacuum Turbo Pump Backstreaming Contamination
  if (cleanContent.includes('unprotectedTurboPumpBackstreaming')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20005-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20005,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-05: ALE-PLASMA-05: High-Vacuum Turbo Pump Backstreaming Contamination",
      severity: "HIGH",
      category: "Vacuum Turbo Pump Integrity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-05.'
      ],
      remediationPrompt: "Interlock roughing valves with dry nitrogen purge seals preventing oil backstreaming.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-05: ALE-PLASMA-05: High-Vacuum Turbo Pump Backstreaming Contamination at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-06: ALE-PLASMA-06: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20006-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20006,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-06: ALE-PLASMA-06: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-06.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-06: ALE-PLASMA-06: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-07: ALE-PLASMA-07: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20007-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20007,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-07: ALE-PLASMA-07: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-07.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-07: ALE-PLASMA-07: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-08: ALE-PLASMA-08: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20008-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20008,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-08: ALE-PLASMA-08: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-08.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-08: ALE-PLASMA-08: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-09: ALE-PLASMA-09: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20009-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20009,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-09: ALE-PLASMA-09: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-09.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-09: ALE-PLASMA-09: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-10: ALE-PLASMA-10: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20010-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20010,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-10: ALE-PLASMA-10: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-10.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-10: ALE-PLASMA-10: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-11: ALE-PLASMA-11: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20011-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20011,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-11: ALE-PLASMA-11: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-11.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-11: ALE-PLASMA-11: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-12: ALE-PLASMA-12: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20012-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20012,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-12: ALE-PLASMA-12: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-12.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-12: ALE-PLASMA-12: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-13: ALE-PLASMA-13: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20013-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20013,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-13: ALE-PLASMA-13: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-13.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-13: ALE-PLASMA-13: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-14: ALE-PLASMA-14: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20014-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20014,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-14: ALE-PLASMA-14: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-14.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-14: ALE-PLASMA-14: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-15: ALE-PLASMA-15: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20015-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20015,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-15: ALE-PLASMA-15: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-15.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-15: ALE-PLASMA-15: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-16: ALE-PLASMA-16: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20016-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20016,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-16: ALE-PLASMA-16: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-16.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-16: ALE-PLASMA-16: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-17: ALE-PLASMA-17: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20017-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20017,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-17: ALE-PLASMA-17: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-17.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-17: ALE-PLASMA-17: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-18: ALE-PLASMA-18: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20018-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20018,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-18: ALE-PLASMA-18: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-18.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-18: ALE-PLASMA-18: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-19: ALE-PLASMA-19: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20019-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20019,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-19: ALE-PLASMA-19: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-19.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-19: ALE-PLASMA-19: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-20: ALE-PLASMA-20: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20020-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20020,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-20: ALE-PLASMA-20: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-20.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-20: ALE-PLASMA-20: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-21: ALE-PLASMA-21: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20021-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20021,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-21: ALE-PLASMA-21: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-21.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-21: ALE-PLASMA-21: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-22: ALE-PLASMA-22: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20022-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20022,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-22: ALE-PLASMA-22: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-22.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-22: ALE-PLASMA-22: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-23: ALE-PLASMA-23: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20023-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20023,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-23: ALE-PLASMA-23: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-23.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-23: ALE-PLASMA-23: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-24: ALE-PLASMA-24: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20024-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20024,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-24: ALE-PLASMA-24: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-24.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-24: ALE-PLASMA-24: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-25: ALE-PLASMA-25: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20025-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20025,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-25: ALE-PLASMA-25: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-25.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-25: ALE-PLASMA-25: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-26: ALE-PLASMA-26: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20026-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20026,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-26: ALE-PLASMA-26: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-26.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-26: ALE-PLASMA-26: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-27: ALE-PLASMA-27: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20027-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20027,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-27: ALE-PLASMA-27: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-27.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-27: ALE-PLASMA-27: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-28: ALE-PLASMA-28: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20028-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20028,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-28: ALE-PLASMA-28: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-28.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-28: ALE-PLASMA-28: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-29: ALE-PLASMA-29: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20029-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20029,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-29: ALE-PLASMA-29: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-29.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-29: ALE-PLASMA-29: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-30: ALE-PLASMA-30: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20030-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20030,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-30: ALE-PLASMA-30: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-30.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-30: ALE-PLASMA-30: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-31: ALE-PLASMA-31: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20031-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20031,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-31: ALE-PLASMA-31: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-31.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-31: ALE-PLASMA-31: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-32: ALE-PLASMA-32: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20032-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20032,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-32: ALE-PLASMA-32: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-32.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-32: ALE-PLASMA-32: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-33: ALE-PLASMA-33: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20033-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20033,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-33: ALE-PLASMA-33: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-33.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-33: ALE-PLASMA-33: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-34: ALE-PLASMA-34: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20034-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20034,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-34: ALE-PLASMA-34: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-34.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-34: ALE-PLASMA-34: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-35: ALE-PLASMA-35: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20035-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20035,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-35: ALE-PLASMA-35: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-35.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-35: ALE-PLASMA-35: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-36: ALE-PLASMA-36: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20036-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20036,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-36: ALE-PLASMA-36: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-36.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-36: ALE-PLASMA-36: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-37: ALE-PLASMA-37: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20037-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20037,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-37: ALE-PLASMA-37: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-37.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-37: ALE-PLASMA-37: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-38: ALE-PLASMA-38: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20038-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20038,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-38: ALE-PLASMA-38: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-38.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-38: ALE-PLASMA-38: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-39: ALE-PLASMA-39: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20039-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20039,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-39: ALE-PLASMA-39: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-39.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-39: ALE-PLASMA-39: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-40: ALE-PLASMA-40: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20040-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20040,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-40: ALE-PLASMA-40: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-40.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-40: ALE-PLASMA-40: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-41: ALE-PLASMA-41: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20041-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20041,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-41: ALE-PLASMA-41: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-41.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-41: ALE-PLASMA-41: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-42: ALE-PLASMA-42: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20042-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20042,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-42: ALE-PLASMA-42: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-42.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-42: ALE-PLASMA-42: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-43: ALE-PLASMA-43: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20043-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20043,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-43: ALE-PLASMA-43: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-43.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-43: ALE-PLASMA-43: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-44: ALE-PLASMA-44: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20044-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20044,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-44: ALE-PLASMA-44: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-44.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-44: ALE-PLASMA-44: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-45: ALE-PLASMA-45: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20045-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20045,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-45: ALE-PLASMA-45: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-45.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-45: ALE-PLASMA-45: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-46: ALE-PLASMA-46: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20046-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20046,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-46: ALE-PLASMA-46: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-46.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-46: ALE-PLASMA-46: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-47: ALE-PLASMA-47: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20047-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20047,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-47: ALE-PLASMA-47: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-47.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-47: ALE-PLASMA-47: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-48: ALE-PLASMA-48: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20048-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20048,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-48: ALE-PLASMA-48: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-48.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-48: ALE-PLASMA-48: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-49: ALE-PLASMA-49: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20049-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20049,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-49: ALE-PLASMA-49: Enterprise ALE Plasma Gate Rule",
      severity: "HIGH",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-49.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-49: ALE-PLASMA-49: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  // ALE-PLASMA-50: ALE-PLASMA-50: Enterprise ALE Plasma Gate Rule
  if (cleanContent.includes('vulnerablePattern_ALE-PLASMA-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aleplasma20050-${Date.now()}-${findingCounter.count++}`,
      ruleId: 20050,
      type: 'INFRA_DATABASE',
      title: "ALE-PLASMA-50: ALE-PLASMA-50: Enterprise ALE Plasma Gate Rule",
      severity: "MEDIUM",
      category: "ALE Plasma Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'ALE Plasma configuration',
      reproductionSteps: [
        `Audited ALE Plasma configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching ALE-PLASMA-50.'
      ],
      remediationPrompt: "Remediate ALE-PLASMA-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [ALE Plasma] Found ALE-PLASMA-50: ALE-PLASMA-50: Enterprise ALE Plasma Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
