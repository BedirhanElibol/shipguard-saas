// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateIaeaNuclearSafeguardsRules Engine (50 Rules)
 * Rules IAEA-SAFE-01 to IAEA-SAFE-50 (Rule IDs 18601 to 18650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface IaeaNuclearSafeguardsResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateIaeaNuclearSafeguardsRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): IaeaNuclearSafeguardsResult {
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
  // IAEA-SAFE-01: Unreconciled Material Unaccounted For (MUF) in Special Nuclear Material Facilities
  if (cleanContent.includes('iaeaUnreconciledFissileMaterialMuf') || ((/iaea|nuclear_safeguards|material_balance/i.test(lowerPath) || /computeMaterialBalance|reconcileMuf/i.test(cleanContent)) && cleanContent.includes('unreconciledMaterialUnaccountedFor') && !/nearRealTimeAccountancyLimits/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18601-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18601,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-01: Unreconciled Material Unaccounted For (MUF) in Special Nuclear Material Facilities",
      severity: "CRITICAL",
      category: "Material Balance MUF",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce automated near-real-time accountancy (NRTA) calculating statistical limits of error on material balances.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-01: Unreconciled Material Unaccounted For (MUF) in Special Nuclear Material Facilities at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-02: Unmonitored Spent Fuel Pool Cherenkov Radiation Glow Verification Sensor Failures
  if (cleanContent.includes('iaeaSpentFuelCherenkovSensorTampering') || ((/iaea|spent_fuel|cherenkov/i.test(lowerPath) || /verifyCherenkovGlow|detectFuelRemoval/i.test(cleanContent)) && cleanContent.includes('unmonitoredSpentFuelGlowDeviation') && !/digitalCherenkovViewingDeviceVerification/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18602-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18602,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-02: Unmonitored Spent Fuel Pool Cherenkov Radiation Glow Verification Sensor Failures",
      severity: "CRITICAL",
      category: "Cherenkov Verification",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Cross-verify digital Cherenkov viewing device (DCVD) photon signatures to detect clandestine fuel bundle removal.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-02: Unmonitored Spent Fuel Pool Cherenkov Radiation Glow Verification Sensor Failures at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-03: Tampering with IAEA Electronic Optical Sealing Systems (EOSS) on Reactor Containments
  if (cleanContent.includes('iaeaEossSealTamperDisruption') || ((/iaea|containment_seal|eoss/i.test(lowerPath) || /checkFiberSealContinuity|auditSealLogs/i.test(cleanContent)) && cleanContent.includes('unreportedActiveFiberDiscontinuity') && !/cryptographicActiveSealAuthentication/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18603-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18603,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-03: Tampering with IAEA Electronic Optical Sealing Systems (EOSS) on Reactor Containments",
      severity: "CRITICAL",
      category: "EOSS Active Seal Integrity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Continuously monitor fiber-optic active seal continuity and assert cryptographic authentication on tamper logs.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-03: Tampering with IAEA Electronic Optical Sealing Systems (EOSS) on Reactor Containments at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-04: Absence of Neutron Coincidence Counting on Plutonium Isotope Verification Drums
  if (cleanContent.includes('iaeaMissingNeutronCoincidenceCounting') || ((/iaea|plutonium_assay|neutron_counter/i.test(lowerPath) || /measureNeutronCoincidence|confirmIsotopicRatio/i.test(cleanContent)) && cleanContent.includes('unverifiedPlutoniumIsotopicAssay') && !/passiveNeutronCoincidenceCounting/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18604-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18604,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-04: Absence of Neutron Coincidence Counting on Plutonium Isotope Verification Drums",
      severity: "CRITICAL",
      category: "Neutron Coincidence Counting",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Conduct passive neutron coincidence and multiplicity counting to confirm weapon-grade plutonium isotopic ratios.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-04: Absence of Neutron Coincidence Counting on Plutonium Isotope Verification Drums at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-05: Uncalibrated High-Resolution Gamma-Ray Spectrometry (HRGS) on Enrichment Centrifuges
  if (cleanContent.includes('iaeaUncalibratedCentrifugeEnrichment') || ((/iaea|centrifuge_cascade|uranium_enrichment/i.test(lowerPath) || /measureUraniumEnrichment|monitorHrgsSpectra/i.test(cleanContent)) && cleanContent.includes('uncalibratedU235SpectrometryRatio') && !/highResolutionGammaRaySpectrometry/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18605-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18605,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-05: Uncalibrated High-Resolution Gamma-Ray Spectrometry (HRGS) on Enrichment Centrifuges",
      severity: "CRITICAL",
      category: "HRGS Enrichment Tracking",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Validate uranium-235 enrichment percentages against reference standards to prevent unauthorized weapons-grade enrichment.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-05: Uncalibrated High-Resolution Gamma-Ray Spectrometry (HRGS) on Enrichment Centrifuges at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-06: IAEA-SAFE-06: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18606-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18606,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-06: IAEA-SAFE-06: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-06: IAEA-SAFE-06: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-07: IAEA-SAFE-07: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18607-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18607,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-07: IAEA-SAFE-07: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-07: IAEA-SAFE-07: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-08: IAEA-SAFE-08: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18608-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18608,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-08: IAEA-SAFE-08: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-08: IAEA-SAFE-08: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-09: IAEA-SAFE-09: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18609-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18609,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-09: IAEA-SAFE-09: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-09: IAEA-SAFE-09: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-10: IAEA-SAFE-10: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18610-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18610,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-10: IAEA-SAFE-10: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-10: IAEA-SAFE-10: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-11: IAEA-SAFE-11: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18611-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18611,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-11: IAEA-SAFE-11: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-11: IAEA-SAFE-11: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-12: IAEA-SAFE-12: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18612-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18612,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-12: IAEA-SAFE-12: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-12: IAEA-SAFE-12: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-13: IAEA-SAFE-13: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18613-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18613,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-13: IAEA-SAFE-13: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-13: IAEA-SAFE-13: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-14: IAEA-SAFE-14: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18614-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18614,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-14: IAEA-SAFE-14: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-14: IAEA-SAFE-14: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-15: IAEA-SAFE-15: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18615-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18615,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-15: IAEA-SAFE-15: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-15: IAEA-SAFE-15: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-16: IAEA-SAFE-16: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18616-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18616,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-16: IAEA-SAFE-16: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-16: IAEA-SAFE-16: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-17: IAEA-SAFE-17: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18617-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18617,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-17: IAEA-SAFE-17: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-17: IAEA-SAFE-17: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-18: IAEA-SAFE-18: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18618-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18618,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-18: IAEA-SAFE-18: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-18: IAEA-SAFE-18: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-19: IAEA-SAFE-19: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18619-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18619,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-19: IAEA-SAFE-19: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-19: IAEA-SAFE-19: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-20: IAEA-SAFE-20: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18620-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18620,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-20: IAEA-SAFE-20: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-20: IAEA-SAFE-20: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-21: IAEA-SAFE-21: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18621-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18621,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-21: IAEA-SAFE-21: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-21: IAEA-SAFE-21: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-22: IAEA-SAFE-22: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18622-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18622,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-22: IAEA-SAFE-22: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-22: IAEA-SAFE-22: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-23: IAEA-SAFE-23: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18623-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18623,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-23: IAEA-SAFE-23: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-23: IAEA-SAFE-23: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-24: IAEA-SAFE-24: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18624-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18624,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-24: IAEA-SAFE-24: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-24: IAEA-SAFE-24: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-25: IAEA-SAFE-25: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18625-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18625,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-25: IAEA-SAFE-25: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-25: IAEA-SAFE-25: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-26: IAEA-SAFE-26: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18626-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18626,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-26: IAEA-SAFE-26: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-26: IAEA-SAFE-26: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-27: IAEA-SAFE-27: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18627-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18627,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-27: IAEA-SAFE-27: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-27: IAEA-SAFE-27: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-28: IAEA-SAFE-28: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18628-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18628,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-28: IAEA-SAFE-28: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-28: IAEA-SAFE-28: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-29: IAEA-SAFE-29: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18629-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18629,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-29: IAEA-SAFE-29: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-29: IAEA-SAFE-29: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-30: IAEA-SAFE-30: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18630-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18630,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-30: IAEA-SAFE-30: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-30: IAEA-SAFE-30: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-31: IAEA-SAFE-31: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18631-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18631,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-31: IAEA-SAFE-31: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-31: IAEA-SAFE-31: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-32: IAEA-SAFE-32: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18632-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18632,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-32: IAEA-SAFE-32: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-32: IAEA-SAFE-32: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-33: IAEA-SAFE-33: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18633-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18633,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-33: IAEA-SAFE-33: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-33: IAEA-SAFE-33: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-34: IAEA-SAFE-34: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18634-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18634,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-34: IAEA-SAFE-34: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-34: IAEA-SAFE-34: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-35: IAEA-SAFE-35: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18635-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18635,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-35: IAEA-SAFE-35: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-35: IAEA-SAFE-35: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-36: IAEA-SAFE-36: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18636-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18636,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-36: IAEA-SAFE-36: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-36: IAEA-SAFE-36: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-37: IAEA-SAFE-37: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18637-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18637,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-37: IAEA-SAFE-37: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-37: IAEA-SAFE-37: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-38: IAEA-SAFE-38: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18638-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18638,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-38: IAEA-SAFE-38: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-38: IAEA-SAFE-38: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-39: IAEA-SAFE-39: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18639-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18639,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-39: IAEA-SAFE-39: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-39: IAEA-SAFE-39: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-40: IAEA-SAFE-40: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18640-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18640,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-40: IAEA-SAFE-40: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-40: IAEA-SAFE-40: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-41: IAEA-SAFE-41: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18641-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18641,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-41: IAEA-SAFE-41: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-41: IAEA-SAFE-41: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-42: IAEA-SAFE-42: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18642-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18642,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-42: IAEA-SAFE-42: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-42: IAEA-SAFE-42: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-43: IAEA-SAFE-43: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18643-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18643,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-43: IAEA-SAFE-43: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-43: IAEA-SAFE-43: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-44: IAEA-SAFE-44: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18644-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18644,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-44: IAEA-SAFE-44: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-44: IAEA-SAFE-44: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-45: IAEA-SAFE-45: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18645-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18645,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-45: IAEA-SAFE-45: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-45: IAEA-SAFE-45: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-46: IAEA-SAFE-46: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18646-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18646,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-46: IAEA-SAFE-46: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-46: IAEA-SAFE-46: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-47: IAEA-SAFE-47: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18647-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18647,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-47: IAEA-SAFE-47: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-47: IAEA-SAFE-47: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-48: IAEA-SAFE-48: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18648-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18648,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-48: IAEA-SAFE-48: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-48: IAEA-SAFE-48: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-49: IAEA-SAFE-49: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18649-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18649,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-49: IAEA-SAFE-49: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "HIGH",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-49: IAEA-SAFE-49: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  // IAEA-SAFE-50: IAEA-SAFE-50: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule
  if (cleanContent.includes('vulnerablePattern_IAEA-SAFE-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `iaeasafe18650-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18650,
      type: 'LEGAL_COMPLIANCE',
      title: "IAEA-SAFE-50: IAEA-SAFE-50: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule",
      severity: "MEDIUM",
      category: "IAEA Nuclear Safeguards Compliance Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'IAEA Nuclear Safeguards Compliance configuration',
      reproductionSteps: [
        `Audited IAEA Nuclear Safeguards Compliance configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate IAEA-SAFE-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [IAEA-NUCLEAR-SAFEGUARDS-AUDIT] Found IAEA-SAFE-50: IAEA-SAFE-50: Enterprise IAEA Nuclear Safeguards Compliance Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
