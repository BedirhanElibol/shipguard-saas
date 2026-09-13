// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateAeroTrajectory4dConflictRules Engine (50 Rules)
 * Rules AERO-TRAJECT-01 to AERO-TRAJECT-50 (Rule IDs 21801 to 21850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface AeroTrajectory4dConflictResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateAeroTrajectory4dConflictRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): AeroTrajectory4dConflictResult {
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
  // AERO-TRAJECT-01: AERO-TRAJECT-01: 4D Trajectory Conflict Detection Lookahead Horizon Insufficient
  if (cleanContent.includes('insufficientLookaheadConflictHorizon')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21801-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21801,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-01: AERO-TRAJECT-01: 4D Trajectory Conflict Detection Lookahead Horizon Insufficient",
      severity: "CRITICAL",
      category: "4D Conflict Prediction",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce minimum 20-minute 4D trajectory lookahead horizon with spatial conflict bounding boxes.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-01: AERO-TRAJECT-01: 4D Trajectory Conflict Detection Lookahead Horizon Insufficient at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-02: AERO-TRAJECT-02: Dynamic Wake Turbulence Category Separation Matrix Unvalidated
  if (cleanContent.includes('unvalidatedWakeTurbulenceSeparation')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21802-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21802,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-02: AERO-TRAJECT-02: Dynamic Wake Turbulence Category Separation Matrix Unvalidated",
      severity: "CRITICAL",
      category: "Wake Separation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Mandate wake vortex decay tracking integrating real-time LiDAR eddy dissipation telemetry.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-02: AERO-TRAJECT-02: Dynamic Wake Turbulence Category Separation Matrix Unvalidated at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-03: AERO-TRAJECT-03: ADS-B Broadcast Position Spoofing Verification Absent
  if (cleanContent.includes('unverifiedAdsbPositionSpoofing')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21803-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21803,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-03: AERO-TRAJECT-03: ADS-B Broadcast Position Spoofing Verification Absent",
      severity: "CRITICAL",
      category: "ADS-B Spoofing Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Cross-verify ADS-B GPS position with multilateration Time Difference of Arrival (TDoA).",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-03: AERO-TRAJECT-03: ADS-B Broadcast Position Spoofing Verification Absent at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-04: AERO-TRAJECT-04: Required Navigation Performance RNP-0.1 Containment Area Breach
  if (cleanContent.includes('breachedRnpContainmentBoundary')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21804-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21804,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-04: AERO-TRAJECT-04: Required Navigation Performance RNP-0.1 Containment Area Breach",
      severity: "HIGH",
      category: "RNP Containment",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Trigger immediate tactical breakout alerts when total system error exceeds 1x RNP navigation corridor.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-04: AERO-TRAJECT-04: Required Navigation Performance RNP-0.1 Containment Area Breach at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-05: AERO-TRAJECT-05: Air Traffic Control Automated Sector Handoff Synchronization Drift
  if (cleanContent.includes('outOfSyncSectorHandoffProtocol')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21805-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21805,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-05: AERO-TRAJECT-05: Air Traffic Control Automated Sector Handoff Synchronization Drift",
      severity: "HIGH",
      category: "Automated Handoff",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Verify bilateral cryptographic handshake and trajectory intention acknowledgment between adjacent sectors.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-05: AERO-TRAJECT-05: Air Traffic Control Automated Sector Handoff Synchronization Drift at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-06: AERO-TRAJECT-06: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21806-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21806,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-06: AERO-TRAJECT-06: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-06: AERO-TRAJECT-06: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-07: AERO-TRAJECT-07: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21807-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21807,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-07: AERO-TRAJECT-07: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-07: AERO-TRAJECT-07: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-08: AERO-TRAJECT-08: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21808-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21808,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-08: AERO-TRAJECT-08: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-08: AERO-TRAJECT-08: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-09: AERO-TRAJECT-09: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21809-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21809,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-09: AERO-TRAJECT-09: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-09: AERO-TRAJECT-09: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-10: AERO-TRAJECT-10: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21810-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21810,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-10: AERO-TRAJECT-10: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-10: AERO-TRAJECT-10: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-11: AERO-TRAJECT-11: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21811-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21811,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-11: AERO-TRAJECT-11: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-11: AERO-TRAJECT-11: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-12: AERO-TRAJECT-12: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21812-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21812,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-12: AERO-TRAJECT-12: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-12: AERO-TRAJECT-12: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-13: AERO-TRAJECT-13: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21813-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21813,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-13: AERO-TRAJECT-13: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-13: AERO-TRAJECT-13: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-14: AERO-TRAJECT-14: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21814-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21814,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-14: AERO-TRAJECT-14: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-14: AERO-TRAJECT-14: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-15: AERO-TRAJECT-15: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21815-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21815,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-15: AERO-TRAJECT-15: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-15: AERO-TRAJECT-15: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-16: AERO-TRAJECT-16: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21816-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21816,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-16: AERO-TRAJECT-16: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-16: AERO-TRAJECT-16: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-17: AERO-TRAJECT-17: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21817-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21817,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-17: AERO-TRAJECT-17: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-17: AERO-TRAJECT-17: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-18: AERO-TRAJECT-18: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21818-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21818,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-18: AERO-TRAJECT-18: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-18: AERO-TRAJECT-18: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-19: AERO-TRAJECT-19: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21819-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21819,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-19: AERO-TRAJECT-19: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-19: AERO-TRAJECT-19: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-20: AERO-TRAJECT-20: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21820-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21820,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-20: AERO-TRAJECT-20: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-20: AERO-TRAJECT-20: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-21: AERO-TRAJECT-21: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21821-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21821,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-21: AERO-TRAJECT-21: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-21: AERO-TRAJECT-21: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-22: AERO-TRAJECT-22: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21822-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21822,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-22: AERO-TRAJECT-22: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-22: AERO-TRAJECT-22: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-23: AERO-TRAJECT-23: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21823-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21823,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-23: AERO-TRAJECT-23: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-23: AERO-TRAJECT-23: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-24: AERO-TRAJECT-24: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21824-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21824,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-24: AERO-TRAJECT-24: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-24: AERO-TRAJECT-24: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-25: AERO-TRAJECT-25: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21825-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21825,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-25: AERO-TRAJECT-25: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-25: AERO-TRAJECT-25: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-26: AERO-TRAJECT-26: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21826-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21826,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-26: AERO-TRAJECT-26: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-26: AERO-TRAJECT-26: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-27: AERO-TRAJECT-27: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21827-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21827,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-27: AERO-TRAJECT-27: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-27: AERO-TRAJECT-27: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-28: AERO-TRAJECT-28: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21828-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21828,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-28: AERO-TRAJECT-28: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-28: AERO-TRAJECT-28: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-29: AERO-TRAJECT-29: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21829-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21829,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-29: AERO-TRAJECT-29: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-29: AERO-TRAJECT-29: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-30: AERO-TRAJECT-30: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21830-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21830,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-30: AERO-TRAJECT-30: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-30: AERO-TRAJECT-30: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-31: AERO-TRAJECT-31: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21831-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21831,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-31: AERO-TRAJECT-31: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-31: AERO-TRAJECT-31: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-32: AERO-TRAJECT-32: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21832-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21832,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-32: AERO-TRAJECT-32: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-32: AERO-TRAJECT-32: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-33: AERO-TRAJECT-33: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21833-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21833,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-33: AERO-TRAJECT-33: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-33: AERO-TRAJECT-33: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-34: AERO-TRAJECT-34: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21834-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21834,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-34: AERO-TRAJECT-34: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-34: AERO-TRAJECT-34: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-35: AERO-TRAJECT-35: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21835-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21835,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-35: AERO-TRAJECT-35: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-35: AERO-TRAJECT-35: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-36: AERO-TRAJECT-36: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21836-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21836,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-36: AERO-TRAJECT-36: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-36: AERO-TRAJECT-36: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-37: AERO-TRAJECT-37: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21837-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21837,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-37: AERO-TRAJECT-37: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-37: AERO-TRAJECT-37: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-38: AERO-TRAJECT-38: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21838-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21838,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-38: AERO-TRAJECT-38: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-38: AERO-TRAJECT-38: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-39: AERO-TRAJECT-39: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21839-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21839,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-39: AERO-TRAJECT-39: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-39: AERO-TRAJECT-39: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-40: AERO-TRAJECT-40: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21840-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21840,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-40: AERO-TRAJECT-40: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-40: AERO-TRAJECT-40: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-41: AERO-TRAJECT-41: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21841-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21841,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-41: AERO-TRAJECT-41: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-41: AERO-TRAJECT-41: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-42: AERO-TRAJECT-42: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21842-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21842,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-42: AERO-TRAJECT-42: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-42: AERO-TRAJECT-42: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-43: AERO-TRAJECT-43: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21843-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21843,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-43: AERO-TRAJECT-43: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-43: AERO-TRAJECT-43: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-44: AERO-TRAJECT-44: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21844-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21844,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-44: AERO-TRAJECT-44: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-44: AERO-TRAJECT-44: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-45: AERO-TRAJECT-45: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21845-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21845,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-45: AERO-TRAJECT-45: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-45: AERO-TRAJECT-45: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-46: AERO-TRAJECT-46: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21846-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21846,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-46: AERO-TRAJECT-46: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-46: AERO-TRAJECT-46: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-47: AERO-TRAJECT-47: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21847-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21847,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-47: AERO-TRAJECT-47: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-47: AERO-TRAJECT-47: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-48: AERO-TRAJECT-48: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21848-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21848,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-48: AERO-TRAJECT-48: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-48: AERO-TRAJECT-48: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-49: AERO-TRAJECT-49: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21849-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21849,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-49: AERO-TRAJECT-49: Enterprise Aero Trajectory Gate Rule",
      severity: "HIGH",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-49: AERO-TRAJECT-49: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  // AERO-TRAJECT-50: AERO-TRAJECT-50: Enterprise Aero Trajectory Gate Rule
  if (cleanContent.includes('vulnerablePattern_AERO-TRAJECT-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aerotraject21850-${Date.now()}-${findingCounter.count++}`,
      ruleId: 21850,
      type: 'INFRA_DATABASE',
      title: "AERO-TRAJECT-50: AERO-TRAJECT-50: Enterprise Aero Trajectory Gate Rule",
      severity: "MEDIUM",
      category: "Aero Trajectory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Aero Trajectory configuration',
      reproductionSteps: [
        `Audited Aero Trajectory configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate AERO-TRAJECT-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [Aero Trajectory] Found AERO-TRAJECT-50: AERO-TRAJECT-50: Enterprise Aero Trajectory Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
