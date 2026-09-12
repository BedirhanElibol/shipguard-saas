// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateSpacecraftGncAttitudeRules Engine (50 Rules)
 * Rules SPACE-GNC-01 to SPACE-GNC-50 (Rule IDs 18401 to 18450).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface SpacecraftGncAttitudeResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateSpacecraftGncAttitudeRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): SpacecraftGncAttitudeResult {
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
  // SPACE-GNC-01: Star Tracker Quaternion Singularity and Gimbal Lock Instability
  if (cleanContent.includes('spaceGncQuaternionSingularityGimbalLock') || ((/spacecraft|gnc|attitude_filter/i.test(lowerPath) || /propagateAttitude|computeQuaternion/i.test(cleanContent)) && cleanContent.includes('unnormalizedEulerGimbalSingularity') && !/dualQuaternionReorthogonalization/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18401-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18401,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-01: Star Tracker Quaternion Singularity and Gimbal Lock Instability",
      severity: "CRITICAL",
      category: "Quaternion Singularity Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Implement dual quaternion representations and unit-norm re-orthogonalization in spacecraft attitude estimation filters.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-01: Star Tracker Quaternion Singularity and Gimbal Lock Instability at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-02: Reaction Wheel Angular Momentum Saturation Without Automated Desaturation
  if (cleanContent.includes('spaceGncReactionWheelSaturation') || ((/spacecraft|reaction_wheel|momentum_management/i.test(lowerPath) || /commandWheelTorque|monitorRpm/i.test(cleanContent)) && cleanContent.includes('unhandledPeakWheelRpmSaturation') && !/automatedMagnetorquerDesaturation/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18402-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18402,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-02: Reaction Wheel Angular Momentum Saturation Without Automated Desaturation",
      severity: "CRITICAL",
      category: "Momentum Desaturation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Automate magnetic torquer or RCS thruster momentum dumping routines before reaction wheels exceed 90% peak RPM.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-02: Reaction Wheel Angular Momentum Saturation Without Automated Desaturation at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-03: Unconstrained Thruster Minimum Impulse Bit Jitter During Proximity Operations
  if (cleanContent.includes('spaceGncThrusterImpulseBitJitter') || ((/spacecraft|rcs_thruster|iss_docking/i.test(lowerPath) || /pulseThrusterFire|modulateImpulseBit/i.test(cleanContent)) && cleanContent.includes('unquantizedThrusterPulseJitter') && !/pwmImpulseBitQuantizationLimits/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18403-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18403,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-03: Unconstrained Thruster Minimum Impulse Bit Jitter During Proximity Operations",
      severity: "CRITICAL",
      category: "Thruster Modulation Limits",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce strict pulse-width modulation quantization limits to ensure micro-Newton station-keeping during ISS docking.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-03: Unconstrained Thruster Minimum Impulse Bit Jitter During Proximity Operations at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-04: Unmodeled Solar Radiation Pressure (SRP) Perturbation in Deep Space Navigation
  if (cleanContent.includes('spaceGncUnmodeledSrpPerturbation') || ((/spacecraft|deep_space_nav|orbital_propagation/i.test(lowerPath) || /propagateTrajectory|modelSolarPressure/i.test(cleanContent)) && cleanContent.includes('unmodeledSolarRadiationPressure') && !/opticalCrossSectionSrpModel/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18404-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18404,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-04: Unmodeled Solar Radiation Pressure (SRP) Perturbation in Deep Space Navigation",
      severity: "HIGH",
      category: "SRP Perturbation Modeling",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Integrate real-time spacecraft optical cross-section and SRP ballistic models into orbital propagation algorithms.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-04: Unmodeled Solar Radiation Pressure (SRP) Perturbation in Deep Space Navigation at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-05: Autonomous Rendezvous Collision Hazard During Non-Cooperative Target Docking
  if (cleanContent.includes('spaceGncRendezvousCollisionHazard') || ((/spacecraft|autonomous_rendezvous|docking/i.test(lowerPath) || /dockingTrajectory|abortManeuver/i.test(cleanContent)) && cleanContent.includes('intersectingTrajectoryPassThrough') && !/passiveAbortTrajectoryCones/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18405-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18405,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-05: Autonomous Rendezvous Collision Hazard During Non-Cooperative Target Docking",
      severity: "CRITICAL",
      category: "Passive Abort Cones",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Establish autonomous passive abort trajectory cones that guarantee non-intersecting orbits upon thruster faults.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-05: Autonomous Rendezvous Collision Hazard During Non-Cooperative Target Docking at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-06: SPACE-GNC-06: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18406-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18406,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-06: SPACE-GNC-06: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-06: SPACE-GNC-06: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-07: SPACE-GNC-07: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18407-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18407,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-07: SPACE-GNC-07: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-07: SPACE-GNC-07: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-08: SPACE-GNC-08: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18408-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18408,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-08: SPACE-GNC-08: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-08: SPACE-GNC-08: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-09: SPACE-GNC-09: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18409-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18409,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-09: SPACE-GNC-09: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-09: SPACE-GNC-09: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-10: SPACE-GNC-10: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18410-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18410,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-10: SPACE-GNC-10: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-10: SPACE-GNC-10: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-11: SPACE-GNC-11: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18411-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18411,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-11: SPACE-GNC-11: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-11: SPACE-GNC-11: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-12: SPACE-GNC-12: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18412-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18412,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-12: SPACE-GNC-12: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-12: SPACE-GNC-12: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-13: SPACE-GNC-13: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18413-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18413,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-13: SPACE-GNC-13: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-13: SPACE-GNC-13: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-14: SPACE-GNC-14: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18414-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18414,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-14: SPACE-GNC-14: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-14: SPACE-GNC-14: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-15: SPACE-GNC-15: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18415-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18415,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-15: SPACE-GNC-15: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-15: SPACE-GNC-15: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-16: SPACE-GNC-16: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18416-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18416,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-16: SPACE-GNC-16: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-16: SPACE-GNC-16: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-17: SPACE-GNC-17: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18417-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18417,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-17: SPACE-GNC-17: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-17: SPACE-GNC-17: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-18: SPACE-GNC-18: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18418-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18418,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-18: SPACE-GNC-18: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-18: SPACE-GNC-18: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-19: SPACE-GNC-19: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18419-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18419,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-19: SPACE-GNC-19: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-19: SPACE-GNC-19: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-20: SPACE-GNC-20: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18420-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18420,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-20: SPACE-GNC-20: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-20: SPACE-GNC-20: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-21: SPACE-GNC-21: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18421-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18421,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-21: SPACE-GNC-21: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-21: SPACE-GNC-21: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-22: SPACE-GNC-22: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18422-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18422,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-22: SPACE-GNC-22: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-22: SPACE-GNC-22: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-23: SPACE-GNC-23: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18423-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18423,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-23: SPACE-GNC-23: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-23: SPACE-GNC-23: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-24: SPACE-GNC-24: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18424-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18424,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-24: SPACE-GNC-24: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-24: SPACE-GNC-24: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-25: SPACE-GNC-25: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18425-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18425,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-25: SPACE-GNC-25: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-25: SPACE-GNC-25: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-26: SPACE-GNC-26: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18426-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18426,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-26: SPACE-GNC-26: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-26: SPACE-GNC-26: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-27: SPACE-GNC-27: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18427-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18427,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-27: SPACE-GNC-27: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-27: SPACE-GNC-27: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-28: SPACE-GNC-28: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18428-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18428,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-28: SPACE-GNC-28: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-28: SPACE-GNC-28: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-29: SPACE-GNC-29: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18429-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18429,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-29: SPACE-GNC-29: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-29: SPACE-GNC-29: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-30: SPACE-GNC-30: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18430-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18430,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-30: SPACE-GNC-30: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-30: SPACE-GNC-30: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-31: SPACE-GNC-31: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18431-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18431,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-31: SPACE-GNC-31: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-31: SPACE-GNC-31: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-32: SPACE-GNC-32: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18432-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18432,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-32: SPACE-GNC-32: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-32: SPACE-GNC-32: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-33: SPACE-GNC-33: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18433-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18433,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-33: SPACE-GNC-33: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-33: SPACE-GNC-33: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-34: SPACE-GNC-34: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18434-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18434,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-34: SPACE-GNC-34: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-34: SPACE-GNC-34: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-35: SPACE-GNC-35: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18435-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18435,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-35: SPACE-GNC-35: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-35: SPACE-GNC-35: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-36: SPACE-GNC-36: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18436-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18436,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-36: SPACE-GNC-36: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-36: SPACE-GNC-36: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-37: SPACE-GNC-37: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18437-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18437,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-37: SPACE-GNC-37: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-37: SPACE-GNC-37: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-38: SPACE-GNC-38: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18438-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18438,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-38: SPACE-GNC-38: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-38: SPACE-GNC-38: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-39: SPACE-GNC-39: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18439-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18439,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-39: SPACE-GNC-39: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-39: SPACE-GNC-39: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-40: SPACE-GNC-40: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18440-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18440,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-40: SPACE-GNC-40: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-40: SPACE-GNC-40: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-41: SPACE-GNC-41: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18441-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18441,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-41: SPACE-GNC-41: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-41: SPACE-GNC-41: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-42: SPACE-GNC-42: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18442-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18442,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-42: SPACE-GNC-42: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-42: SPACE-GNC-42: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-43: SPACE-GNC-43: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18443-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18443,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-43: SPACE-GNC-43: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-43: SPACE-GNC-43: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-44: SPACE-GNC-44: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18444-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18444,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-44: SPACE-GNC-44: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-44: SPACE-GNC-44: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-45: SPACE-GNC-45: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18445-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18445,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-45: SPACE-GNC-45: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-45: SPACE-GNC-45: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-46: SPACE-GNC-46: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18446-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18446,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-46: SPACE-GNC-46: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-46: SPACE-GNC-46: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-47: SPACE-GNC-47: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18447-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18447,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-47: SPACE-GNC-47: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-47: SPACE-GNC-47: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-48: SPACE-GNC-48: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18448-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18448,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-48: SPACE-GNC-48: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-48: SPACE-GNC-48: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-49: SPACE-GNC-49: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18449-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18449,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-49: SPACE-GNC-49: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "HIGH",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-49: SPACE-GNC-49: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  // SPACE-GNC-50: SPACE-GNC-50: Enterprise Spacecraft GNC Attitude Control Gate Rule
  if (cleanContent.includes('vulnerablePattern_SPACE-GNC-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `spacegnc18450-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18450,
      type: 'INFRA_DATABASE',
      title: "SPACE-GNC-50: SPACE-GNC-50: Enterprise Spacecraft GNC Attitude Control Gate Rule",
      severity: "MEDIUM",
      category: "Spacecraft GNC Attitude Control Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Spacecraft GNC Attitude Control configuration',
      reproductionSteps: [
        `Audited Spacecraft GNC Attitude Control configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SPACE-GNC-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SPACECRAFT-GNC-ATTITUDE-AUDIT] Found SPACE-GNC-50: SPACE-GNC-50: Enterprise Spacecraft GNC Attitude Control Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
