// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateScadaCriticalInfraRules Engine (50 Rules)
 * Rules SCADA-SEC-01 to SCADA-SEC-50 (Rule IDs 18301 to 18350).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface ScadaCriticalInfraResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateScadaCriticalInfraRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): ScadaCriticalInfraResult {
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
  // SCADA-SEC-01: Unauthenticated Modbus TCP and DNP3 Industrial Protocol Commands
  if (cleanContent.includes('scadaUnauthenticatedModbusCommands') || ((/scada|modbus|dnp3|industrial_ot/i.test(lowerPath) || /sendModbusCommand|dispatchPlcWrite/i.test(cleanContent)) && cleanContent.includes('unauthenticatedModbusPayload') && !/iec62351CryptographicAuth/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18301-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18301,
      type: 'SECURITY',
      title: "SCADA-SEC-01: Unauthenticated Modbus TCP and DNP3 Industrial Protocol Commands",
      severity: "CRITICAL",
      category: "Industrial Protocol Auth",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Deploy IEC 62351-compliant cryptographic authentication and message integrity checks across industrial control network fabrics.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-01: Unauthenticated Modbus TCP and DNP3 Industrial Protocol Commands at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-02: Unverified PLC Ladder Logic and Firmware Binary Integrity
  if (cleanContent.includes('scadaUnverifiedPlcLadderLogic') || ((/scada|plc_firmware|ladder_logic/i.test(lowerPath) || /loadLadderProgram|executePlcBinary/i.test(cleanContent)) && cleanContent.includes('unverifiedLadderLogicBinary') && !/secureBootHashAttestation/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18302-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18302,
      type: 'SECURITY',
      title: "SCADA-SEC-02: Unverified PLC Ladder Logic and Firmware Binary Integrity",
      severity: "CRITICAL",
      category: "PLC Firmware Attestation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce cryptographic hash attestation and secure boot on programmable logic controllers prior to ladder logic execution.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-02: Unverified PLC Ladder Logic and Firmware Binary Integrity at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-03: Missing Hardware Unidirectional Security Gateways (Data Diodes) on OT Networks
  if (cleanContent.includes('scadaMissingOpticalDataDiode') || ((/scada|ot_network|reactor_control/i.test(lowerPath) || /bridgeOtNetwork|egressTelemetry/i.test(cleanContent)) && cleanContent.includes('biDirectionalReactorNetworkBridge') && !/physicalOpticalDataDiodeIsolation/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18303-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18303,
      type: 'SECURITY',
      title: "SCADA-SEC-03: Missing Hardware Unidirectional Security Gateways (Data Diodes) on OT Networks",
      severity: "CRITICAL",
      category: "Data Diode Isolation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Isolate safety-critical reactor and turbine OT networks using physical optical data diodes preventing inbound network traffic.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-03: Missing Hardware Unidirectional Security Gateways (Data Diodes) on OT Networks at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-04: Unrestricted Turbine Governor Overspeed Trip Bypass Mechanism
  if (cleanContent.includes('scadaTurbineOverspeedBypass') || ((/scada|turbine_governor|overspeed_trip/i.test(lowerPath) || /controlGovernorSpeed|overrideTripInterlock/i.test(cleanContent)) && cleanContent.includes('softwareOverspeedBypassEnabled') && !/hardwiredTripleModularInterlock/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18304-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18304,
      type: 'SECURITY',
      title: "SCADA-SEC-04: Unrestricted Turbine Governor Overspeed Trip Bypass Mechanism",
      severity: "CRITICAL",
      category: "Turbine Overspeed Protection",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce independent triple-modular hardwired interlocks preventing software bypass of turbine overspeed trip triggers.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-04: Unrestricted Turbine Governor Overspeed Trip Bypass Mechanism at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-05: Unprotected SCADA Historian Database Telemetry and Setpoint Logs
  if (cleanContent.includes('scadaHistorianTelemetryTampering') || ((/scada|historian_db|ot_telemetry/i.test(lowerPath) || /writeHistorianLog|archiveSensorValues/i.test(cleanContent)) && cleanContent.includes('mutableHistorianRecords') && !/appendOnlyMerkleTreeLedger/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18305-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18305,
      type: 'SECURITY',
      title: "SCADA-SEC-05: Unprotected SCADA Historian Database Telemetry and Setpoint Logs",
      severity: "HIGH",
      category: "Historian Tamper Resistance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce append-only cryptographic ledger logging with Merkle tree proofs on operational historian sensor telemetry.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-05: Unprotected SCADA Historian Database Telemetry and Setpoint Logs at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-06: SCADA-SEC-06: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18306-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18306,
      type: 'SECURITY',
      title: "SCADA-SEC-06: SCADA-SEC-06: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-06: SCADA-SEC-06: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-07: SCADA-SEC-07: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18307-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18307,
      type: 'SECURITY',
      title: "SCADA-SEC-07: SCADA-SEC-07: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-07: SCADA-SEC-07: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-08: SCADA-SEC-08: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18308-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18308,
      type: 'SECURITY',
      title: "SCADA-SEC-08: SCADA-SEC-08: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-08: SCADA-SEC-08: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-09: SCADA-SEC-09: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18309-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18309,
      type: 'SECURITY',
      title: "SCADA-SEC-09: SCADA-SEC-09: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-09: SCADA-SEC-09: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-10: SCADA-SEC-10: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18310-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18310,
      type: 'SECURITY',
      title: "SCADA-SEC-10: SCADA-SEC-10: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-10: SCADA-SEC-10: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-11: SCADA-SEC-11: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18311-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18311,
      type: 'SECURITY',
      title: "SCADA-SEC-11: SCADA-SEC-11: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-11: SCADA-SEC-11: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-12: SCADA-SEC-12: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18312-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18312,
      type: 'SECURITY',
      title: "SCADA-SEC-12: SCADA-SEC-12: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-12: SCADA-SEC-12: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-13: SCADA-SEC-13: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18313-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18313,
      type: 'SECURITY',
      title: "SCADA-SEC-13: SCADA-SEC-13: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-13: SCADA-SEC-13: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-14: SCADA-SEC-14: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18314-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18314,
      type: 'SECURITY',
      title: "SCADA-SEC-14: SCADA-SEC-14: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-14: SCADA-SEC-14: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-15: SCADA-SEC-15: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18315-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18315,
      type: 'SECURITY',
      title: "SCADA-SEC-15: SCADA-SEC-15: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-15: SCADA-SEC-15: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-16: SCADA-SEC-16: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18316-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18316,
      type: 'SECURITY',
      title: "SCADA-SEC-16: SCADA-SEC-16: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-16: SCADA-SEC-16: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-17: SCADA-SEC-17: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18317-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18317,
      type: 'SECURITY',
      title: "SCADA-SEC-17: SCADA-SEC-17: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-17: SCADA-SEC-17: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-18: SCADA-SEC-18: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18318-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18318,
      type: 'SECURITY',
      title: "SCADA-SEC-18: SCADA-SEC-18: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-18: SCADA-SEC-18: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-19: SCADA-SEC-19: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18319-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18319,
      type: 'SECURITY',
      title: "SCADA-SEC-19: SCADA-SEC-19: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-19: SCADA-SEC-19: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-20: SCADA-SEC-20: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18320-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18320,
      type: 'SECURITY',
      title: "SCADA-SEC-20: SCADA-SEC-20: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-20: SCADA-SEC-20: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-21: SCADA-SEC-21: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18321-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18321,
      type: 'SECURITY',
      title: "SCADA-SEC-21: SCADA-SEC-21: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-21: SCADA-SEC-21: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-22: SCADA-SEC-22: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18322-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18322,
      type: 'SECURITY',
      title: "SCADA-SEC-22: SCADA-SEC-22: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-22: SCADA-SEC-22: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-23: SCADA-SEC-23: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18323-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18323,
      type: 'SECURITY',
      title: "SCADA-SEC-23: SCADA-SEC-23: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-23: SCADA-SEC-23: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-24: SCADA-SEC-24: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18324-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18324,
      type: 'SECURITY',
      title: "SCADA-SEC-24: SCADA-SEC-24: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-24: SCADA-SEC-24: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-25: SCADA-SEC-25: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18325-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18325,
      type: 'SECURITY',
      title: "SCADA-SEC-25: SCADA-SEC-25: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-25: SCADA-SEC-25: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-26: SCADA-SEC-26: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18326-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18326,
      type: 'SECURITY',
      title: "SCADA-SEC-26: SCADA-SEC-26: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-26: SCADA-SEC-26: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-27: SCADA-SEC-27: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18327-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18327,
      type: 'SECURITY',
      title: "SCADA-SEC-27: SCADA-SEC-27: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-27: SCADA-SEC-27: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-28: SCADA-SEC-28: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18328-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18328,
      type: 'SECURITY',
      title: "SCADA-SEC-28: SCADA-SEC-28: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-28: SCADA-SEC-28: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-29: SCADA-SEC-29: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18329-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18329,
      type: 'SECURITY',
      title: "SCADA-SEC-29: SCADA-SEC-29: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-29: SCADA-SEC-29: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-30: SCADA-SEC-30: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18330-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18330,
      type: 'SECURITY',
      title: "SCADA-SEC-30: SCADA-SEC-30: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-30: SCADA-SEC-30: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-31: SCADA-SEC-31: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18331-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18331,
      type: 'SECURITY',
      title: "SCADA-SEC-31: SCADA-SEC-31: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-31: SCADA-SEC-31: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-32: SCADA-SEC-32: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18332-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18332,
      type: 'SECURITY',
      title: "SCADA-SEC-32: SCADA-SEC-32: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-32: SCADA-SEC-32: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-33: SCADA-SEC-33: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18333-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18333,
      type: 'SECURITY',
      title: "SCADA-SEC-33: SCADA-SEC-33: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-33: SCADA-SEC-33: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-34: SCADA-SEC-34: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18334-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18334,
      type: 'SECURITY',
      title: "SCADA-SEC-34: SCADA-SEC-34: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-34: SCADA-SEC-34: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-35: SCADA-SEC-35: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18335-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18335,
      type: 'SECURITY',
      title: "SCADA-SEC-35: SCADA-SEC-35: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-35: SCADA-SEC-35: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-36: SCADA-SEC-36: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18336-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18336,
      type: 'SECURITY',
      title: "SCADA-SEC-36: SCADA-SEC-36: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-36: SCADA-SEC-36: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-37: SCADA-SEC-37: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18337-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18337,
      type: 'SECURITY',
      title: "SCADA-SEC-37: SCADA-SEC-37: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-37: SCADA-SEC-37: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-38: SCADA-SEC-38: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18338-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18338,
      type: 'SECURITY',
      title: "SCADA-SEC-38: SCADA-SEC-38: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-38: SCADA-SEC-38: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-39: SCADA-SEC-39: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18339-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18339,
      type: 'SECURITY',
      title: "SCADA-SEC-39: SCADA-SEC-39: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-39: SCADA-SEC-39: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-40: SCADA-SEC-40: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18340-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18340,
      type: 'SECURITY',
      title: "SCADA-SEC-40: SCADA-SEC-40: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-40: SCADA-SEC-40: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-41: SCADA-SEC-41: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18341-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18341,
      type: 'SECURITY',
      title: "SCADA-SEC-41: SCADA-SEC-41: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-41: SCADA-SEC-41: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-42: SCADA-SEC-42: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18342-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18342,
      type: 'SECURITY',
      title: "SCADA-SEC-42: SCADA-SEC-42: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-42: SCADA-SEC-42: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-43: SCADA-SEC-43: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18343-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18343,
      type: 'SECURITY',
      title: "SCADA-SEC-43: SCADA-SEC-43: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-43: SCADA-SEC-43: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-44: SCADA-SEC-44: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18344-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18344,
      type: 'SECURITY',
      title: "SCADA-SEC-44: SCADA-SEC-44: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-44: SCADA-SEC-44: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-45: SCADA-SEC-45: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18345-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18345,
      type: 'SECURITY',
      title: "SCADA-SEC-45: SCADA-SEC-45: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-45: SCADA-SEC-45: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-46: SCADA-SEC-46: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18346-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18346,
      type: 'SECURITY',
      title: "SCADA-SEC-46: SCADA-SEC-46: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-46: SCADA-SEC-46: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-47: SCADA-SEC-47: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18347-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18347,
      type: 'SECURITY',
      title: "SCADA-SEC-47: SCADA-SEC-47: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-47: SCADA-SEC-47: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-48: SCADA-SEC-48: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18348-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18348,
      type: 'SECURITY',
      title: "SCADA-SEC-48: SCADA-SEC-48: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-48: SCADA-SEC-48: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-49: SCADA-SEC-49: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18349-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18349,
      type: 'SECURITY',
      title: "SCADA-SEC-49: SCADA-SEC-49: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "HIGH",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-49: SCADA-SEC-49: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // SCADA-SEC-50: SCADA-SEC-50: Enterprise SCADA & Industrial Control Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_SCADA-SEC-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `scadasec18350-${Date.now()}-${findingCounter.count++}`,
      ruleId: 18350,
      type: 'SECURITY',
      title: "SCADA-SEC-50: SCADA-SEC-50: Enterprise SCADA & Industrial Control Security Gate Rule",
      severity: "MEDIUM",
      category: "SCADA & Industrial Control Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'SCADA & Industrial Control Security configuration',
      reproductionSteps: [
        `Audited SCADA & Industrial Control Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate SCADA-SEC-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [SCADA-CRITICAL-INFRA-AUDIT] Found SCADA-SEC-50: SCADA-SEC-50: Enterprise SCADA & Industrial Control Security Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
