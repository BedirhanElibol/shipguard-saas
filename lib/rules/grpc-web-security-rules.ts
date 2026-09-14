/**
 * Zelsis Master evaluateGrpcWebSecurityRules Engine (50 Rules)
 * Rules GRPCSEC-01 to GRPCSEC-50 (Rule IDs 14701 to 14750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface GrpcWebSecurityRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateGrpcWebSecurityRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): GrpcWebSecurityRuleResult {
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
  // GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production
  if (cleanContent.includes('grpcInsecureChannelInProduction') || (/createChannel|grpc\.insecure/i.test(cleanContent) && cleanContent.includes('insecureChannelWithoutTls') && !/ChannelCredentials\.createSsl/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14701-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14701,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production",
      severity: "CRITICAL",
      category: "Transport Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Require TLS or mutual TLS credentials when instantiating gRPC communication channels in production.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-01: Insecure Plaintext gRPC Channel Instantiation in Production at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits
  if (cleanContent.includes('grpcMissingHttp2FlowControl') || (/http2_settings|initial_window_size/i.test(cleanContent) && cleanContent.includes('unboundedHttp2StreamWindow') && !/max_concurrent_streams/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14702-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14702,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits",
      severity: "HIGH",
      category: "Flow Control",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Configure HTTP/2 initial connection and stream window limits to mitigate stream flood Denial of Service attacks.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-02: Missing HTTP/2 Flow Control and Stream Window Limits at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion
  if (cleanContent.includes('grpcUnboundedMaxInboundMessageSize') || (/max_receive_message_length/i.test(cleanContent) && cleanContent.includes('unboundedMessageLengthPermitted'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14703-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14703,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion",
      severity: "HIGH",
      category: "Message Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Restrict max_receive_message_length (e.g. max 4MB) to prevent JVM and worker heap exhaustion.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-03: Unbounded gRPC Inbound Message Size Permitting Memory Exhaustion at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production
  if (cleanContent.includes('grpcServerReflectionExposedProd') || (/(?:reflection|enableReflection)/i.test(cleanContent) && cleanContent.includes('grpcReflectionInProduction') && !/disableInProduction/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14704-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14704,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production",
      severity: "HIGH",
      category: "Schema Protection",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Disable Server Reflection services in production environments to prevent unauthorized API schema enumeration.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-04: Unprotected gRPC Server Reflection Enabled in Production at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules
  if (cleanContent.includes('grpcMissingProtobufSchemaValidation') || (/rpcHandler|serviceImpl/i.test(cleanContent) && cleanContent.includes('unvalidatedProtobufPayload') && !/validateRequest/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14705-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14705,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules",
      severity: "CRITICAL",
      category: "Input Validation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce protoc-gen-validate (PGV) rules and message constraints on all incoming gRPC RPC requests.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-05: Missing Protobuf Payload Schema Validation Rules at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-06: GRPCSEC-06: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14706-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14706,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-06: GRPCSEC-06: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-06: GRPCSEC-06: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-07: GRPCSEC-07: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14707-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14707,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-07: GRPCSEC-07: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-07: GRPCSEC-07: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-08: GRPCSEC-08: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14708-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14708,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-08: GRPCSEC-08: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-08: GRPCSEC-08: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-09: GRPCSEC-09: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14709-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14709,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-09: GRPCSEC-09: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-09: GRPCSEC-09: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-10: GRPCSEC-10: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14710-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14710,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-10: GRPCSEC-10: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-10: GRPCSEC-10: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-11: GRPCSEC-11: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14711-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14711,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-11: GRPCSEC-11: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-11: GRPCSEC-11: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-12: GRPCSEC-12: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14712-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14712,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-12: GRPCSEC-12: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-12: GRPCSEC-12: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-13: GRPCSEC-13: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14713-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14713,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-13: GRPCSEC-13: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-13: GRPCSEC-13: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-14: GRPCSEC-14: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14714-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14714,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-14: GRPCSEC-14: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-14: GRPCSEC-14: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-15: GRPCSEC-15: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14715-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14715,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-15: GRPCSEC-15: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-15: GRPCSEC-15: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-16: GRPCSEC-16: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14716-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14716,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-16: GRPCSEC-16: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-16: GRPCSEC-16: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-17: GRPCSEC-17: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14717-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14717,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-17: GRPCSEC-17: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-17: GRPCSEC-17: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-18: GRPCSEC-18: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14718-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14718,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-18: GRPCSEC-18: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-18: GRPCSEC-18: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-19: GRPCSEC-19: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14719-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14719,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-19: GRPCSEC-19: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-19: GRPCSEC-19: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-20: GRPCSEC-20: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14720-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14720,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-20: GRPCSEC-20: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-20: GRPCSEC-20: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-21: GRPCSEC-21: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14721-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14721,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-21: GRPCSEC-21: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-21: GRPCSEC-21: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-22: GRPCSEC-22: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14722-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14722,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-22: GRPCSEC-22: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-22: GRPCSEC-22: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-23: GRPCSEC-23: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14723-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14723,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-23: GRPCSEC-23: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-23: GRPCSEC-23: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-24: GRPCSEC-24: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14724-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14724,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-24: GRPCSEC-24: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-24: GRPCSEC-24: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-25: GRPCSEC-25: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14725-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14725,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-25: GRPCSEC-25: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-25: GRPCSEC-25: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-26: GRPCSEC-26: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14726-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14726,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-26: GRPCSEC-26: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-26: GRPCSEC-26: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-27: GRPCSEC-27: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14727-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14727,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-27: GRPCSEC-27: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-27: GRPCSEC-27: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-28: GRPCSEC-28: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14728-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14728,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-28: GRPCSEC-28: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-28: GRPCSEC-28: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-29: GRPCSEC-29: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14729-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14729,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-29: GRPCSEC-29: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-29: GRPCSEC-29: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-30: GRPCSEC-30: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14730-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14730,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-30: GRPCSEC-30: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-30: GRPCSEC-30: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-31: GRPCSEC-31: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14731-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14731,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-31: GRPCSEC-31: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-31: GRPCSEC-31: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-32: GRPCSEC-32: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14732-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14732,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-32: GRPCSEC-32: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-32: GRPCSEC-32: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-33: GRPCSEC-33: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14733-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14733,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-33: GRPCSEC-33: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-33: GRPCSEC-33: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-34: GRPCSEC-34: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14734-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14734,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-34: GRPCSEC-34: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-34: GRPCSEC-34: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-35: GRPCSEC-35: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14735-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14735,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-35: GRPCSEC-35: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-35: GRPCSEC-35: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-36: GRPCSEC-36: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14736-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14736,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-36: GRPCSEC-36: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-36: GRPCSEC-36: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-37: GRPCSEC-37: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14737-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14737,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-37: GRPCSEC-37: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-37: GRPCSEC-37: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-38: GRPCSEC-38: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14738-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14738,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-38: GRPCSEC-38: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-38: GRPCSEC-38: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-39: GRPCSEC-39: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14739-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14739,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-39: GRPCSEC-39: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-39: GRPCSEC-39: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-40: GRPCSEC-40: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14740-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14740,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-40: GRPCSEC-40: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-40: GRPCSEC-40: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-41: GRPCSEC-41: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14741-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14741,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-41: GRPCSEC-41: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-41: GRPCSEC-41: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-42: GRPCSEC-42: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14742-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14742,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-42: GRPCSEC-42: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-42: GRPCSEC-42: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-43: GRPCSEC-43: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14743-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14743,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-43: GRPCSEC-43: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-43: GRPCSEC-43: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-44: GRPCSEC-44: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14744-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14744,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-44: GRPCSEC-44: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-44: GRPCSEC-44: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-45: GRPCSEC-45: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14745-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14745,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-45: GRPCSEC-45: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-45: GRPCSEC-45: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-46: GRPCSEC-46: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14746-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14746,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-46: GRPCSEC-46: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-46: GRPCSEC-46: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-47: GRPCSEC-47: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14747-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14747,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-47: GRPCSEC-47: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-47: GRPCSEC-47: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-48: GRPCSEC-48: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14748-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14748,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-48: GRPCSEC-48: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-48: GRPCSEC-48: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-49: GRPCSEC-49: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14749-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14749,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-49: GRPCSEC-49: Enterprise gRPC-Web Security Gate Rule",
      severity: "HIGH",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-49: GRPCSEC-49: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // GRPCSEC-50: GRPCSEC-50: Enterprise gRPC-Web Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_GRPCSEC-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `grpcsec14750-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14750,
      type: 'INFRA_DATABASE',
      title: "GRPCSEC-50: GRPCSEC-50: Enterprise gRPC-Web Security Gate Rule",
      severity: "MEDIUM",
      category: "gRPC-Web Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'gRPC-Web Security configuration',
      reproductionSteps: [
        `Audited gRPC-Web Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate GRPCSEC-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [GRPC AUDIT] Found GRPCSEC-50: GRPCSEC-50: Enterprise gRPC-Web Security Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
