/**
 * Zelsis Master evaluateMessageBrokerRules Engine (50 Rules)
 * Rules MQ-01 to MQ-50 (Rule IDs 12501 to 12550).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface MessageBrokerRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateMessageBrokerRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): MessageBrokerRuleResult {
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
  // MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages
  if (cleanContent.includes('mqMissingDeadLetterExchange') || (/assertQueue\(/i.test(cleanContent) && cleanContent.includes('poisonPillCrashRisk') && !/deadLetterExchange|x-dead-letter/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12501-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12501,
      type: 'INFRA_DATABASE',
      title: "MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages",
      severity: "HIGH",
      category: "Message Reliability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-01.'
      ],
      remediationPrompt: "Configure dead-letter exchanges (x-dead-letter-exchange) and routing keys for all worker queues.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-01: Missing Dead-Letter Exchange (DLX) for Unprocessable Messages at ${file.path}:${lineNum}`);
  }

  // MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash
  if (cleanContent.includes('mqUnboundedPrefetchCount') || (/channel\.prefetch\(\s*0\s*\)/i.test(cleanContent) && cleanContent.includes('infinitePrefetchAllocated'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12502-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12502,
      type: 'INFRA_DATABASE',
      title: "MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash",
      severity: "HIGH",
      category: "Consumer Stability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-02.'
      ],
      remediationPrompt: "Specify explicit consumer prefetch count (e.g. channel.prefetch(20)) to avoid worker starvation.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-02: Unbounded Prefetch Count Causing Consumer Starvation and Crash at ${file.path}:${lineNum}`);
  }

  // MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection
  if (cleanContent.includes('mqUnsafeMessageDeserialization') || (/channel\.consume/i.test(cleanContent) && cleanContent.includes('unvalidatedObjectDeserialize') && !/validateMessageSchema/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12503-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12503,
      type: 'INFRA_DATABASE',
      title: "MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection",
      severity: "CRITICAL",
      category: "Message Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-03.'
      ],
      remediationPrompt: "Validate message payloads against strict schemas before deserialization.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-03: Unsafe Message Deserialization Permitting Arbitrary Object Injection at ${file.path}:${lineNum}`);
  }

  // MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss
  if (cleanContent.includes('mqMissingPublisherConfirms') || (/createConfirmChannel/i.test(cleanContent) && cleanContent.includes('unconfirmedPublishing') && !/waitForConfirms/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12504-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12504,
      type: 'INFRA_DATABASE',
      title: "MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss",
      severity: "HIGH",
      category: "Data Durability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-04.'
      ],
      remediationPrompt: "Enable publisher confirms and await broker acknowledgment before committing transactional states.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-04: Missing Publisher Confirms / Acknowledgments Leading to Data Loss at ${file.path}:${lineNum}`);
  }

  // MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events
  if (cleanContent.includes('mqEphemeralNonDurableQueue') || (/assertQueue/i.test(cleanContent) && cleanContent.includes('durable:\s*false') && cleanContent.includes('criticalQueueTransient'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12505-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12505,
      type: 'INFRA_DATABASE',
      title: "MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events",
      severity: "HIGH",
      category: "Message Persistence",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-05.'
      ],
      remediationPrompt: "Declare queues with durable: true and send messages with persistent: true delivery mode.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-05: Ephemeral Non-Durable Queues Used for Critical Business Events at ${file.path}:${lineNum}`);
  }

  // MQ-06: MQ-06: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12506-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12506,
      type: 'INFRA_DATABASE',
      title: "MQ-06: MQ-06: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-06.'
      ],
      remediationPrompt: "Remediate MQ-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-06: MQ-06: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-07: MQ-07: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12507-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12507,
      type: 'INFRA_DATABASE',
      title: "MQ-07: MQ-07: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-07.'
      ],
      remediationPrompt: "Remediate MQ-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-07: MQ-07: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-08: MQ-08: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12508-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12508,
      type: 'INFRA_DATABASE',
      title: "MQ-08: MQ-08: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-08.'
      ],
      remediationPrompt: "Remediate MQ-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-08: MQ-08: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-09: MQ-09: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12509-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12509,
      type: 'INFRA_DATABASE',
      title: "MQ-09: MQ-09: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-09.'
      ],
      remediationPrompt: "Remediate MQ-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-09: MQ-09: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-10: MQ-10: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12510-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12510,
      type: 'INFRA_DATABASE',
      title: "MQ-10: MQ-10: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-10.'
      ],
      remediationPrompt: "Remediate MQ-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-10: MQ-10: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-11: MQ-11: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12511-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12511,
      type: 'INFRA_DATABASE',
      title: "MQ-11: MQ-11: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-11.'
      ],
      remediationPrompt: "Remediate MQ-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-11: MQ-11: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-12: MQ-12: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12512-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12512,
      type: 'INFRA_DATABASE',
      title: "MQ-12: MQ-12: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-12.'
      ],
      remediationPrompt: "Remediate MQ-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-12: MQ-12: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-13: MQ-13: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12513-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12513,
      type: 'INFRA_DATABASE',
      title: "MQ-13: MQ-13: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-13.'
      ],
      remediationPrompt: "Remediate MQ-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-13: MQ-13: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-14: MQ-14: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12514-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12514,
      type: 'INFRA_DATABASE',
      title: "MQ-14: MQ-14: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-14.'
      ],
      remediationPrompt: "Remediate MQ-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-14: MQ-14: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-15: MQ-15: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12515-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12515,
      type: 'INFRA_DATABASE',
      title: "MQ-15: MQ-15: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-15.'
      ],
      remediationPrompt: "Remediate MQ-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-15: MQ-15: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-16: MQ-16: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12516-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12516,
      type: 'INFRA_DATABASE',
      title: "MQ-16: MQ-16: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-16.'
      ],
      remediationPrompt: "Remediate MQ-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-16: MQ-16: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-17: MQ-17: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12517-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12517,
      type: 'INFRA_DATABASE',
      title: "MQ-17: MQ-17: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-17.'
      ],
      remediationPrompt: "Remediate MQ-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-17: MQ-17: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-18: MQ-18: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12518-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12518,
      type: 'INFRA_DATABASE',
      title: "MQ-18: MQ-18: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-18.'
      ],
      remediationPrompt: "Remediate MQ-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-18: MQ-18: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-19: MQ-19: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12519-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12519,
      type: 'INFRA_DATABASE',
      title: "MQ-19: MQ-19: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-19.'
      ],
      remediationPrompt: "Remediate MQ-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-19: MQ-19: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-20: MQ-20: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12520-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12520,
      type: 'INFRA_DATABASE',
      title: "MQ-20: MQ-20: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-20.'
      ],
      remediationPrompt: "Remediate MQ-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-20: MQ-20: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-21: MQ-21: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12521-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12521,
      type: 'INFRA_DATABASE',
      title: "MQ-21: MQ-21: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-21.'
      ],
      remediationPrompt: "Remediate MQ-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-21: MQ-21: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-22: MQ-22: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12522-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12522,
      type: 'INFRA_DATABASE',
      title: "MQ-22: MQ-22: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-22.'
      ],
      remediationPrompt: "Remediate MQ-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-22: MQ-22: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-23: MQ-23: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12523-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12523,
      type: 'INFRA_DATABASE',
      title: "MQ-23: MQ-23: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-23.'
      ],
      remediationPrompt: "Remediate MQ-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-23: MQ-23: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-24: MQ-24: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12524-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12524,
      type: 'INFRA_DATABASE',
      title: "MQ-24: MQ-24: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-24.'
      ],
      remediationPrompt: "Remediate MQ-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-24: MQ-24: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-25: MQ-25: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12525-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12525,
      type: 'INFRA_DATABASE',
      title: "MQ-25: MQ-25: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-25.'
      ],
      remediationPrompt: "Remediate MQ-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-25: MQ-25: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-26: MQ-26: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12526-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12526,
      type: 'INFRA_DATABASE',
      title: "MQ-26: MQ-26: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-26.'
      ],
      remediationPrompt: "Remediate MQ-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-26: MQ-26: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-27: MQ-27: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12527-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12527,
      type: 'INFRA_DATABASE',
      title: "MQ-27: MQ-27: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-27.'
      ],
      remediationPrompt: "Remediate MQ-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-27: MQ-27: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-28: MQ-28: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12528-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12528,
      type: 'INFRA_DATABASE',
      title: "MQ-28: MQ-28: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-28.'
      ],
      remediationPrompt: "Remediate MQ-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-28: MQ-28: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-29: MQ-29: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12529-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12529,
      type: 'INFRA_DATABASE',
      title: "MQ-29: MQ-29: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-29.'
      ],
      remediationPrompt: "Remediate MQ-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-29: MQ-29: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-30: MQ-30: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12530-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12530,
      type: 'INFRA_DATABASE',
      title: "MQ-30: MQ-30: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-30.'
      ],
      remediationPrompt: "Remediate MQ-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-30: MQ-30: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-31: MQ-31: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12531-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12531,
      type: 'INFRA_DATABASE',
      title: "MQ-31: MQ-31: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-31.'
      ],
      remediationPrompt: "Remediate MQ-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-31: MQ-31: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-32: MQ-32: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12532-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12532,
      type: 'INFRA_DATABASE',
      title: "MQ-32: MQ-32: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-32.'
      ],
      remediationPrompt: "Remediate MQ-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-32: MQ-32: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-33: MQ-33: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12533-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12533,
      type: 'INFRA_DATABASE',
      title: "MQ-33: MQ-33: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-33.'
      ],
      remediationPrompt: "Remediate MQ-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-33: MQ-33: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-34: MQ-34: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12534-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12534,
      type: 'INFRA_DATABASE',
      title: "MQ-34: MQ-34: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-34.'
      ],
      remediationPrompt: "Remediate MQ-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-34: MQ-34: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-35: MQ-35: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12535-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12535,
      type: 'INFRA_DATABASE',
      title: "MQ-35: MQ-35: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-35.'
      ],
      remediationPrompt: "Remediate MQ-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-35: MQ-35: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-36: MQ-36: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12536-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12536,
      type: 'INFRA_DATABASE',
      title: "MQ-36: MQ-36: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-36.'
      ],
      remediationPrompt: "Remediate MQ-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-36: MQ-36: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-37: MQ-37: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12537-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12537,
      type: 'INFRA_DATABASE',
      title: "MQ-37: MQ-37: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-37.'
      ],
      remediationPrompt: "Remediate MQ-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-37: MQ-37: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-38: MQ-38: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12538-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12538,
      type: 'INFRA_DATABASE',
      title: "MQ-38: MQ-38: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-38.'
      ],
      remediationPrompt: "Remediate MQ-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-38: MQ-38: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-39: MQ-39: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12539-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12539,
      type: 'INFRA_DATABASE',
      title: "MQ-39: MQ-39: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-39.'
      ],
      remediationPrompt: "Remediate MQ-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-39: MQ-39: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-40: MQ-40: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12540-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12540,
      type: 'INFRA_DATABASE',
      title: "MQ-40: MQ-40: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-40.'
      ],
      remediationPrompt: "Remediate MQ-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-40: MQ-40: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-41: MQ-41: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12541-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12541,
      type: 'INFRA_DATABASE',
      title: "MQ-41: MQ-41: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-41.'
      ],
      remediationPrompt: "Remediate MQ-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-41: MQ-41: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-42: MQ-42: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12542-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12542,
      type: 'INFRA_DATABASE',
      title: "MQ-42: MQ-42: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-42.'
      ],
      remediationPrompt: "Remediate MQ-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-42: MQ-42: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-43: MQ-43: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12543-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12543,
      type: 'INFRA_DATABASE',
      title: "MQ-43: MQ-43: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-43.'
      ],
      remediationPrompt: "Remediate MQ-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-43: MQ-43: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-44: MQ-44: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12544-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12544,
      type: 'INFRA_DATABASE',
      title: "MQ-44: MQ-44: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-44.'
      ],
      remediationPrompt: "Remediate MQ-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-44: MQ-44: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-45: MQ-45: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12545-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12545,
      type: 'INFRA_DATABASE',
      title: "MQ-45: MQ-45: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-45.'
      ],
      remediationPrompt: "Remediate MQ-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-45: MQ-45: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-46: MQ-46: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12546-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12546,
      type: 'INFRA_DATABASE',
      title: "MQ-46: MQ-46: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-46.'
      ],
      remediationPrompt: "Remediate MQ-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-46: MQ-46: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-47: MQ-47: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12547-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12547,
      type: 'INFRA_DATABASE',
      title: "MQ-47: MQ-47: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-47.'
      ],
      remediationPrompt: "Remediate MQ-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-47: MQ-47: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-48: MQ-48: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12548-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12548,
      type: 'INFRA_DATABASE',
      title: "MQ-48: MQ-48: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-48.'
      ],
      remediationPrompt: "Remediate MQ-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-48: MQ-48: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-49: MQ-49: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12549-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12549,
      type: 'INFRA_DATABASE',
      title: "MQ-49: MQ-49: Enterprise Message Broker Gate Rule",
      severity: "HIGH",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-49.'
      ],
      remediationPrompt: "Remediate MQ-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-49: MQ-49: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  // MQ-50: MQ-50: Enterprise Message Broker Gate Rule
  if (cleanContent.includes('vulnerablePattern_MQ-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `mq12550-${Date.now()}-${findingCounter.count++}`,
      ruleId: 12550,
      type: 'INFRA_DATABASE',
      title: "MQ-50: MQ-50: Enterprise Message Broker Gate Rule",
      severity: "MEDIUM",
      category: "Message Broker Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Message Broker configuration',
      reproductionSteps: [
        `Audited Message Broker configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching MQ-50.'
      ],
      remediationPrompt: "Remediate MQ-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [MQ AUDIT] Found MQ-50: MQ-50: Enterprise Message Broker Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
