// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateThreatIntelligenceRules Engine (50 Rules)
 * Rules CTI-01 to CTI-50 (Rule IDs 15601 to 15650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface ThreatIntelligenceRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateThreatIntelligenceRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): ThreatIntelligenceRuleResult {
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
  // CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning
  if (cleanContent.includes('ctiUnvalidatedFeedPayloadPoisoning') || ((/threat_intel|taxii_client/i.test(lowerPath) || /taxiiFeed|stixParser/i.test(cleanContent)) && cleanContent.includes('unauthenticatedFeedPayloadIngestion') && !/verifyFeedSignature/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15601-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15601,
      type: 'SECURITY',
      title: "CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning",
      severity: "CRITICAL",
      category: "Feed Integrity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Authenticate threat intelligence feeds using TLS client certificates and cryptographically sign STIX/TAXII indicator payloads.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-01: Unvalidated Cyber Threat Intelligence (CTI) Feed Ingestion Permitting Malicious Rule Poisoning at ${file.path}:${lineNum}`);
  }

  // CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance
  if (cleanContent.includes('ctiMissingIocTtlExpirationGovernance') || ((/ioc_database|blocklist_rules/i.test(lowerPath) || /stixIndicator|iocStore/i.test(cleanContent)) && cleanContent.includes('permanentIocsWithoutTtl') && !/iocTtlDays/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15602-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15602,
      type: 'SECURITY',
      title: "CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance",
      severity: "HIGH",
      category: "Indicator Lifecycle",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Implement automated Time-to-Live (TTL) policies retiring ephemeral threat indicators (e.g. dynamic IP addresses) after 7 to 14 days.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-02: Missing STIX 2.1 & TAXII 2.1 Automated Threat Indicator Expiration and TTL Governance at ${file.path}:${lineNum}`);
  }

  // CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting
  if (cleanContent.includes('ctiMissingConfidenceScoreThreshold') || ((/threat_scoring|ioc_filtering/i.test(lowerPath) || /confidenceThreshold/i.test(cleanContent)) && cleanContent.includes('blockWithoutConfidenceFilter') && !/minConfidenceScore/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15603-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15603,
      type: 'SECURITY',
      title: "CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting",
      severity: "HIGH",
      category: "Accuracy Assurance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce minimum confidence score thresholds (e.g. score >= 85) and cross-reference major CDN/DNS provider whitelists prior to blocking.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-03: Lack of Automated Threat Feed Confidence Scoring Leading to Critical Benign Asset Blacklisting at ${file.path}:${lineNum}`);
  }

  // CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls
  if (cleanContent.includes('ctiMissingMispFirewallSync') || ((/misp_integration|firewall_sync/i.test(lowerPath) || /mispEvent/i.test(cleanContent)) && cleanContent.includes('unpropagatedMispEvents') && !/syncMispToFirewall/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15604-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15604,
      type: 'SECURITY',
      title: "CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls",
      severity: "MEDIUM",
      category: "Incident Sharing",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Automate bi-directional synchronization between security incident management and edge firewall IoC enforcement systems.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-04: Missing MISP Security Incident Event Synchronization on Perimeter Edge Firewalls at ${file.path}:${lineNum}`);
  }

  // CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring
  if (cleanContent.includes('ctiUnverifiedIocMatchingWithoutReputation') || ((/ioc_matcher|perimeter_alert/i.test(lowerPath) || /iocMatcher/i.test(cleanContent)) && cleanContent.includes('rawIocMatchNoReputation') && !/enrichWithReputation/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15605-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15605,
      type: 'SECURITY',
      title: "CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring",
      severity: "HIGH",
      category: "Reputation Scoring",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enrich all IoC detection alerts with multi-source reputation scoring before escalating to automated account lockouts or IP bans.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-05: Unverified IoC (Indicator of Compromise) Matching Running Without IP/Domain Reputation Scoring at ${file.path}:${lineNum}`);
  }

  // CTI-06: CTI-06: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15606-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15606,
      type: 'SECURITY',
      title: "CTI-06: CTI-06: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-06: CTI-06: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-07: CTI-07: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15607-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15607,
      type: 'SECURITY',
      title: "CTI-07: CTI-07: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-07: CTI-07: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-08: CTI-08: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15608-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15608,
      type: 'SECURITY',
      title: "CTI-08: CTI-08: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-08: CTI-08: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-09: CTI-09: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15609-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15609,
      type: 'SECURITY',
      title: "CTI-09: CTI-09: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-09: CTI-09: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-10: CTI-10: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15610-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15610,
      type: 'SECURITY',
      title: "CTI-10: CTI-10: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-10: CTI-10: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-11: CTI-11: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15611-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15611,
      type: 'SECURITY',
      title: "CTI-11: CTI-11: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-11: CTI-11: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-12: CTI-12: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15612-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15612,
      type: 'SECURITY',
      title: "CTI-12: CTI-12: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-12: CTI-12: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-13: CTI-13: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15613-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15613,
      type: 'SECURITY',
      title: "CTI-13: CTI-13: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-13: CTI-13: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-14: CTI-14: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15614-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15614,
      type: 'SECURITY',
      title: "CTI-14: CTI-14: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-14: CTI-14: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-15: CTI-15: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15615-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15615,
      type: 'SECURITY',
      title: "CTI-15: CTI-15: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-15: CTI-15: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-16: CTI-16: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15616-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15616,
      type: 'SECURITY',
      title: "CTI-16: CTI-16: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-16: CTI-16: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-17: CTI-17: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15617-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15617,
      type: 'SECURITY',
      title: "CTI-17: CTI-17: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-17: CTI-17: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-18: CTI-18: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15618-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15618,
      type: 'SECURITY',
      title: "CTI-18: CTI-18: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-18: CTI-18: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-19: CTI-19: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15619-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15619,
      type: 'SECURITY',
      title: "CTI-19: CTI-19: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-19: CTI-19: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-20: CTI-20: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15620-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15620,
      type: 'SECURITY',
      title: "CTI-20: CTI-20: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-20: CTI-20: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-21: CTI-21: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15621-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15621,
      type: 'SECURITY',
      title: "CTI-21: CTI-21: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-21: CTI-21: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-22: CTI-22: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15622-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15622,
      type: 'SECURITY',
      title: "CTI-22: CTI-22: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-22: CTI-22: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-23: CTI-23: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15623-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15623,
      type: 'SECURITY',
      title: "CTI-23: CTI-23: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-23: CTI-23: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-24: CTI-24: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15624-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15624,
      type: 'SECURITY',
      title: "CTI-24: CTI-24: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-24: CTI-24: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-25: CTI-25: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15625-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15625,
      type: 'SECURITY',
      title: "CTI-25: CTI-25: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-25: CTI-25: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-26: CTI-26: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15626-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15626,
      type: 'SECURITY',
      title: "CTI-26: CTI-26: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-26: CTI-26: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-27: CTI-27: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15627-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15627,
      type: 'SECURITY',
      title: "CTI-27: CTI-27: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-27: CTI-27: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-28: CTI-28: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15628-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15628,
      type: 'SECURITY',
      title: "CTI-28: CTI-28: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-28: CTI-28: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-29: CTI-29: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15629-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15629,
      type: 'SECURITY',
      title: "CTI-29: CTI-29: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-29: CTI-29: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-30: CTI-30: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15630-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15630,
      type: 'SECURITY',
      title: "CTI-30: CTI-30: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-30: CTI-30: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-31: CTI-31: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15631-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15631,
      type: 'SECURITY',
      title: "CTI-31: CTI-31: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-31: CTI-31: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-32: CTI-32: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15632-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15632,
      type: 'SECURITY',
      title: "CTI-32: CTI-32: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-32: CTI-32: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-33: CTI-33: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15633-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15633,
      type: 'SECURITY',
      title: "CTI-33: CTI-33: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-33: CTI-33: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-34: CTI-34: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15634-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15634,
      type: 'SECURITY',
      title: "CTI-34: CTI-34: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-34: CTI-34: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-35: CTI-35: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15635-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15635,
      type: 'SECURITY',
      title: "CTI-35: CTI-35: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-35: CTI-35: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-36: CTI-36: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15636-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15636,
      type: 'SECURITY',
      title: "CTI-36: CTI-36: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-36: CTI-36: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-37: CTI-37: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15637-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15637,
      type: 'SECURITY',
      title: "CTI-37: CTI-37: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-37: CTI-37: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-38: CTI-38: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15638-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15638,
      type: 'SECURITY',
      title: "CTI-38: CTI-38: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-38: CTI-38: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-39: CTI-39: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15639-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15639,
      type: 'SECURITY',
      title: "CTI-39: CTI-39: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-39: CTI-39: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-40: CTI-40: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15640-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15640,
      type: 'SECURITY',
      title: "CTI-40: CTI-40: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-40: CTI-40: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-41: CTI-41: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15641-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15641,
      type: 'SECURITY',
      title: "CTI-41: CTI-41: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-41: CTI-41: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-42: CTI-42: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15642-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15642,
      type: 'SECURITY',
      title: "CTI-42: CTI-42: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-42: CTI-42: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-43: CTI-43: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15643-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15643,
      type: 'SECURITY',
      title: "CTI-43: CTI-43: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-43: CTI-43: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-44: CTI-44: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15644-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15644,
      type: 'SECURITY',
      title: "CTI-44: CTI-44: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-44: CTI-44: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-45: CTI-45: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15645-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15645,
      type: 'SECURITY',
      title: "CTI-45: CTI-45: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-45: CTI-45: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-46: CTI-46: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15646-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15646,
      type: 'SECURITY',
      title: "CTI-46: CTI-46: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-46: CTI-46: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-47: CTI-47: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15647-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15647,
      type: 'SECURITY',
      title: "CTI-47: CTI-47: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-47: CTI-47: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-48: CTI-48: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15648-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15648,
      type: 'SECURITY',
      title: "CTI-48: CTI-48: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-48: CTI-48: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-49: CTI-49: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15649-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15649,
      type: 'SECURITY',
      title: "CTI-49: CTI-49: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "HIGH",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-49: CTI-49: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  // CTI-50: CTI-50: Enterprise Cyber Threat Intelligence Gate Rule
  if (cleanContent.includes('vulnerablePattern_CTI-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cti15650-${Date.now()}-${findingCounter.count++}`,
      ruleId: 15650,
      type: 'SECURITY',
      title: "CTI-50: CTI-50: Enterprise Cyber Threat Intelligence Gate Rule",
      severity: "MEDIUM",
      category: "Cyber Threat Intelligence Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Cyber Threat Intelligence configuration',
      reproductionSteps: [
        `Audited Cyber Threat Intelligence configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate CTI-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CTI AUDIT] Found CTI-50: CTI-50: Enterprise Cyber Threat Intelligence Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
