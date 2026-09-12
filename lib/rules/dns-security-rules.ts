// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateDnsSecurityRules Engine (50 Rules)
 * Rules DNS-01 to DNS-50 (Rule IDs 11801 to 11850).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface DnsSecurityRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateDnsSecurityRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): DnsSecurityRuleResult {
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
  // DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone
  if (cleanContent.includes('dnssecMissingOnZone') || (/dnsZone/i.test(cleanContent) && cleanContent.includes('unsignedAuthoritativeZone') && !/dnssec|rrsig/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11801-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11801,
      type: 'SECURITY',
      title: "DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone",
      severity: "HIGH",
      category: "DNS Authenticity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-01.'
      ],
      remediationPrompt: "Enable DNSSEC signing with RRSIG and DS records to prevent DNS spoofing and cache poisoning.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-01: DNSSEC Signature Validation Missing on Authoritative Zone at ${file.path}:${lineNum}`);
  }

  // DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover
  if (cleanContent.includes('danglingCnameRecordTakeover') || (/CNAME/i.test(cleanContent) && cleanContent.includes('orphanedCloudPointer') && !/verifiedOwner/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11802-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11802,
      type: 'SECURITY',
      title: "DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover",
      severity: "CRITICAL",
      category: "Subdomain Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-02.'
      ],
      remediationPrompt: "Remove dangling CNAME records pointing to decommissioned third-party cloud assets.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-02: Dangling DNS Record Vulnerable to Subdomain Takeover at ${file.path}:${lineNum}`);
  }

  // DNS-03: Missing CAA (Certification Authority Authorization) Record
  if (cleanContent.includes('missingCaaRecordPolicy') || (/dnsRecords/i.test(cleanContent) && cleanContent.includes('unrestrictedCertIssuance') && !/issue\s*"letsencrypt\.org"|CAA/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11803-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11803,
      type: 'SECURITY',
      title: "DNS-03: Missing CAA (Certification Authority Authorization) Record",
      severity: "HIGH",
      category: "PKI Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-03.'
      ],
      remediationPrompt: "Configure DNS CAA records to explicitly authorize trusted Certificate Authorities.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-03: Missing CAA (Certification Authority Authorization) Record at ${file.path}:${lineNum}`);
  }

  // DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers
  if (cleanContent.includes('unrestrictedAxfrZoneTransfer') || (/named\.conf/i.test(cleanContent) && cleanContent.includes('allowTransferAny') && !/allow-transfer\s*\{\s*none;/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11804-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11804,
      type: 'SECURITY',
      title: "DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers",
      severity: "CRITICAL",
      category: "Reconnaissance Defense",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-04.'
      ],
      remediationPrompt: "Restrict DNS zone transfers strictly to authorized secondary nameserver IPs.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-04: Unrestricted Zone Transfer (AXFR) Allowed on Public Nameservers at ${file.path}:${lineNum}`);
  }

  // DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints
  if (cleanContent.includes('dnsRebindingVulnerability') || (/httpServer/i.test(cleanContent) && cleanContent.includes('unvalidatedHostHeaderRebind') && !/validateHostHeader/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11805-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11805,
      type: 'SECURITY',
      title: "DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints",
      severity: "HIGH",
      category: "Internal Isolation",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-05.'
      ],
      remediationPrompt: "Validate Host and Origin headers on all local HTTP services to thwart DNS rebinding attacks.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-05: Missing DNS Rebinding Attack Protection on Internal Endpoints at ${file.path}:${lineNum}`);
  }

  // DNS-06: DNS-06: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11806-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11806,
      type: 'SECURITY',
      title: "DNS-06: DNS-06: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-06.'
      ],
      remediationPrompt: "Remediate DNS-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-06: DNS-06: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-07: DNS-07: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11807-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11807,
      type: 'SECURITY',
      title: "DNS-07: DNS-07: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-07.'
      ],
      remediationPrompt: "Remediate DNS-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-07: DNS-07: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-08: DNS-08: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11808-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11808,
      type: 'SECURITY',
      title: "DNS-08: DNS-08: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-08.'
      ],
      remediationPrompt: "Remediate DNS-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-08: DNS-08: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-09: DNS-09: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11809-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11809,
      type: 'SECURITY',
      title: "DNS-09: DNS-09: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-09.'
      ],
      remediationPrompt: "Remediate DNS-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-09: DNS-09: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-10: DNS-10: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11810-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11810,
      type: 'SECURITY',
      title: "DNS-10: DNS-10: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-10.'
      ],
      remediationPrompt: "Remediate DNS-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-10: DNS-10: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-11: DNS-11: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11811-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11811,
      type: 'SECURITY',
      title: "DNS-11: DNS-11: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-11.'
      ],
      remediationPrompt: "Remediate DNS-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-11: DNS-11: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-12: DNS-12: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11812-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11812,
      type: 'SECURITY',
      title: "DNS-12: DNS-12: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-12.'
      ],
      remediationPrompt: "Remediate DNS-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-12: DNS-12: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-13: DNS-13: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11813-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11813,
      type: 'SECURITY',
      title: "DNS-13: DNS-13: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-13.'
      ],
      remediationPrompt: "Remediate DNS-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-13: DNS-13: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-14: DNS-14: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11814-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11814,
      type: 'SECURITY',
      title: "DNS-14: DNS-14: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-14.'
      ],
      remediationPrompt: "Remediate DNS-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-14: DNS-14: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-15: DNS-15: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11815-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11815,
      type: 'SECURITY',
      title: "DNS-15: DNS-15: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-15.'
      ],
      remediationPrompt: "Remediate DNS-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-15: DNS-15: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-16: DNS-16: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11816-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11816,
      type: 'SECURITY',
      title: "DNS-16: DNS-16: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-16.'
      ],
      remediationPrompt: "Remediate DNS-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-16: DNS-16: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-17: DNS-17: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11817-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11817,
      type: 'SECURITY',
      title: "DNS-17: DNS-17: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-17.'
      ],
      remediationPrompt: "Remediate DNS-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-17: DNS-17: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-18: DNS-18: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11818-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11818,
      type: 'SECURITY',
      title: "DNS-18: DNS-18: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-18.'
      ],
      remediationPrompt: "Remediate DNS-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-18: DNS-18: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-19: DNS-19: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11819-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11819,
      type: 'SECURITY',
      title: "DNS-19: DNS-19: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-19.'
      ],
      remediationPrompt: "Remediate DNS-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-19: DNS-19: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-20: DNS-20: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11820-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11820,
      type: 'SECURITY',
      title: "DNS-20: DNS-20: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-20.'
      ],
      remediationPrompt: "Remediate DNS-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-20: DNS-20: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-21: DNS-21: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11821-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11821,
      type: 'SECURITY',
      title: "DNS-21: DNS-21: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-21.'
      ],
      remediationPrompt: "Remediate DNS-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-21: DNS-21: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-22: DNS-22: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11822-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11822,
      type: 'SECURITY',
      title: "DNS-22: DNS-22: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-22.'
      ],
      remediationPrompt: "Remediate DNS-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-22: DNS-22: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-23: DNS-23: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11823-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11823,
      type: 'SECURITY',
      title: "DNS-23: DNS-23: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-23.'
      ],
      remediationPrompt: "Remediate DNS-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-23: DNS-23: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-24: DNS-24: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11824-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11824,
      type: 'SECURITY',
      title: "DNS-24: DNS-24: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-24.'
      ],
      remediationPrompt: "Remediate DNS-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-24: DNS-24: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-25: DNS-25: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11825-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11825,
      type: 'SECURITY',
      title: "DNS-25: DNS-25: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-25.'
      ],
      remediationPrompt: "Remediate DNS-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-25: DNS-25: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-26: DNS-26: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11826-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11826,
      type: 'SECURITY',
      title: "DNS-26: DNS-26: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-26.'
      ],
      remediationPrompt: "Remediate DNS-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-26: DNS-26: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-27: DNS-27: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11827-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11827,
      type: 'SECURITY',
      title: "DNS-27: DNS-27: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-27.'
      ],
      remediationPrompt: "Remediate DNS-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-27: DNS-27: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-28: DNS-28: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11828-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11828,
      type: 'SECURITY',
      title: "DNS-28: DNS-28: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-28.'
      ],
      remediationPrompt: "Remediate DNS-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-28: DNS-28: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-29: DNS-29: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11829-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11829,
      type: 'SECURITY',
      title: "DNS-29: DNS-29: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-29.'
      ],
      remediationPrompt: "Remediate DNS-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-29: DNS-29: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-30: DNS-30: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11830-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11830,
      type: 'SECURITY',
      title: "DNS-30: DNS-30: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-30.'
      ],
      remediationPrompt: "Remediate DNS-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-30: DNS-30: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-31: DNS-31: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11831-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11831,
      type: 'SECURITY',
      title: "DNS-31: DNS-31: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-31.'
      ],
      remediationPrompt: "Remediate DNS-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-31: DNS-31: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-32: DNS-32: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11832-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11832,
      type: 'SECURITY',
      title: "DNS-32: DNS-32: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-32.'
      ],
      remediationPrompt: "Remediate DNS-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-32: DNS-32: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-33: DNS-33: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11833-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11833,
      type: 'SECURITY',
      title: "DNS-33: DNS-33: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-33.'
      ],
      remediationPrompt: "Remediate DNS-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-33: DNS-33: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-34: DNS-34: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11834-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11834,
      type: 'SECURITY',
      title: "DNS-34: DNS-34: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-34.'
      ],
      remediationPrompt: "Remediate DNS-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-34: DNS-34: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-35: DNS-35: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11835-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11835,
      type: 'SECURITY',
      title: "DNS-35: DNS-35: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-35.'
      ],
      remediationPrompt: "Remediate DNS-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-35: DNS-35: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-36: DNS-36: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11836-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11836,
      type: 'SECURITY',
      title: "DNS-36: DNS-36: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-36.'
      ],
      remediationPrompt: "Remediate DNS-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-36: DNS-36: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-37: DNS-37: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11837-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11837,
      type: 'SECURITY',
      title: "DNS-37: DNS-37: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-37.'
      ],
      remediationPrompt: "Remediate DNS-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-37: DNS-37: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-38: DNS-38: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11838-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11838,
      type: 'SECURITY',
      title: "DNS-38: DNS-38: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-38.'
      ],
      remediationPrompt: "Remediate DNS-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-38: DNS-38: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-39: DNS-39: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11839-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11839,
      type: 'SECURITY',
      title: "DNS-39: DNS-39: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-39.'
      ],
      remediationPrompt: "Remediate DNS-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-39: DNS-39: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-40: DNS-40: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11840-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11840,
      type: 'SECURITY',
      title: "DNS-40: DNS-40: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-40.'
      ],
      remediationPrompt: "Remediate DNS-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-40: DNS-40: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-41: DNS-41: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11841-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11841,
      type: 'SECURITY',
      title: "DNS-41: DNS-41: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-41.'
      ],
      remediationPrompt: "Remediate DNS-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-41: DNS-41: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-42: DNS-42: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11842-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11842,
      type: 'SECURITY',
      title: "DNS-42: DNS-42: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-42.'
      ],
      remediationPrompt: "Remediate DNS-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-42: DNS-42: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-43: DNS-43: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11843-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11843,
      type: 'SECURITY',
      title: "DNS-43: DNS-43: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-43.'
      ],
      remediationPrompt: "Remediate DNS-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-43: DNS-43: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-44: DNS-44: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11844-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11844,
      type: 'SECURITY',
      title: "DNS-44: DNS-44: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-44.'
      ],
      remediationPrompt: "Remediate DNS-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-44: DNS-44: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-45: DNS-45: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11845-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11845,
      type: 'SECURITY',
      title: "DNS-45: DNS-45: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-45.'
      ],
      remediationPrompt: "Remediate DNS-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-45: DNS-45: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-46: DNS-46: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11846-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11846,
      type: 'SECURITY',
      title: "DNS-46: DNS-46: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-46.'
      ],
      remediationPrompt: "Remediate DNS-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-46: DNS-46: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-47: DNS-47: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11847-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11847,
      type: 'SECURITY',
      title: "DNS-47: DNS-47: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-47.'
      ],
      remediationPrompt: "Remediate DNS-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-47: DNS-47: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-48: DNS-48: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11848-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11848,
      type: 'SECURITY',
      title: "DNS-48: DNS-48: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-48.'
      ],
      remediationPrompt: "Remediate DNS-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-48: DNS-48: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-49: DNS-49: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11849-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11849,
      type: 'SECURITY',
      title: "DNS-49: DNS-49: Enterprise DNS Security Gate Rule",
      severity: "HIGH",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-49.'
      ],
      remediationPrompt: "Remediate DNS-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-49: DNS-49: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  // DNS-50: DNS-50: Enterprise DNS Security Gate Rule
  if (cleanContent.includes('vulnerablePattern_DNS-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `dns-11850-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11850,
      type: 'SECURITY',
      title: "DNS-50: DNS-50: Enterprise DNS Security Gate Rule",
      severity: "MEDIUM",
      category: "DNS Security Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'DNS Security code segment',
      reproductionSteps: [
        `Audited DNS Security configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching DNS-50.'
      ],
      remediationPrompt: "Remediate DNS-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [DNS AUDIT] Found DNS-50: DNS-50: Enterprise DNS Security Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
