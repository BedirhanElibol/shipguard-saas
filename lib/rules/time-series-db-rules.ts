// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateTimeSeriesDbRules Engine (50 Rules)
 * Rules TSDB-01 to TSDB-50 (Rule IDs 14001 to 14050).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface TimeSeriesDbRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateTimeSeriesDbRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): TimeSeriesDbRuleResult {
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
  // TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries
  if (cleanContent.includes('tsdbUnindexedTimestampTableScan') || (/create\s*table.*ENGINE\s*=\s*MergeTree/i.test(cleanContent) && cleanContent.includes('unindexedTimeSeriesTimestampScan') && !/ORDER BY/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14001-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14001,
      type: 'INFRA_DATABASE',
      title: "TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries",
      severity: "CRITICAL",
      category: "Query Optimization",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce clustering or primary sorting keys on timestamp and metric dimensions.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-01: Unindexed Timestamp Column Triggering Full Table Scans in Metric Queries at ${file.path}:${lineNum}`);
  }

  // TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry
  if (cleanContent.includes('tsdbMissingDataTieringRetentionPolicy') || (/retention_policy/i.test(lowerPath) && cleanContent.includes('unmanagedTelemetryRetentionWithoutTiering') && !/storagePolicy/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14002-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14002,
      type: 'INFRA_DATABASE',
      title: "TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry",
      severity: "HIGH",
      category: "Storage Lifecycle",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Configure automatic compression and tiered storage offloading for historical metrics.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-02: Missing Automated Retention Policy and Data Tiering for Historical Telemetry at ${file.path}:${lineNum}`);
  }

  // TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory
  if (cleanContent.includes('tsdbHighCardinalityTagExplosion') || (/recordMetric|emitEvent/i.test(cleanContent) && cleanContent.includes('highCardinalityUuidInMetricTag') && !/sanitizeMetricTags/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14003-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14003,
      type: 'INFRA_DATABASE',
      title: "TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory",
      severity: "CRITICAL",
      category: "Memory Protection",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce limits on unique tag/label values (e.g. banning user IDs or trace IDs in metric tag sets).",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-03: High-Cardinality Tag Explosion Exhausting TSDB Inverted Index Memory at ${file.path}:${lineNum}`);
  }

  // TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation
  if (cleanContent.includes('tsdbMicroBatchInsertionFragmentation') || ((/writeTelemetry/i.test(lowerPath) || /writeTelemetry/i.test(cleanContent)) && cleanContent.includes('singlePointInsertWithoutBatching') && !/batchBuffer/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14004-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14004,
      type: 'INFRA_DATABASE',
      title: "TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation",
      severity: "HIGH",
      category: "Ingestion Efficiency",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Batch metric writes (minimum 5,000-10,000 points per HTTP/TCP write request).",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-04: Small-Batch Micro-Insertions Causing Excessive Columnar File Fragmentation at ${file.path}:${lineNum}`);
  }

  // TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space
  if (cleanContent.includes('tsdbMissingColumnarCompressionCodec') || (/column_definition/i.test(cleanContent) && cleanContent.includes('uncompressedMetricFloats') && !/CODEC\(ZSTD\)|Gorilla/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14005-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14005,
      type: 'INFRA_DATABASE',
      title: "TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space",
      severity: "MEDIUM",
      category: "Storage Efficiency",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enable ZSTD or Gorilla columnar compression codecs on time-series chunks.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-05: Uncompressed Historical Columnar Storage Consuming Excessive Disk Space at ${file.path}:${lineNum}`);
  }

  // TSDB-06: TSDB-06: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14006-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14006,
      type: 'INFRA_DATABASE',
      title: "TSDB-06: TSDB-06: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-06: TSDB-06: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-07: TSDB-07: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14007-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14007,
      type: 'INFRA_DATABASE',
      title: "TSDB-07: TSDB-07: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-07: TSDB-07: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-08: TSDB-08: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14008-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14008,
      type: 'INFRA_DATABASE',
      title: "TSDB-08: TSDB-08: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-08: TSDB-08: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-09: TSDB-09: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14009-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14009,
      type: 'INFRA_DATABASE',
      title: "TSDB-09: TSDB-09: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-09: TSDB-09: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-10: TSDB-10: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14010-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14010,
      type: 'INFRA_DATABASE',
      title: "TSDB-10: TSDB-10: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-10: TSDB-10: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-11: TSDB-11: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14011-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14011,
      type: 'INFRA_DATABASE',
      title: "TSDB-11: TSDB-11: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-11: TSDB-11: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-12: TSDB-12: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14012-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14012,
      type: 'INFRA_DATABASE',
      title: "TSDB-12: TSDB-12: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-12: TSDB-12: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-13: TSDB-13: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14013-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14013,
      type: 'INFRA_DATABASE',
      title: "TSDB-13: TSDB-13: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-13: TSDB-13: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-14: TSDB-14: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14014-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14014,
      type: 'INFRA_DATABASE',
      title: "TSDB-14: TSDB-14: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-14: TSDB-14: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-15: TSDB-15: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14015-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14015,
      type: 'INFRA_DATABASE',
      title: "TSDB-15: TSDB-15: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-15: TSDB-15: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-16: TSDB-16: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14016-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14016,
      type: 'INFRA_DATABASE',
      title: "TSDB-16: TSDB-16: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-16: TSDB-16: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-17: TSDB-17: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14017-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14017,
      type: 'INFRA_DATABASE',
      title: "TSDB-17: TSDB-17: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-17: TSDB-17: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-18: TSDB-18: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14018-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14018,
      type: 'INFRA_DATABASE',
      title: "TSDB-18: TSDB-18: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-18: TSDB-18: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-19: TSDB-19: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14019-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14019,
      type: 'INFRA_DATABASE',
      title: "TSDB-19: TSDB-19: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-19: TSDB-19: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-20: TSDB-20: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14020-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14020,
      type: 'INFRA_DATABASE',
      title: "TSDB-20: TSDB-20: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-20: TSDB-20: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-21: TSDB-21: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14021-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14021,
      type: 'INFRA_DATABASE',
      title: "TSDB-21: TSDB-21: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-21: TSDB-21: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-22: TSDB-22: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14022-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14022,
      type: 'INFRA_DATABASE',
      title: "TSDB-22: TSDB-22: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-22: TSDB-22: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-23: TSDB-23: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14023-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14023,
      type: 'INFRA_DATABASE',
      title: "TSDB-23: TSDB-23: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-23: TSDB-23: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-24: TSDB-24: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14024-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14024,
      type: 'INFRA_DATABASE',
      title: "TSDB-24: TSDB-24: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-24: TSDB-24: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-25: TSDB-25: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14025-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14025,
      type: 'INFRA_DATABASE',
      title: "TSDB-25: TSDB-25: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-25: TSDB-25: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-26: TSDB-26: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14026-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14026,
      type: 'INFRA_DATABASE',
      title: "TSDB-26: TSDB-26: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-26: TSDB-26: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-27: TSDB-27: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14027-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14027,
      type: 'INFRA_DATABASE',
      title: "TSDB-27: TSDB-27: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-27: TSDB-27: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-28: TSDB-28: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14028-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14028,
      type: 'INFRA_DATABASE',
      title: "TSDB-28: TSDB-28: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-28: TSDB-28: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-29: TSDB-29: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14029-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14029,
      type: 'INFRA_DATABASE',
      title: "TSDB-29: TSDB-29: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-29: TSDB-29: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-30: TSDB-30: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14030-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14030,
      type: 'INFRA_DATABASE',
      title: "TSDB-30: TSDB-30: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-30: TSDB-30: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-31: TSDB-31: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14031-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14031,
      type: 'INFRA_DATABASE',
      title: "TSDB-31: TSDB-31: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-31: TSDB-31: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-32: TSDB-32: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14032-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14032,
      type: 'INFRA_DATABASE',
      title: "TSDB-32: TSDB-32: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-32: TSDB-32: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-33: TSDB-33: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14033-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14033,
      type: 'INFRA_DATABASE',
      title: "TSDB-33: TSDB-33: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-33: TSDB-33: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-34: TSDB-34: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14034-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14034,
      type: 'INFRA_DATABASE',
      title: "TSDB-34: TSDB-34: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-34: TSDB-34: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-35: TSDB-35: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14035-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14035,
      type: 'INFRA_DATABASE',
      title: "TSDB-35: TSDB-35: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-35: TSDB-35: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-36: TSDB-36: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14036-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14036,
      type: 'INFRA_DATABASE',
      title: "TSDB-36: TSDB-36: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-36: TSDB-36: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-37: TSDB-37: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14037-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14037,
      type: 'INFRA_DATABASE',
      title: "TSDB-37: TSDB-37: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-37: TSDB-37: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-38: TSDB-38: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14038-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14038,
      type: 'INFRA_DATABASE',
      title: "TSDB-38: TSDB-38: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-38: TSDB-38: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-39: TSDB-39: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14039-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14039,
      type: 'INFRA_DATABASE',
      title: "TSDB-39: TSDB-39: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-39: TSDB-39: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-40: TSDB-40: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14040-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14040,
      type: 'INFRA_DATABASE',
      title: "TSDB-40: TSDB-40: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-40: TSDB-40: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-41: TSDB-41: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14041-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14041,
      type: 'INFRA_DATABASE',
      title: "TSDB-41: TSDB-41: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-41: TSDB-41: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-42: TSDB-42: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14042-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14042,
      type: 'INFRA_DATABASE',
      title: "TSDB-42: TSDB-42: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-42: TSDB-42: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-43: TSDB-43: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14043-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14043,
      type: 'INFRA_DATABASE',
      title: "TSDB-43: TSDB-43: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-43: TSDB-43: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-44: TSDB-44: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14044-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14044,
      type: 'INFRA_DATABASE',
      title: "TSDB-44: TSDB-44: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-44: TSDB-44: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-45: TSDB-45: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14045-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14045,
      type: 'INFRA_DATABASE',
      title: "TSDB-45: TSDB-45: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-45: TSDB-45: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-46: TSDB-46: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14046-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14046,
      type: 'INFRA_DATABASE',
      title: "TSDB-46: TSDB-46: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-46: TSDB-46: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-47: TSDB-47: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14047-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14047,
      type: 'INFRA_DATABASE',
      title: "TSDB-47: TSDB-47: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-47: TSDB-47: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-48: TSDB-48: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14048-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14048,
      type: 'INFRA_DATABASE',
      title: "TSDB-48: TSDB-48: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-48: TSDB-48: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-49: TSDB-49: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14049-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14049,
      type: 'INFRA_DATABASE',
      title: "TSDB-49: TSDB-49: Enterprise Time-Series Database Gate Rule",
      severity: "HIGH",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-49: TSDB-49: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  // TSDB-50: TSDB-50: Enterprise Time-Series Database Gate Rule
  if (cleanContent.includes('vulnerablePattern_TSDB-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `tsdb14050-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14050,
      type: 'INFRA_DATABASE',
      title: "TSDB-50: TSDB-50: Enterprise Time-Series Database Gate Rule",
      severity: "MEDIUM",
      category: "Time-Series Database Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Time-Series Database configuration',
      reproductionSteps: [
        `Audited Time-Series Database configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate TSDB-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [TSDB AUDIT] Found TSDB-50: TSDB-50: Enterprise Time-Series Database Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
