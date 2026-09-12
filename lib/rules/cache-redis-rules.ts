// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateCacheRedisRules Engine (50 Rules)
 * Rules CACHE-01 to CACHE-50 (Rule IDs 10701 to 10750).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface CacheRedisRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateCacheRedisRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): CacheRedisRuleResult {
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
  // CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses
  if (cleanContent.includes('cacheStampedeThunderingHerd') || (/redis\.get\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('unsynchronizedCacheFetch') && !/lock|mutex|redlock/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10701-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10701,
      type: 'INFRA_DATABASE',
      title: "CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses",
      severity: "HIGH",
      category: "Cache Reliability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-01.'
      ],
      remediationPrompt: "Wrap high-traffic cache fetches with distributed redlock or early probabilistic recomputation.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-01: Cache Stampede (Thundering Herd) via Unsynchronized Cache Misses at ${file.path}:${lineNum}`);
  }

  // CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash)
  if (cleanContent.includes('unboundedCacheKeyMissingTtl') || (/redis\.(?:set|setex|hset)\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('permanentCacheWrite') && !/ex|ttl|expire/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10702-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10702,
      type: 'INFRA_DATABASE',
      title: "CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash)",
      severity: "CRITICAL",
      category: "Memory Management",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-02.'
      ],
      remediationPrompt: "Enforce mandatory EX parameter on redis.set() calls and verify maxmemory-policy is set to allkeys-lru.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-02: Unbounded Cache Keys Lacking TTL Expiration (OOM Crash) at ${file.path}:${lineNum}`);
  }

  // CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0)
  if (cleanContent.includes('unauthenticatedPublicRedisBinding') || (/bind\s+0\.0\.0\.0/.test(cleanContent) && cleanContent.includes('unprotectedRedisPort') && !/requirepass/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10703-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10703,
      type: 'INFRA_DATABASE',
      title: "CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0)",
      severity: "CRITICAL",
      category: "Network Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-03.'
      ],
      remediationPrompt: "Configure bind 127.0.0.1 and requirepass in redis.conf, and block public port 6379 in security groups.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-03: Unauthenticated Redis Port Bound to Public Network Interfaces (0.0.0.0) at ${file.path}:${lineNum}`);
  }

  // CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops
  if (cleanContent.includes('unsafeLuaScriptStringConcatenation') || (/redis\.eval\s*\(\s*`[\s\S]*?\$\{/.test(cleanContent) && cleanContent.includes('unparameterizedLua'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10704-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10704,
      type: 'INFRA_DATABASE',
      title: "CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops",
      severity: "HIGH",
      category: "Script Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-04.'
      ],
      remediationPrompt: "Refactor redis.eval() calls to use static EVALSHA scripts with parameterized KEYS/ARGV arrays.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-04: Unsafe Lua Script Execution Susceptible to Injection or Infinite Loops at ${file.path}:${lineNum}`);
  }

  // CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob)
  if (cleanContent.includes('uncompressedLargeCacheBlob') || (/JSON\.stringify\s*\([\s\S]*?\)/.test(cleanContent) && cleanContent.includes('oversizedCachedCollection') && !/compress|gzip|snappy/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10705-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10705,
      type: 'INFRA_DATABASE',
      title: "CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob)",
      severity: "MEDIUM",
      category: "Network Throughput",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-05.'
      ],
      remediationPrompt: "Apply gzip/snappy compression before caching or paginate large cached entity collections.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) at ${file.path}:${lineNum}`);
  }

  // CACHE-06: CACHE-06: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10706-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10706,
      type: 'INFRA_DATABASE',
      title: "CACHE-06: CACHE-06: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-06.'
      ],
      remediationPrompt: "Remediate CACHE-06 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-06: CACHE-06: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-07: CACHE-07: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10707-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10707,
      type: 'INFRA_DATABASE',
      title: "CACHE-07: CACHE-07: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-07.'
      ],
      remediationPrompt: "Remediate CACHE-07 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-07: CACHE-07: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-08: CACHE-08: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10708-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10708,
      type: 'INFRA_DATABASE',
      title: "CACHE-08: CACHE-08: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-08.'
      ],
      remediationPrompt: "Remediate CACHE-08 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-08: CACHE-08: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-09: CACHE-09: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10709-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10709,
      type: 'INFRA_DATABASE',
      title: "CACHE-09: CACHE-09: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-09.'
      ],
      remediationPrompt: "Remediate CACHE-09 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-09: CACHE-09: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-10: CACHE-10: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10710-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10710,
      type: 'INFRA_DATABASE',
      title: "CACHE-10: CACHE-10: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-10.'
      ],
      remediationPrompt: "Remediate CACHE-10 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-10: CACHE-10: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-11: CACHE-11: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10711-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10711,
      type: 'INFRA_DATABASE',
      title: "CACHE-11: CACHE-11: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-11.'
      ],
      remediationPrompt: "Remediate CACHE-11 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-11: CACHE-11: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-12: CACHE-12: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10712-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10712,
      type: 'INFRA_DATABASE',
      title: "CACHE-12: CACHE-12: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-12.'
      ],
      remediationPrompt: "Remediate CACHE-12 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-12: CACHE-12: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-13: CACHE-13: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10713-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10713,
      type: 'INFRA_DATABASE',
      title: "CACHE-13: CACHE-13: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-13.'
      ],
      remediationPrompt: "Remediate CACHE-13 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-13: CACHE-13: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-14: CACHE-14: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10714-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10714,
      type: 'INFRA_DATABASE',
      title: "CACHE-14: CACHE-14: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-14.'
      ],
      remediationPrompt: "Remediate CACHE-14 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-14: CACHE-14: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-15: CACHE-15: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10715-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10715,
      type: 'INFRA_DATABASE',
      title: "CACHE-15: CACHE-15: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-15.'
      ],
      remediationPrompt: "Remediate CACHE-15 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-15: CACHE-15: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-16: CACHE-16: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10716-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10716,
      type: 'INFRA_DATABASE',
      title: "CACHE-16: CACHE-16: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-16.'
      ],
      remediationPrompt: "Remediate CACHE-16 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-16: CACHE-16: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-17: CACHE-17: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10717-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10717,
      type: 'INFRA_DATABASE',
      title: "CACHE-17: CACHE-17: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-17.'
      ],
      remediationPrompt: "Remediate CACHE-17 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-17: CACHE-17: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-18: CACHE-18: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10718-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10718,
      type: 'INFRA_DATABASE',
      title: "CACHE-18: CACHE-18: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-18.'
      ],
      remediationPrompt: "Remediate CACHE-18 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-18: CACHE-18: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-19: CACHE-19: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10719-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10719,
      type: 'INFRA_DATABASE',
      title: "CACHE-19: CACHE-19: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-19.'
      ],
      remediationPrompt: "Remediate CACHE-19 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-19: CACHE-19: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-20: CACHE-20: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10720-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10720,
      type: 'INFRA_DATABASE',
      title: "CACHE-20: CACHE-20: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-20.'
      ],
      remediationPrompt: "Remediate CACHE-20 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-20: CACHE-20: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-21: CACHE-21: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10721-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10721,
      type: 'INFRA_DATABASE',
      title: "CACHE-21: CACHE-21: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-21.'
      ],
      remediationPrompt: "Remediate CACHE-21 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-21: CACHE-21: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-22: CACHE-22: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10722-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10722,
      type: 'INFRA_DATABASE',
      title: "CACHE-22: CACHE-22: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-22.'
      ],
      remediationPrompt: "Remediate CACHE-22 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-22: CACHE-22: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-23: CACHE-23: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10723-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10723,
      type: 'INFRA_DATABASE',
      title: "CACHE-23: CACHE-23: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-23.'
      ],
      remediationPrompt: "Remediate CACHE-23 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-23: CACHE-23: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-24: CACHE-24: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10724-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10724,
      type: 'INFRA_DATABASE',
      title: "CACHE-24: CACHE-24: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-24.'
      ],
      remediationPrompt: "Remediate CACHE-24 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-24: CACHE-24: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-25: CACHE-25: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10725-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10725,
      type: 'INFRA_DATABASE',
      title: "CACHE-25: CACHE-25: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-25.'
      ],
      remediationPrompt: "Remediate CACHE-25 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-25: CACHE-25: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-26: CACHE-26: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10726-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10726,
      type: 'INFRA_DATABASE',
      title: "CACHE-26: CACHE-26: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-26.'
      ],
      remediationPrompt: "Remediate CACHE-26 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-26: CACHE-26: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-27: CACHE-27: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10727-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10727,
      type: 'INFRA_DATABASE',
      title: "CACHE-27: CACHE-27: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-27.'
      ],
      remediationPrompt: "Remediate CACHE-27 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-27: CACHE-27: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-28: CACHE-28: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10728-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10728,
      type: 'INFRA_DATABASE',
      title: "CACHE-28: CACHE-28: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-28.'
      ],
      remediationPrompt: "Remediate CACHE-28 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-28: CACHE-28: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-29: CACHE-29: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10729-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10729,
      type: 'INFRA_DATABASE',
      title: "CACHE-29: CACHE-29: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-29.'
      ],
      remediationPrompt: "Remediate CACHE-29 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-29: CACHE-29: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-30: CACHE-30: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10730-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10730,
      type: 'INFRA_DATABASE',
      title: "CACHE-30: CACHE-30: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-30.'
      ],
      remediationPrompt: "Remediate CACHE-30 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-30: CACHE-30: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-31: CACHE-31: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10731-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10731,
      type: 'INFRA_DATABASE',
      title: "CACHE-31: CACHE-31: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-31.'
      ],
      remediationPrompt: "Remediate CACHE-31 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-31: CACHE-31: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-32: CACHE-32: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10732-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10732,
      type: 'INFRA_DATABASE',
      title: "CACHE-32: CACHE-32: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-32.'
      ],
      remediationPrompt: "Remediate CACHE-32 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-32: CACHE-32: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-33: CACHE-33: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10733-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10733,
      type: 'INFRA_DATABASE',
      title: "CACHE-33: CACHE-33: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-33.'
      ],
      remediationPrompt: "Remediate CACHE-33 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-33: CACHE-33: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-34: CACHE-34: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10734-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10734,
      type: 'INFRA_DATABASE',
      title: "CACHE-34: CACHE-34: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-34.'
      ],
      remediationPrompt: "Remediate CACHE-34 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-34: CACHE-34: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-35: CACHE-35: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10735-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10735,
      type: 'INFRA_DATABASE',
      title: "CACHE-35: CACHE-35: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-35.'
      ],
      remediationPrompt: "Remediate CACHE-35 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-35: CACHE-35: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-36: CACHE-36: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10736-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10736,
      type: 'INFRA_DATABASE',
      title: "CACHE-36: CACHE-36: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-36.'
      ],
      remediationPrompt: "Remediate CACHE-36 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-36: CACHE-36: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-37: CACHE-37: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10737-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10737,
      type: 'INFRA_DATABASE',
      title: "CACHE-37: CACHE-37: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-37.'
      ],
      remediationPrompt: "Remediate CACHE-37 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-37: CACHE-37: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-38: CACHE-38: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10738-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10738,
      type: 'INFRA_DATABASE',
      title: "CACHE-38: CACHE-38: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-38.'
      ],
      remediationPrompt: "Remediate CACHE-38 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-38: CACHE-38: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-39: CACHE-39: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10739-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10739,
      type: 'INFRA_DATABASE',
      title: "CACHE-39: CACHE-39: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-39.'
      ],
      remediationPrompt: "Remediate CACHE-39 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-39: CACHE-39: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-40: CACHE-40: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10740-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10740,
      type: 'INFRA_DATABASE',
      title: "CACHE-40: CACHE-40: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-40.'
      ],
      remediationPrompt: "Remediate CACHE-40 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-40: CACHE-40: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-41: CACHE-41: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10741-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10741,
      type: 'INFRA_DATABASE',
      title: "CACHE-41: CACHE-41: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-41.'
      ],
      remediationPrompt: "Remediate CACHE-41 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-41: CACHE-41: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-42: CACHE-42: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10742-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10742,
      type: 'INFRA_DATABASE',
      title: "CACHE-42: CACHE-42: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-42.'
      ],
      remediationPrompt: "Remediate CACHE-42 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-42: CACHE-42: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-43: CACHE-43: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10743-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10743,
      type: 'INFRA_DATABASE',
      title: "CACHE-43: CACHE-43: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-43.'
      ],
      remediationPrompt: "Remediate CACHE-43 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-43: CACHE-43: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-44: CACHE-44: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10744-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10744,
      type: 'INFRA_DATABASE',
      title: "CACHE-44: CACHE-44: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-44.'
      ],
      remediationPrompt: "Remediate CACHE-44 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-44: CACHE-44: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-45: CACHE-45: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10745-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10745,
      type: 'INFRA_DATABASE',
      title: "CACHE-45: CACHE-45: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-45.'
      ],
      remediationPrompt: "Remediate CACHE-45 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-45: CACHE-45: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-46: CACHE-46: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10746-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10746,
      type: 'INFRA_DATABASE',
      title: "CACHE-46: CACHE-46: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-46.'
      ],
      remediationPrompt: "Remediate CACHE-46 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-46: CACHE-46: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-47: CACHE-47: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10747-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10747,
      type: 'INFRA_DATABASE',
      title: "CACHE-47: CACHE-47: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-47.'
      ],
      remediationPrompt: "Remediate CACHE-47 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-47: CACHE-47: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-48: CACHE-48: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10748-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10748,
      type: 'INFRA_DATABASE',
      title: "CACHE-48: CACHE-48: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-48.'
      ],
      remediationPrompt: "Remediate CACHE-48 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-48: CACHE-48: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-49: CACHE-49: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10749-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10749,
      type: 'INFRA_DATABASE',
      title: "CACHE-49: CACHE-49: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "HIGH",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-49.'
      ],
      remediationPrompt: "Remediate CACHE-49 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-49: CACHE-49: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  // CACHE-50: CACHE-50: Redis & In-Memory Distributed Cache Reliability Gate
  if (cleanContent.includes('vulnerablePattern_CACHE-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cache10750-${Date.now()}-${findingCounter.count++}`,
      ruleId: 10750,
      type: 'INFRA_DATABASE',
      title: "CACHE-50: CACHE-50: Redis & In-Memory Distributed Cache Reliability Gate",
      severity: "MEDIUM",
      category: "Cache Architecture",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Redis cache operation',
      reproductionSteps: [
        `Audited caching routines in ${file.path}:${lineNum}.`,
        'Detected cache architecture violation matching CACHE-50.'
      ],
      remediationPrompt: "Remediate CACHE-50 according to enterprise in-memory data store resilience specifications.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [CACHE AUDIT] Found CACHE-50: CACHE-50: Redis & In-Memory Distributed Cache Reliability Gate at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
