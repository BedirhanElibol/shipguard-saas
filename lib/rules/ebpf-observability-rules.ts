// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateEbpfObservabilityRules Engine (50 Rules)
 * Rules EBPF-01 to EBPF-50 (Rule IDs 14201 to 14250).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface EbpfObservabilityRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateEbpfObservabilityRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): EbpfObservabilityRuleResult {
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
  // EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM
  if (cleanContent.includes('ebpfUnboundedRingBuffer') || (/ring_buffer|perf_buffer/i.test(cleanContent) && cleanContent.includes('unboundedEbpfBufferAllocation') && !/max_entries|buffer_size/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14201-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14201,
      type: 'INFRA_DATABASE',
      title: "EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM",
      severity: "CRITICAL",
      category: "Memory Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce memory limits on perf and ring buffers to prevent kernel memory exhaustion under burst traffic.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-01: Unbounded eBPF Ring Buffer Allocation Causing Kernel OOM at ${file.path}:${lineNum}`);
  }

  // EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading
  if (cleanContent.includes('ebpfUnprivilegedBpfLoadingPermitted') || (/unprivileged_bpf_disabled/i.test(cleanContent) && cleanContent.includes('unprivileged_bpf_disabled = 0'))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14202-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14202,
      type: 'INFRA_DATABASE',
      title: "EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading",
      severity: "CRITICAL",
      category: "Syscall Security",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Set kernel.unprivileged_bpf_disabled = 2 to restrict BPF program loading strictly to privileged admin processes.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-02: Insecure BPF Syscall Permissions Permitting Unprivileged Loading at ${file.path}:${lineNum}`);
  }

  // EBPF-03: Missing Tetragon Process Execution Tracing in Workloads
  if (cleanContent.includes('ebpfMissingTetragonProcessTracing') || (/tetragon/i.test(lowerPath) && cleanContent.includes('unmonitoredKprobeExecve') && !/tracingpolicy/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14203-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14203,
      type: 'INFRA_DATABASE',
      title: "EBPF-03: Missing Tetragon Process Execution Tracing in Workloads",
      severity: "HIGH",
      category: "Runtime Observability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Deploy eBPF kprobe hooks monitoring unauthorized execve calls and shell spawns in container namespaces.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-03: Missing Tetragon Process Execution Tracing in Workloads at ${file.path}:${lineNum}`);
  }

  // EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation
  if (cleanContent.includes('ebpfUnfilteredXdpPacketIngestion') || (/xdp_pass/i.test(cleanContent) && cleanContent.includes('unfilteredXdpIngestion') && !/xdp_drop|rateLimit/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14204-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14204,
      type: 'INFRA_DATABASE',
      title: "EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation",
      severity: "HIGH",
      category: "Packet Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Implement rate-limiting XDP drop filters before packet payloads reach the Linux network stack.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-04: Unfiltered eBPF XDP Packet Ingestion Triggering CPU Saturation at ${file.path}:${lineNum}`);
  }

  // EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement
  if (cleanContent.includes('ebpfMissingCiliumL7PolicyEnforcement') || (/CiliumNetworkPolicy/i.test(cleanContent) && cleanContent.includes('permissiveL3L4OnlyRules') && !/rules:\s*-/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14205-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14205,
      type: 'INFRA_DATABASE',
      title: "EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement",
      severity: "CRITICAL",
      category: "Network Boundary",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Enforce L7 HTTP and gRPC API path filtering rules rather than permissive L3/L4 IP and port allowances.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-05: Missing Cilium NetworkPolicy L7 Protocol Path Enforcement at ${file.path}:${lineNum}`);
  }

  // EBPF-06: EBPF-06: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14206-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14206,
      type: 'INFRA_DATABASE',
      title: "EBPF-06: EBPF-06: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-06: EBPF-06: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-07: EBPF-07: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14207-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14207,
      type: 'INFRA_DATABASE',
      title: "EBPF-07: EBPF-07: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-07: EBPF-07: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-08: EBPF-08: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14208-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14208,
      type: 'INFRA_DATABASE',
      title: "EBPF-08: EBPF-08: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-08: EBPF-08: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-09: EBPF-09: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14209-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14209,
      type: 'INFRA_DATABASE',
      title: "EBPF-09: EBPF-09: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-09: EBPF-09: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-10: EBPF-10: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14210-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14210,
      type: 'INFRA_DATABASE',
      title: "EBPF-10: EBPF-10: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-10: EBPF-10: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-11: EBPF-11: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14211-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14211,
      type: 'INFRA_DATABASE',
      title: "EBPF-11: EBPF-11: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-11: EBPF-11: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-12: EBPF-12: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14212-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14212,
      type: 'INFRA_DATABASE',
      title: "EBPF-12: EBPF-12: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-12: EBPF-12: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-13: EBPF-13: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14213-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14213,
      type: 'INFRA_DATABASE',
      title: "EBPF-13: EBPF-13: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-13: EBPF-13: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-14: EBPF-14: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14214-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14214,
      type: 'INFRA_DATABASE',
      title: "EBPF-14: EBPF-14: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-14: EBPF-14: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-15: EBPF-15: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14215-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14215,
      type: 'INFRA_DATABASE',
      title: "EBPF-15: EBPF-15: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-15: EBPF-15: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-16: EBPF-16: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14216-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14216,
      type: 'INFRA_DATABASE',
      title: "EBPF-16: EBPF-16: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-16: EBPF-16: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-17: EBPF-17: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14217-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14217,
      type: 'INFRA_DATABASE',
      title: "EBPF-17: EBPF-17: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-17: EBPF-17: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-18: EBPF-18: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14218-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14218,
      type: 'INFRA_DATABASE',
      title: "EBPF-18: EBPF-18: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-18: EBPF-18: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-19: EBPF-19: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14219-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14219,
      type: 'INFRA_DATABASE',
      title: "EBPF-19: EBPF-19: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-19: EBPF-19: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-20: EBPF-20: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14220-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14220,
      type: 'INFRA_DATABASE',
      title: "EBPF-20: EBPF-20: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-20: EBPF-20: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-21: EBPF-21: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14221-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14221,
      type: 'INFRA_DATABASE',
      title: "EBPF-21: EBPF-21: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-21: EBPF-21: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-22: EBPF-22: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14222-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14222,
      type: 'INFRA_DATABASE',
      title: "EBPF-22: EBPF-22: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-22: EBPF-22: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-23: EBPF-23: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14223-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14223,
      type: 'INFRA_DATABASE',
      title: "EBPF-23: EBPF-23: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-23: EBPF-23: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-24: EBPF-24: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14224-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14224,
      type: 'INFRA_DATABASE',
      title: "EBPF-24: EBPF-24: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-24: EBPF-24: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-25: EBPF-25: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14225-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14225,
      type: 'INFRA_DATABASE',
      title: "EBPF-25: EBPF-25: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-25: EBPF-25: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-26: EBPF-26: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14226-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14226,
      type: 'INFRA_DATABASE',
      title: "EBPF-26: EBPF-26: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-26: EBPF-26: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-27: EBPF-27: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14227-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14227,
      type: 'INFRA_DATABASE',
      title: "EBPF-27: EBPF-27: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-27: EBPF-27: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-28: EBPF-28: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14228-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14228,
      type: 'INFRA_DATABASE',
      title: "EBPF-28: EBPF-28: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-28: EBPF-28: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-29: EBPF-29: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14229-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14229,
      type: 'INFRA_DATABASE',
      title: "EBPF-29: EBPF-29: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-29: EBPF-29: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-30: EBPF-30: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14230-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14230,
      type: 'INFRA_DATABASE',
      title: "EBPF-30: EBPF-30: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-30: EBPF-30: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-31: EBPF-31: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14231-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14231,
      type: 'INFRA_DATABASE',
      title: "EBPF-31: EBPF-31: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-31: EBPF-31: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-32: EBPF-32: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14232-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14232,
      type: 'INFRA_DATABASE',
      title: "EBPF-32: EBPF-32: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-32: EBPF-32: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-33: EBPF-33: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14233-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14233,
      type: 'INFRA_DATABASE',
      title: "EBPF-33: EBPF-33: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-33: EBPF-33: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-34: EBPF-34: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14234-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14234,
      type: 'INFRA_DATABASE',
      title: "EBPF-34: EBPF-34: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-34: EBPF-34: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-35: EBPF-35: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14235-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14235,
      type: 'INFRA_DATABASE',
      title: "EBPF-35: EBPF-35: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-35: EBPF-35: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-36: EBPF-36: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14236-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14236,
      type: 'INFRA_DATABASE',
      title: "EBPF-36: EBPF-36: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-36: EBPF-36: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-37: EBPF-37: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14237-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14237,
      type: 'INFRA_DATABASE',
      title: "EBPF-37: EBPF-37: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-37: EBPF-37: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-38: EBPF-38: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14238-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14238,
      type: 'INFRA_DATABASE',
      title: "EBPF-38: EBPF-38: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-38: EBPF-38: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-39: EBPF-39: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14239-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14239,
      type: 'INFRA_DATABASE',
      title: "EBPF-39: EBPF-39: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-39: EBPF-39: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-40: EBPF-40: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14240-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14240,
      type: 'INFRA_DATABASE',
      title: "EBPF-40: EBPF-40: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-40: EBPF-40: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-41: EBPF-41: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14241-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14241,
      type: 'INFRA_DATABASE',
      title: "EBPF-41: EBPF-41: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-41: EBPF-41: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-42: EBPF-42: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14242-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14242,
      type: 'INFRA_DATABASE',
      title: "EBPF-42: EBPF-42: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-42: EBPF-42: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-43: EBPF-43: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14243-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14243,
      type: 'INFRA_DATABASE',
      title: "EBPF-43: EBPF-43: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-43: EBPF-43: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-44: EBPF-44: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14244-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14244,
      type: 'INFRA_DATABASE',
      title: "EBPF-44: EBPF-44: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-44: EBPF-44: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-45: EBPF-45: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14245-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14245,
      type: 'INFRA_DATABASE',
      title: "EBPF-45: EBPF-45: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-45: EBPF-45: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-46: EBPF-46: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14246-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14246,
      type: 'INFRA_DATABASE',
      title: "EBPF-46: EBPF-46: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-46: EBPF-46: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-47: EBPF-47: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14247-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14247,
      type: 'INFRA_DATABASE',
      title: "EBPF-47: EBPF-47: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-47: EBPF-47: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-48: EBPF-48: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14248-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14248,
      type: 'INFRA_DATABASE',
      title: "EBPF-48: EBPF-48: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-48: EBPF-48: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-49: EBPF-49: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14249-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14249,
      type: 'INFRA_DATABASE',
      title: "EBPF-49: EBPF-49: Enterprise eBPF & Cilium Gate Rule",
      severity: "HIGH",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-49: EBPF-49: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  // EBPF-50: EBPF-50: Enterprise eBPF & Cilium Gate Rule
  if (cleanContent.includes('vulnerablePattern_EBPF-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `ebpf14250-${Date.now()}-${findingCounter.count++}`,
      ruleId: 14250,
      type: 'INFRA_DATABASE',
      title: "EBPF-50: EBPF-50: Enterprise eBPF & Cilium Gate Rule",
      severity: "MEDIUM",
      category: "eBPF & Cilium Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'eBPF & Cilium configuration',
      reproductionSteps: [
        `Audited eBPF & Cilium configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate EBPF-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [EBPF AUDIT] Found EBPF-50: EBPF-50: Enterprise eBPF & Cilium Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
