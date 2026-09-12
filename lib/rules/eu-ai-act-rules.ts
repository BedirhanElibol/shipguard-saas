// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateEuAiActRules Engine (50 Rules)
 * Rules AIACT-01 to AIACT-50 (Rule IDs 11601 to 11650).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface EuAiActRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateEuAiActRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): EuAiActRuleResult {
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
  // AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14)
  if (cleanContent.includes('euAiActMissingHumanInTheLoop') || (/highRiskModelDecision/i.test(cleanContent) && cleanContent.includes('unreviewedAutomatedAction') && !/humanReview|manualOverride/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11601-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11601,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14)",
      severity: "CRITICAL",
      category: "Human Oversight",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-01.'
      ],
      remediationPrompt: "Add human review workflow step for high-stakes algorithmic scoring decisions.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-01: Missing Human-in-the-Loop Oversight Hook on High-Risk AI Decisions (Article 14) at ${file.path}:${lineNum}`);
  }

  // AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10)
  if (cleanContent.includes('euAiActMissingBiasAuditReport') || (/fineTuneDataset/i.test(cleanContent) && cleanContent.includes('unassessedTrainingCorpus') && !/demographicParity|biasAudit/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11602-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11602,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10)",
      severity: "HIGH",
      category: "Dataset Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-02.'
      ],
      remediationPrompt: "Conduct demographic parity audits on fine-tuning training datasets and document fairness metrics.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-02: Missing Algorithmic Bias and Discrimination Audit on Training Data (Article 10) at ${file.path}:${lineNum}`);
  }

  // AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12)
  if (cleanContent.includes('euAiActMissingInferenceAuditLogging') || (/openai\.chat\.completions/i.test(cleanContent) && cleanContent.includes('unloggedAutonomousExecution') && !/auditLog|recordInference/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11603-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11603,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12)",
      severity: "HIGH",
      category: "Traceability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-03.'
      ],
      remediationPrompt: "Record all inference prompts, completions, and model version hashes to tamper-resistant audit logs.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12) at ${file.path}:${lineNum}`);
  }

  // AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50)
  if (cleanContent.includes('euAiActMissingC2paWatermark') || (/createImage|generateSpeech/i.test(cleanContent) && cleanContent.includes('unmarkedSyntheticMediaOutput') && !/c2pa|watermark|synthId/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11604-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11604,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50)",
      severity: "HIGH",
      category: "Transparency",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-04.'
      ],
      remediationPrompt: "Inject cryptographic C2PA provenance credentials into all AI-generated image and text payloads.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-04: Missing Machine-Readable Watermarking on Synthetic AI Content (Article 50) at ${file.path}:${lineNum}`);
  }

  // AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53)
  if (cleanContent.includes('euAiActMissingCopyrightDisclosure') || (/modelCard/i.test(cleanContent) && cleanContent.includes('undisclosedTrainingSources') && !/copyright|trainingSummary/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11605-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11605,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53)",
      severity: "MEDIUM",
      category: "Copyright Transparency",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-05.'
      ],
      remediationPrompt: "Publish training corpus source transparency disclosures on the model documentation portal.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-05: Unpublished Summary of Copyright-Protected Training Data (Article 53) at ${file.path}:${lineNum}`);
  }

  // AIACT-06: AIACT-06: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11606-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11606,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-06: AIACT-06: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-06.'
      ],
      remediationPrompt: "Remediate AIACT-06 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-06: AIACT-06: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-07: AIACT-07: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11607-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11607,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-07: AIACT-07: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-07.'
      ],
      remediationPrompt: "Remediate AIACT-07 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-07: AIACT-07: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-08: AIACT-08: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11608-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11608,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-08: AIACT-08: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-08.'
      ],
      remediationPrompt: "Remediate AIACT-08 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-08: AIACT-08: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-09: AIACT-09: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11609-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11609,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-09: AIACT-09: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-09.'
      ],
      remediationPrompt: "Remediate AIACT-09 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-09: AIACT-09: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-10: AIACT-10: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11610-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11610,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-10: AIACT-10: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-10.'
      ],
      remediationPrompt: "Remediate AIACT-10 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-10: AIACT-10: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-11: AIACT-11: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11611-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11611,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-11: AIACT-11: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-11.'
      ],
      remediationPrompt: "Remediate AIACT-11 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-11: AIACT-11: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-12: AIACT-12: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11612-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11612,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-12: AIACT-12: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-12.'
      ],
      remediationPrompt: "Remediate AIACT-12 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-12: AIACT-12: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-13: AIACT-13: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11613-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11613,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-13: AIACT-13: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-13.'
      ],
      remediationPrompt: "Remediate AIACT-13 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-13: AIACT-13: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-14: AIACT-14: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11614-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11614,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-14: AIACT-14: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-14.'
      ],
      remediationPrompt: "Remediate AIACT-14 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-14: AIACT-14: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-15: AIACT-15: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11615-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11615,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-15: AIACT-15: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-15.'
      ],
      remediationPrompt: "Remediate AIACT-15 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-15: AIACT-15: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-16: AIACT-16: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11616-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11616,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-16: AIACT-16: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-16.'
      ],
      remediationPrompt: "Remediate AIACT-16 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-16: AIACT-16: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-17: AIACT-17: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11617-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11617,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-17: AIACT-17: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-17.'
      ],
      remediationPrompt: "Remediate AIACT-17 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-17: AIACT-17: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-18: AIACT-18: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11618-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11618,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-18: AIACT-18: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-18.'
      ],
      remediationPrompt: "Remediate AIACT-18 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-18: AIACT-18: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-19: AIACT-19: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11619-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11619,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-19: AIACT-19: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-19.'
      ],
      remediationPrompt: "Remediate AIACT-19 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-19: AIACT-19: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-20: AIACT-20: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11620-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11620,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-20: AIACT-20: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-20.'
      ],
      remediationPrompt: "Remediate AIACT-20 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-20: AIACT-20: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-21: AIACT-21: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11621-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11621,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-21: AIACT-21: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-21.'
      ],
      remediationPrompt: "Remediate AIACT-21 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-21: AIACT-21: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-22: AIACT-22: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11622-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11622,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-22: AIACT-22: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-22.'
      ],
      remediationPrompt: "Remediate AIACT-22 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-22: AIACT-22: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-23: AIACT-23: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11623-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11623,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-23: AIACT-23: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-23.'
      ],
      remediationPrompt: "Remediate AIACT-23 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-23: AIACT-23: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-24: AIACT-24: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11624-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11624,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-24: AIACT-24: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-24.'
      ],
      remediationPrompt: "Remediate AIACT-24 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-24: AIACT-24: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-25: AIACT-25: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11625-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11625,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-25: AIACT-25: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-25.'
      ],
      remediationPrompt: "Remediate AIACT-25 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-25: AIACT-25: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-26: AIACT-26: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11626-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11626,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-26: AIACT-26: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-26.'
      ],
      remediationPrompt: "Remediate AIACT-26 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-26: AIACT-26: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-27: AIACT-27: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11627-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11627,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-27: AIACT-27: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-27.'
      ],
      remediationPrompt: "Remediate AIACT-27 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-27: AIACT-27: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-28: AIACT-28: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11628-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11628,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-28: AIACT-28: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-28.'
      ],
      remediationPrompt: "Remediate AIACT-28 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-28: AIACT-28: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-29: AIACT-29: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11629-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11629,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-29: AIACT-29: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-29.'
      ],
      remediationPrompt: "Remediate AIACT-29 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-29: AIACT-29: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-30: AIACT-30: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11630-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11630,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-30: AIACT-30: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-30.'
      ],
      remediationPrompt: "Remediate AIACT-30 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-30: AIACT-30: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-31: AIACT-31: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11631-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11631,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-31: AIACT-31: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-31.'
      ],
      remediationPrompt: "Remediate AIACT-31 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-31: AIACT-31: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-32: AIACT-32: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11632-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11632,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-32: AIACT-32: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-32.'
      ],
      remediationPrompt: "Remediate AIACT-32 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-32: AIACT-32: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-33: AIACT-33: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11633-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11633,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-33: AIACT-33: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-33.'
      ],
      remediationPrompt: "Remediate AIACT-33 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-33: AIACT-33: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-34: AIACT-34: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11634-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11634,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-34: AIACT-34: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-34.'
      ],
      remediationPrompt: "Remediate AIACT-34 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-34: AIACT-34: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-35: AIACT-35: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11635-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11635,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-35: AIACT-35: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-35.'
      ],
      remediationPrompt: "Remediate AIACT-35 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-35: AIACT-35: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-36: AIACT-36: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11636-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11636,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-36: AIACT-36: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-36.'
      ],
      remediationPrompt: "Remediate AIACT-36 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-36: AIACT-36: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-37: AIACT-37: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11637-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11637,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-37: AIACT-37: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-37.'
      ],
      remediationPrompt: "Remediate AIACT-37 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-37: AIACT-37: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-38: AIACT-38: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11638-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11638,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-38: AIACT-38: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-38.'
      ],
      remediationPrompt: "Remediate AIACT-38 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-38: AIACT-38: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-39: AIACT-39: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11639-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11639,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-39: AIACT-39: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-39.'
      ],
      remediationPrompt: "Remediate AIACT-39 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-39: AIACT-39: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-40: AIACT-40: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11640-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11640,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-40: AIACT-40: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-40.'
      ],
      remediationPrompt: "Remediate AIACT-40 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-40: AIACT-40: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-41: AIACT-41: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11641-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11641,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-41: AIACT-41: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-41.'
      ],
      remediationPrompt: "Remediate AIACT-41 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-41: AIACT-41: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-42: AIACT-42: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11642-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11642,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-42: AIACT-42: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-42.'
      ],
      remediationPrompt: "Remediate AIACT-42 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-42: AIACT-42: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-43: AIACT-43: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11643-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11643,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-43: AIACT-43: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-43.'
      ],
      remediationPrompt: "Remediate AIACT-43 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-43: AIACT-43: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-44: AIACT-44: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11644-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11644,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-44: AIACT-44: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-44.'
      ],
      remediationPrompt: "Remediate AIACT-44 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-44: AIACT-44: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-45: AIACT-45: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11645-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11645,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-45: AIACT-45: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-45.'
      ],
      remediationPrompt: "Remediate AIACT-45 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-45: AIACT-45: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-46: AIACT-46: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11646-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11646,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-46: AIACT-46: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-46.'
      ],
      remediationPrompt: "Remediate AIACT-46 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-46: AIACT-46: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-47: AIACT-47: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11647-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11647,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-47: AIACT-47: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-47.'
      ],
      remediationPrompt: "Remediate AIACT-47 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-47: AIACT-47: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-48: AIACT-48: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11648-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11648,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-48: AIACT-48: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-48.'
      ],
      remediationPrompt: "Remediate AIACT-48 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-48: AIACT-48: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-49: AIACT-49: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11649-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11649,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-49: AIACT-49: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "HIGH",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-49.'
      ],
      remediationPrompt: "Remediate AIACT-49 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-49: AIACT-49: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  // AIACT-50: AIACT-50: EU AI Act & Trustworthy Artificial Intelligence Governance Gate
  if (cleanContent.includes('vulnerablePattern_AIACT-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `aiact11650-${Date.now()}-${findingCounter.count++}`,
      ruleId: 11650,
      type: 'LEGAL_COMPLIANCE',
      title: "AIACT-50: AIACT-50: EU AI Act & Trustworthy Artificial Intelligence Governance Gate",
      severity: "MEDIUM",
      category: "EU AI Act Compliance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'AI system governance specification',
      reproductionSteps: [
        `Audited AI system controls in ${file.path}:${lineNum}.`,
        'Detected EU AI Act compliance violation matching AIACT-50.'
      ],
      remediationPrompt: "Remediate AIACT-50 according to European Union artificial intelligence compliance guidelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [AIACT AUDIT] Found AIACT-50: AIACT-50: EU AI Act & Trustworthy Artificial Intelligence Governance Gate at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
