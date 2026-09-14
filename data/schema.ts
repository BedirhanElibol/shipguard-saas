import { z } from 'zod';

export const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED']);
export const StatusEnum = z.enum(['OPEN', 'ACCEPTED_RISK', 'RESOLVED']);
export const GateStatusEnum = z.enum(['PASSED', 'FAILED', 'WARNING']);
export const PillarTypeEnum = z.enum(['SECURITY', 'VIBEPOLISH', 'VIBECARE', 'LEGAL_COMPLIANCE', 'INFRA_DATABASE']);

export const FindingSchema = z.object({
  id: z.string(),
  ruleId: z.number(),
  type: PillarTypeEnum,
  title: z.string(),
  severity: SeverityEnum,
  category: z.string(),
  filePath: z.string(),
  lineRange: z.string(),
  snippet: z.string(),
  reproductionSteps: z.array(z.string()),
  remediationPrompt: z.string(),
  diffPatch: z.string().optional(),
  status: StatusEnum,
  owner: z.string().optional(),
  falsePositive: z.boolean().default(false),
});

export interface ScanHistoryItem {
  id: string;
  date: string;
  target: string;
  score: number;
  gateStatus: 'PASSED' | 'FAILED' | 'WARNING';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  duration: string;
  triggeredBy: string;
}

export const ProjectSchema = z.object({
  id: z.string(),
  name: z.string(),
  repoUrl: z.string(),
  githubToken: z.string().optional(),
  previewUrl: z.string().optional(),
  framework: z.string(),
  providers: z.array(z.string()),
  lastScanAt: z.string(),
  readinessScore: z.number().min(0).max(100),
  gateStatus: GateStatusEnum,
  criticalCount: z.number(),
  highCount: z.number(),
  mediumCount: z.number(),
  lowCount: z.number(),
  uiClicheCount: z.number(),
  findings: z.array(FindingSchema),
  scanHistory: z.array(z.any()).optional(),
});

export const SecurityRuleSchema = z.object({
  id: z.number(),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  owaspTag: z.string(),
  riskLevel: SeverityEnum,
  description: z.string(),
  verificationControl: z.string(),
  claudePrompt: z.string(),
});

export const UiRuleSchema = z.object({
  id: z.number(),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  clichePattern: z.string(),
  whyAiDoesIt: z.string(),
  zelsisSolution: z.string().optional(),
  shipguardSolution: z.string().optional(),
});

export const ComplianceRuleSchema = z.object({
  id: z.number(),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  legalFramework: z.string(),
  riskLevel: SeverityEnum,
  penaltyExposure: z.string(),
  description: z.string(),
  verificationControl: z.string(),
  remediationPrompt: z.string(),
});

export const InfraRuleSchema = z.object({
  id: z.number(),
  code: z.string(),
  title: z.string(),
  category: z.string(),
  targetStack: z.string(),
  riskLevel: SeverityEnum,
  description: z.string(),
  verificationControl: z.string(),
  remediationPrompt: z.string(),
  sampleDiff: z.string().optional(),
});

export type SeverityLevel = z.infer<typeof SeverityEnum>;
export type StatusLevel = z.infer<typeof StatusEnum>;
export type GateStatusLevel = z.infer<typeof GateStatusEnum>;
export type PillarType = z.infer<typeof PillarTypeEnum>;
export type Finding = z.infer<typeof FindingSchema>;
export type Project = z.infer<typeof ProjectSchema>;
export type SecurityRule = z.infer<typeof SecurityRuleSchema>;
export type UiRule = z.infer<typeof UiRuleSchema>;
export type ComplianceRule = z.infer<typeof ComplianceRuleSchema>;
export type InfraRule = z.infer<typeof InfraRuleSchema>;

