// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { z } from 'zod';

export const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED']);
export const StatusEnum = z.enum(['OPEN', 'ACCEPTED_RISK', 'RESOLVED']);
export const GateStatusEnum = z.enum(['PASSED', 'FAILED', 'WARNING']);
export const PillarTypeEnum = z.enum(['SECURITY', 'VIBEPOLISH', 'VIBECARE']);

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
  status: StatusEnum,
  owner: z.string().optional(),
  falsePositive: z.boolean().default(false),
});

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
  shipguardSolution: z.string(),
});

export type SeverityLevel = z.infer<typeof SeverityEnum>;
export type StatusLevel = z.infer<typeof StatusEnum>;
export type GateStatusLevel = z.infer<typeof GateStatusEnum>;
export type PillarType = z.infer<typeof PillarTypeEnum>;
export type Finding = z.infer<typeof FindingSchema>;
export type Project = z.infer<typeof ProjectSchema>;
export type SecurityRule = z.infer<typeof SecurityRuleSchema>;
export type UiRule = z.infer<typeof UiRuleSchema>;
