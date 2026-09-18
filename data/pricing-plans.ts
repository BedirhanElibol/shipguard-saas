import { z } from 'zod';

export const PricingPlanSchema = z.object({
  id: z.enum(['zelsis-core', 'shipguard-core', 'vibecare', 'zelsis-suite']),
  name: z.string(),
  priceMonthly: z.number(),
  priceAnnual: z.number(),
  description: z.string(),
  features: z.array(z.string()),
  isPopular: z.boolean().optional(),
  buttonText: z.string(),
  polarCheckoutUrl: z.string().optional(),
});

export type PricingPlanItem = z.infer<typeof PricingPlanSchema>;

export const ZELSIS_PRICING_PLANS: PricingPlanItem[] = [
  {
    id: 'zelsis-core',
    name: 'Zelsis Pro',
    priceMonthly: 19,
    priceAnnual: 15,
    isPopular: true,
    description: 'Comprehensive Security Pre-flight Checks, Secret Isolation, DB RLS rules & Claude Auto-Remediations.',
    features: [
      'Full Pre-flight Security Audit Taxonomy',
      'Real-time CI/CD GitHub & Vercel Release Gate',
      'One-click Claude & Cursor Auto-Fix Prompts',
      'Unlimited connected AI applications',
      'Priority 24/7 SLA Guarantee',
    ],
    buttonText: 'Select Zelsis Pro',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC',
  },
  {
    id: 'vibecare',
    name: 'Zelsis Enterprise',
    priceMonthly: 99,
    priceAnnual: 79,
    isPopular: false,
    description: 'Long-term lifecycle monitoring, Dependency CVE drifts, Cloud & LLM cost alerts, Multi-Org Security Gates.',
    features: [
      'Everything in Zelsis Pro',
      'Dedicated Parallel AST Scan Cluster',
      'Autonomous PR CI/CD Merge Blocker',
      'White-Label PDF Audit Reports & SOC 2 Dossiers',
      '1-Hour Priority SLA & Dedicated Solutions Architect',
    ],
    buttonText: 'Select Zelsis Enterprise',
    polarCheckoutUrl: 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od',
  },
];

export const SHIPGUARD_PRICING_PLANS = ZELSIS_PRICING_PLANS;
