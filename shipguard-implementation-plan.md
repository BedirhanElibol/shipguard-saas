# Implementation Plan: ShipGuard - Pricing & B2B Checkout Enhancement

Refine ShipGuard's monetization flow with dedicated pricing data (`data/pricing-plans.ts`), dynamic query-param routing (`/checkout?plan=[id]&billing=[monthly|annual]`), and a sticky order summary checkout page layout.

---

## Data Structure (`data/pricing-plans.ts`)

```typescript
export interface PricingPlanItem {
  id: string;
  name: string;
  priceMonthly: number;
  priceAnnual: number; // per month billed annually
  description: string;
  features: string[];
  isPopular?: boolean;
  buttonText: string;
}

export const SHIPGUARD_PRICING_PLANS: PricingPlanItem[] = [
  {
    id: 'vibepolish',
    name: 'VibePolish',
    priceMonthly: 49,
    priceAnnual: 39,
    description: 'Focuses on UI/UX Anti-Cliché Audits, Design System Polish & Accessibility.',
    features: [
      '30 VibePolish UI Anti-Pattern Matrix Audit',
      'Negative Prompt Generator for Cursor / v0 / Lovable',
      'Accessibility & Contrast Scorecard',
      'Up to 5 connected AI applications',
    ],
    buttonText: 'Select VibePolish',
  },
  {
    id: 'shipguard-core',
    name: 'ShipGuard Core',
    priceMonthly: 129,
    priceAnnual: 99,
    isPopular: true,
    description: '23 Security Pre-flight Checks, Secret Isolation, DB RLS rules & Claude Auto-Remediations.',
    features: [
      'Full 23 Pre-flight Security Audit Taxonomy',
      'Real-time CI/CD GitHub & Vercel Release Gate',
      'One-click Claude & Cursor Auto-Fix Prompts',
      'Unlimited connected AI applications',
      'Priority 24/7 SLA Guarantee',
    ],
    buttonText: 'Select ShipGuard Core',
  },
  {
    id: 'vibecare',
    name: 'VibeCare Suite',
    priceMonthly: 249,
    priceAnnual: 199,
    description: 'Long-term lifecycle monitoring, Dependency CVE drifts, Cloud & LLM cost alerts.',
    features: [
      'Everything in ShipGuard Core',
      'LLM & Cloud Budget Guardrails ($50/80/100% caps)',
      'Automated Encrypted DR S3 Snapshots',
      'White-label Client Rescue PDF Audit Reports',
      'Dedicated Security Architect Consultation',
    ],
    buttonText: 'Select VibeCare Suite',
  },
];
```

---

## Architecture & Page Breakdown

```
data/
└── pricing-plans.ts                  # Dedicated pricing data mapping 3 pillars (VibePolish, ShipGuard Core, VibeCare Suite)

components/
├── ui/
│   └── pricing.tsx                   # Interactive 3-tier pricing component with Framer Motion, confetti on annual toggle, and NumberFlow counters
└── checkout/
    └── CheckoutView.tsx              # High-trust B2B checkout layout with Invoice Form (Left) & Sticky Order Summary (Right)

app/
└── checkout/page.tsx                 # Dynamic route reading `?plan=[id]&billing=[monthly|annual]` URL query parameters
```

---

## Step-by-Step Implementation Roadmap

1. Create `data/pricing-plans.ts` with strict TypeScript types for VibePolish ($49/39), ShipGuard Core ($129/99), and VibeCare Suite ($249/199).
2. Refactor `components/ui/pricing.tsx` to handle URL query navigation `/checkout?plan=[id]&billing=[monthly|annual]`.
3. Create `app/checkout/page.tsx` and `components/checkout/CheckoutView.tsx` with high-trust B2B left invoice form and right sticky order summary.
4. Verify complete build with `npx next build` and test server output.
