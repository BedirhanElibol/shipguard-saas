# 🛡️ SHIPGUARD SAAS: SUBSCRIPTION VALIDITY & DURATION COUNTDOWN ARCHITECTURE PLAN
## Version 7.0.0 — Comprehensive Multi-Touchpoint Subscription Countdown & Renewal Visibility

> **Document Version:** 7.0.0-SUBSCRIPTION-UX-ARCHITECTURE  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning Checkpoint)  
> **Target User Query:** `"/orchestrate süresinin ne kadar kaldığını nerede görüyor kullanıcı"`  
> **Author:** Project Planner & Systems Architect  
> **Language Standard:** Strict 100% Native English in all code, documentation, interfaces, and UI copy  
> **Compliance Standard:** `.agent/Proje_Gelistirme_Rehberi.md` (Zero AI Slop, WCAG 2.2 AA Accessibility, OWASP Security Hardening)

---

## 1. Executive Summary & Problem Analysis

### 1.1 Context & User Query
A frequent and fundamental question in SaaS user workflows is: **"Where does the user see how much time is left on their subscription / plan validity?"** (`"/orchestrate süresinin ne kadar kaldığını nerede görüyor kullanıcı"`).

When developers and engineering teams subscribe to ShipGuard (or activate a Pro / Enterprise license), ambient visibility of their subscription duration is critical for:
1. **Predictability:** Knowing when the next billing cycle will trigger without having to search through settings.
2. **Operational Continuity:** Ensuring CI/CD gate checks and automated security audits do not fail unexpectedly due to quiet subscription expiration.
3. **Transparency & Trust:** Eliminating surprise renewals by providing real-time countdowns across daily application workflows.

### 1.2 Current State Audit & Friction Points

An exhaustive audit of the existing ShipGuard codebase reveals that subscription validity information is severely hidden, fragmented, or missing from primary navigation surfaces:

| Surface / Component | Current Implementation | Usability & Product Defect |
| :--- | :--- | :--- |
| **Header User Profile Dropdown**<br>([`components/layout/Header.tsx`](file:///C:/Users/Bedirhan/.gemini/antigravity/worktrees/newday/evaluate_app_deployment_readiness/components/layout/Header.tsx#L239-L245)) | Shows only a static text badge: `Status: Pro Plan - Active` with a pulsing green dot. | **Critical Omission.** No expiration date, no remaining day countdown, and no indication of renewal timing. This is the first place users click when checking their account status. |
| **Sidebar User Footer**<br>([`components/layout/Sidebar.tsx`](file:///C:/Users/Bedirhan/.gemini/antigravity/worktrees/newday/evaluate_app_deployment_readiness/components/layout/Sidebar.tsx#L190-L201)) | Displays only user name and a static pill: `Pro Plan` or `Free Plan`. | **Zero Ambient Awareness.** Users spend 95% of their session looking at the sidebar navigation, yet there is zero visual feedback on whether 2 days or 300 days remain on their active tier. |
| **Settings Billing Tab**<br>([`components/ProjectSettingsView.tsx`](file:///C:/Users/Bedirhan/.gemini/antigravity/worktrees/newday/evaluate_app_deployment_readiness/components/ProjectSettingsView.tsx#L391-L402)) | Displays: `Renews / Valid until: Oct 10, 2026`. | **Incomplete Cognitive Feedback.** Shows a raw calendar date string without a computed countdown (e.g. `28 days remaining`), without a visual billing cycle progress bar, and without urgency threshold coloring. |
| **Checkout Modal / View**<br>([`components/checkout/CheckoutView.tsx`](file:///C:/Users/Bedirhan/.gemini/antigravity/worktrees/newday/evaluate_app_deployment_readiness/components/checkout/CheckoutView.tsx#L380)) | Text snippet: `Valid / renews on: Oct 10, 2026. You do not need to re-purchase this plan.` | **Isolated Context.** Only visible if the user navigates to the checkout/upgrade page, which existing active subscribers rarely visit. |
| **Lifecycle Banner**<br>([`components/dashboard/LifecycleBanner.tsx`](file:///C:/Users/Bedirhan/.gemini/antigravity/worktrees/newday/evaluate_app_deployment_readiness/components/dashboard/LifecycleBanner.tsx#L58-L85)) | Displays an alert banner only when `daysLeft <= 3`. | **Reactive, Not Proactive.** Invisible during standard operation (>3 days). Furthermore, its days calculation logic is isolated and duplicated rather than shared. |

### 1.3 Target Architecture Objective
Transform subscription validity from a hidden, raw date into an **ambient, informative, multi-tier UI system**:
1. **Centralized Domain Logic (`lib/subscription-utils.ts`):** Single source of truth for date calculations, remaining days, cycle percentages, urgency states, and semantic badge palettes.
2. **Touchpoint A (Header Dropdown):** Dedicated, high-contrast Subscription Validity Card with remaining countdown, renewal date, and direct manage button.
3. **Touchpoint B (Sidebar Footer):** Compact, non-intrusive countdown pill (`28d left`, `3d left`, `Renews today`) next to the plan badge on both desktop and mobile drawer.
4. **Touchpoint C (Settings Billing Card):** Rich renewal dashboard widget featuring days remaining, renewal date, visual billing cycle progress bar, and one-click Polar portal management.
5. **Anti-Slop Compliance:** Strict adherence to `.agent/Proje_Gelistirme_Rehberi.md` (no generic purple gradients, semantic colors, high contrast typography, accessible progressbars, and 44px min touch targets).

---

## 2. Proposed UI Architecture & Touchpoints

```
                                  ┌──────────────────────────────────────────────┐
                                  │   UserProfile State (useDashboardState.ts)   │
                                  │   tier, expiresAt, status, billingCycle     │
                                  └──────────────────────┬───────────────────────┘
                                                         │
                                                         ▼
                                  ┌──────────────────────────────────────────────┐
                                  │     lib/subscription-utils.ts (DRY Logic)     │
                                  │  - getSubscriptionValidityInfo(user)        │
                                  │  - getRemainingDays(expiresAt)               │
                                  │  - formatRenewalDate(expiresAt)              │
                                  │  - getBillingCycleProgress(expiresAt, cycle) │
                                  │  - getSubscriptionStatusColors(status)      │
                                  └──────┬───────────────┬───────────────┬───────┘
                                         │               │               │
                 ┌───────────────────────┘               │               └───────────────────────┐
                 ▼                                       ▼                                       ▼
    ┌─────────────────────────┐             ┌─────────────────────────┐             ┌─────────────────────────┐
    │      TOUCHPOINT A       │             │      TOUCHPOINT B       │             │      TOUCHPOINT C       │
    │ Header Profile Dropdown │             │  Sidebar Footer & Drawer │             │ Project Settings View   │
    │                         │             │                         │             │                         │
    │ • Plan Badge & Dot      │             │ • Desktop User Card     │             │ • Days Remaining Banner │
    │ • "28 days remaining"   │             │ • Compact "28d left"    │             │ • Visual Progress Bar   │
    │ • "Renews Oct 10, 2026" │             │ • Urgency Color Coding  │             │ • Exact Renewal Date    │
    │ • Direct Manage Action  │             │ • Mobile Drawer Synced  │             │ • Polar Portal Deep Link│
    └─────────────────────────┘             └─────────────────────────┘             └─────────────────────────┘
```

---

### 2.1 Touchpoint D: Centralized Utility Foundation (`lib/subscription-utils.ts`)

To eliminate code duplication, prevent timezone bugs, and enforce consistent rounding rules across the entire platform, all subscription calculations will reside in a new dedicated module: `lib/subscription-utils.ts`.

#### 2.1.1 TypeScript Interfaces & Contract
```ts
export type SubscriptionUrgency = 'healthy' | 'warning' | 'critical' | 'past_due' | 'expired' | 'lifetime' | 'free';

export interface SubscriptionValidityInfo {
  tier: 'Free' | 'Pro' | 'Enterprise';
  urgency: SubscriptionUrgency;
  daysRemaining: number | null;
  formattedRenewalDate: string;
  isExpiringSoon: boolean;      // <= 7 days
  isCritical: boolean;          // <= 2 days
  isPastDue: boolean;
  isLifetime: boolean;
  isFree: boolean;
  countdownLabel: string;       // e.g. "28 days remaining", "3 days left", "Renews today", "Expired"
  compactLabel: string;         // e.g. "28d left", "3d left", "Today", "Due", "Free"
  cycleProgressPercent: number; // 0 - 100% of the elapsed billing cycle
  badgeColors: {
    bg: string;
    border: string;
    text: string;
    dot: string;
    bar: string;
  };
}
```

#### 2.1.2 Business Logic & Edge-Case Rules
1. **Remaining Days Calculation:**
   - Use UTC-normalized timestamps or millisecond delta: `Math.ceil((expiryTime - Date.now()) / (1000 * 60 * 60 * 24))`.
   - If delta is negative, classify as `expired` or `past_due` rather than returning negative numbers.
   - If `daysLeft === 0`, return label `"Renews today"`, compact label `"Today"`.
   - If `daysLeft === 1`, return label `"1 day remaining"`, compact label `"1d left"`.
2. **Billing Cycle Progress Bar:**
   - Based on standard 30-day monthly cycle (or 365-day annual cycle when `user.billingCycle === 'annual'`).
   - `cycleProgress = Math.max(0, Math.min(100, Math.round(((totalDays - daysRemaining) / totalDays) * 100)))`.
   - Provides a visual metric showing how far along the user is in their current billing period.
3. **Color Tokens (UI Anti-Slop Strict Standards):**
   - **Healthy (> 7 days remaining):**
     - Background: `bg-emerald-500/10` | Border: `border-emerald-500/25` | Text: `text-emerald-400` | Dot: `bg-emerald-400` | Bar: `bg-emerald-500`
   - **Warning (3 to 7 days remaining):**
     - Background: `bg-amber-500/10` | Border: `border-amber-500/30` | Text: `text-amber-300` | Dot: `bg-amber-400` | Bar: `bg-amber-500`
   - **Critical (0 to 2 days remaining):**
     - Background: `bg-rose-500/10` | Border: `border-rose-500/30` | Text: `text-rose-400` | Dot: `bg-rose-400 animate-pulse` | Bar: `bg-rose-500`
   - **Past Due / Grace Period:**
     - Background: `bg-rose-950/40` | Border: `border-rose-500/40` | Text: `text-rose-300` | Dot: `bg-rose-500 animate-ping` | Bar: `bg-rose-600`
   - **Free Tier:**
     - Background: `bg-white/5` | Border: `border-white/10` | Text: `text-[#A1A1AA]` | Dot: `bg-[#71717A]` | Bar: `bg-white/20`
4. **Defensive Parsing:**
   - Safe parsing of ISO strings with `isNaN(new Date(expiresAt).getTime())` fallback.
   - If `expiresAt` is missing or invalid, gracefully treat active Pro/Enterprise as `"Active Monthly Subscription"` without throwing runtime errors.

---

### 2.2 Touchpoint A: Header Profile Dropdown (`components/layout/Header.tsx`)

#### Current Deficiency:
The user menu in `components/layout/Header.tsx` (lines 239-245) displays:
```tsx
<div className="px-3 py-2 bg-white/[0.03] rounded-lg my-1 flex items-center justify-between border border-white/5">
  <span className="text-[11px] text-[#A1A1AA]">Status:</span>
  <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
    {user.tier === 'Free' ? 'Free Tier - Active' : `${user.tier} Plan - Active`}
  </span>
</div>
```

#### Proposed Enhancement:
Replace the generic single-line box with a **Structured Subscription Validity Card**:
1. **Header Row:**
   - Current tier badge (`Pro Plan` or `Enterprise Plan`) alongside an active pulse dot.
   - Status tag: `Active`, `Expiring Soon`, or `Grace Period`.
2. **Countdown & Validity Row:**
   - Prominent countdown metric: `<span className="font-mono font-bold text-white text-xs">28 days remaining</span>`.
   - Subtle subline: `<span className="text-[10px] text-[#A1A1AA]">Renews on Oct 10, 2026</span>`.
3. **Mini Progress Indicator:**
   - Sleek 2px progress bar illustrating cycle position.
4. **Direct Management Link:**
   - Small `"Manage"` text button linked to Polar customer portal or navigating directly to Settings Billing.

```
┌─────────────────────────────────────────────────────────┐
│ [Avatar] Bedirhan Elibol                                │
│          developer@shipguard.dev                        │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ PRO PLAN                              ● Active      │ │
│ │ 28 days remaining                                   │ │
│ │ Renews Oct 10, 2026 • Monthly Cycle                 │ │
│ │ [═════════════════════════════════════════] (40%)   │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ⚡ Upgrade Plan                                         │
│ ⚙️ Profile & Settings (Billing)                          │
│ 🚪 Sign Out                                             │
└─────────────────────────────────────────────────────────┘
```

---

### 2.3 Touchpoint B: Sidebar User Footer (`components/layout/Sidebar.tsx`)

#### Current Deficiency:
The user card in `components/layout/Sidebar.tsx` (lines 190-201) displays:
```tsx
<div className="mt-0.5">
  <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${...}`}>
    {user.tier === 'Free' ? 'Free Plan' : `${user.tier} Plan`}
  </span>
</div>
```

#### Proposed Enhancement:
Embed an ambient, space-efficient **Validity Pill** right next to the plan badge:
1. **Visual Balance:**
   - Next to `Pro Plan`, display `•` followed by `<span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/25">28d left</span>`.
   - When `<= 7 days`, color shifts automatically to amber (`3d left`).
   - When `<= 2 days`, shifts to rose (`1d left` / `Renews today`).
2. **Tooltip & Accessibility:**
   - Add native HTML `title` and `aria-label`: `"Pro Plan - 28 days remaining. Renews Oct 10, 2026"`.
3. **Mobile Drawer Parity:**
   - Ensure the mobile drawer footer (`renderFooter()`) exhibits identical countdown fidelity so mobile phone and tablet users get the exact same awareness.

```
┌───────────────────────────────────────────────────────┐
│ [Avatar]  Alex Morgan                                 │
│           [Pro Plan] [28d left]                   [⚙] │
└───────────────────────────────────────────────────────┘
```

---

### 2.4 Touchpoint C: Project Settings Billing View (`components/ProjectSettingsView.tsx`)

#### Current Deficiency:
Lines 390-402 of `ProjectSettingsView.tsx` render:
```tsx
{user?.tier && user.tier !== 'Free' && (
  <div className="flex items-center gap-1.5 mt-1 text-xs text-[#A1A1AA]">
    <Calendar size={13} className="text-emerald-400 shrink-0" />
    <span>
      Renews / Valid until:{' '}
      <strong className="text-white font-mono">
        {user?.expiresAt
          ? new Date(user.expiresAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
          : 'Monthly Active'}
      </strong>
    </span>
  </div>
)}
```

#### Proposed Enhancement:
Upgrade this into a **Rich Subscription Lifecycle Widget**:
1. **Highlight Hero Card:**
   - Display a high-visibility badge block:
     - Left: Days remaining countdown with large font: `<div className="text-2xl font-mono font-black text-white">28 <span className="text-sm font-sans font-medium text-[#A1A1AA]">Days Left</span></div>`.
     - Right: Cycle status indicator (`Active`, `Renews Automatically on Oct 10, 2026`).
2. **Visual Billing Cycle Progress Bar:**
   - Accessible progress bar:
     ```tsx
     <div className="flex flex-col gap-1.5 mt-3">
       <div className="flex items-center justify-between text-[11px] font-mono text-[#A1A1AA]">
         <span>Current Billing Cycle</span>
         <span>{validity.cycleProgressPercent}% Elapsed</span>
       </div>
       <div 
         role="progressbar" 
         aria-valuenow={validity.cycleProgressPercent} 
         aria-valuemin={0} 
         aria-valuemax={100}
         aria-label="Billing cycle duration elapsed"
         className="w-full h-2 bg-white/5 rounded-full overflow-hidden border border-white/10"
       >
         <div 
           className={`h-full transition-all duration-500 ${validity.badgeColors.bar}`}
           style={{ width: `${validity.cycleProgressPercent}%` }}
         />
       </div>
     </div>
     ```
3. **Action Integration:**
   - Prominent "Manage Subscription at Polar" button (`https://polar.sh/purchases`).
   - "Sync Subscription" button to force re-verification against the Polar webhook registry.
   - Upgrade / Tier adjustment controls.

---

## 3. Implementation Work Breakdown (Specialist Agent Assignments)

Following the autonomous agent workflow, execution in Phase 2 will be distributed across 3 specialized agents:

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Phase 2 Execution Workstream                       │
├───────────────────────┬────────────────────────┬───────────────────────┤
│  frontend-specialist  │   security-auditor     │     test-engineer     │
├───────────────────────┼────────────────────────┼───────────────────────┤
│ • lib/subscription-   │ • Date Injection Audit │ • Unit Test Suite     │
│   utils.ts creation   │ • Timezone & Leap Year │   (edge-cases & math) │
│ • Header Dropdown Card│ • XSS & PII Validation │ • TypeScript Compile  │
│ • Sidebar Footer Pill │ • Polar Link Hardening │ • Next.js Prod Build  │
│ • Settings Renewal UI │ • Cookie/Storage Check │ • Headless Browser QA │
└───────────────────────┴────────────────────────┴───────────────────────┘
```

### 3.1 Task Group 1: `frontend-specialist`
- **Module 1: Create Centralized Utility (`lib/subscription-utils.ts`)**
  - Implement `getSubscriptionValidity(user: UserProfile | null | undefined): SubscriptionValidityInfo`.
  - Implement `getRemainingDays(expiresAt?: string | null): number | null`.
  - Implement `formatRenewalDate(expiresAt?: string | null): string`.
  - Implement `getBillingCycleProgress(expiresAt?: string | null, cycle?: string): number`.
  - Implement `getSubscriptionStatusColors(urgency: SubscriptionUrgency)`.
- **Module 2: Header Profile Dropdown Integration (`components/layout/Header.tsx`)**
  - Replace static `Status: Pro Plan - Active` box with the rich `SubscriptionValidityCard`.
  - Ensure clean layout that does not clip on mobile screens or overflow the dropdown.
  - Implement keyboard navigation accessibility (`tabindex`, `aria-label`).
- **Module 3: Sidebar Footer Integration (`components/layout/Sidebar.tsx`)**
  - Update both Desktop persistent sidebar footer and Mobile slide-over drawer footer.
  - Add compact validity pill (`28d left`, `3d left`) next to plan badge.
  - Add hover tooltip (`title`) with exact date and remaining duration.
- **Module 4: Project Settings Billing View (`components/ProjectSettingsView.tsx`)**
  - Replace single-line calendar text with the comprehensive renewal card.
  - Add remaining days counter, cycle progress bar, and formatted renewal date.
  - Retain "Sync Subscription" and "Manage at Polar" action buttons with min 44px touch targets.
- **Module 5: Refactor Dashboard Banner (`components/dashboard/LifecycleBanner.tsx`)**
  - Refactor `LifecycleBanner.tsx` to consume `lib/subscription-utils.ts`, removing duplicate `Math.ceil` logic.

### 3.2 Task Group 2: `security-auditor`
- **Security Check 1: Safe Date Parsing & ReDoS Defense**
  - Ensure date parsing functions reject malformed strings, prototype-polluting payloads, or arbitrary inputs without throwing unhandled exceptions.
  - Test bounds: epoch 0, distant future dates (`2099-12-31`), negative timestamps, and non-ISO strings.
- **Security Check 2: Zero PII or Sensitive Metadata Leak**
  - Verify that no Polar customer IDs, internal webhook tokens, or payment card details are exposed in the DOM or client-side validity objects.
- **Security Check 3: External Link Hardening**
  - Audit all links pointing to `https://polar.sh/purchases` to guarantee strict inclusion of `target="_blank"` and `rel="noopener noreferrer"` to prevent tabnabbing.
- **Security Check 4: Local Storage & Cookie Integrity**
  - Verify that `user.expiresAt` stored in `localStorage` (`zelsis_user` / `shipguard_user`) cannot be trivially tampered with to grant persistent unauthorized access (server-side verification remains authoritative via `/api/v1/subscription/sync`).

### 3.3 Task Group 3: `test-engineer`
- **Test Suite 1: Automated Unit Testing (`scratch/test_subscription_validity.py`)**
  - Test Case A: User with 30 days remaining -> returns `28-30 days remaining`, `healthy` urgency, green colors.
  - Test Case B: User with 5 days remaining -> returns `5 days remaining`, `warning` urgency, amber colors.
  - Test Case C: User with 1 day remaining -> returns `1 day remaining`, `critical` urgency, rose colors.
  - Test Case D: User expiring today -> returns `Renews today`, `critical` urgency.
  - Test Case E: User with past expiration date -> returns `Expired`, auto-downgrades.
  - Test Case F: Free tier user -> returns `Free Tier`, no countdown pill, neutral colors.
  - Test Case G: Enterprise user with annual cycle -> computes 365-day progress correctly.
  - Test Case H: `expiresAt` is `null` or `undefined` -> returns fallback `"Active Monthly Subscription"`.
- **Test Suite 2: Static Analysis & Build Verification**
  - Execute `npx tsc --noEmit` to confirm zero TypeScript compilation errors.
  - Execute `npm run build` to verify clean static generation of all 18 routes.
- **Test Suite 3: Cross-Device UI QA**
  - Verify layout responsiveness across Desktop (1440px), Tablet (768px), and Mobile (375px).
  - Verify touch targets strictly meet >= 44x44px per WCAG 2.2 AA.
  - Verify dark theme contrast ratios meet >= 4.5:1.

---

## 4. Acceptance Criteria & Verification Protocol

### 4.1 Functional Acceptance Criteria
1. **Universal Visibility:** An active subscriber can see how many days remain on their plan from **any screen** in the application without navigating away:
   - Within 1 second of looking at the sidebar (`28d left`).
   - Within 1 click by opening the Header profile dropdown (`28 days remaining • Renews Oct 10, 2026`).
   - In full detail under `Settings -> Billing Tab` with a progress bar and renewal date.
2. **Urgency Thresholds:**
   - `> 7 days`: Displayed in Emerald (`text-emerald-400`, `bg-emerald-500/10`).
   - `3 to 7 days`: Displayed in Amber (`text-amber-300`, `bg-amber-500/10`).
   - `<= 2 days` or `today`: Displayed in Rose (`text-rose-400`, `bg-rose-500/10`) with a subtle pulse.
3. **Free & Guest Modes:**
   - Free users see `Free Plan` without confusing countdown numbers or zero-day warnings.
   - Guest developers see `Guest Mode` with clean sign-in CTA buttons.
4. **Accuracy & Synchronization:**
   - Days countdown matches real-time server timestamps.
   - Clicking "Sync Subscription" immediately re-fetches latest Polar status and updates the UI countdown without page reload.

### 4.2 Quality & Anti-Slop Acceptance Criteria (Per Guide)
1. **No Cliché Styling:**
   - No generic purple/blue neon gradients.
   - No meaningless decorative sparkles or magic wand icons.
   - Monospace typography used consistently for numbers and dates (`font-mono`).
2. **Accessibility (WCAG 2.2 AA):**
   - Minimum touch target >= 44x44px for all interactive buttons and triggers.
   - Progress bar contains full ARIA tags (`role="progressbar"`, `aria-valuenow`, `aria-valuemin`, `aria-valuemax`).
   - Color is not used as the sole indicator of state (text labels accompany color codes).
3. **Language Consistency:**
   - 100% Native English across all UI text, tooltips, ARIA labels, and log outputs.

---

## 5. Next Steps & Execution Command

Once this Phase 1 Plan is approved by the user, Phase 2 implementation can proceed immediately using the specialist agents:
1. `frontend-specialist`: Implement `lib/subscription-utils.ts`, `Header.tsx`, `Sidebar.tsx`, and `ProjectSettingsView.tsx`.
2. `security-auditor`: Audit input validation, external links, and storage privacy.
3. `test-engineer`: Run unit tests, TypeScript validation, production build, and live browser verification.
