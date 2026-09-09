# 🛡️ SHIPGUARD SAAS: MASTER BUG, USABILITY & LOGIC REMEDIATION PLAN
## Version 6.0.0 — Zero-Friction Production Hardening & Bug Elimination

> **Document Version:** 6.0.0-STABILITY-AUDIT  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning — Socratic Gate Checkpoint)  
> **Author:** Project Planner & Systems Architect  
> **Language Standard:** Strict 100% Native English in all code, rules, catalogs, schemas, and UI text  

---

## 1. Executive Summary: Exhaustive Audit Findings

Following the user's directive (`/orchestrate bug , kullanım veya mantık hatası kaldı mı`), a deep static analysis across all 18 routes, hooks, state engines, and authentication flows was conducted. 

While core release gates and TypeScript compilation are 100% passing, **5 concrete logic bugs, privacy leaks, and usability friction points** were identified:

### 🔴 Finding 1: Personal PII & Email Leak in Polar Checkout Return (`hooks/useDashboardState.ts`)
- **Severity:** `CRITICAL` (Data Privacy & Auth Leak)
- **File:** `hooks/useDashboardState.ts:162-163`
- **Root Cause:** When returning from Polar checkout (`?status=success` or `?checkout_id=`), if no active session existed in `localStorage`, the code fell back to hardcoded developer credentials:
  ```ts
  const userEmail = currentUserObj?.email || 'bedirelibol7@gmail.com';
  const userName = currentUserObj?.name || 'Bedirhan Elibol';
  ```
- **Impact:** Any anonymous visitor or paying customer arriving on `/dashboard?status=success` was automatically logged in as Bedirhan Elibol with a personal Gmail address.
- **Remediation:** Safely fall back to `'subscriber@shipguard.dev'` and `'Pro Subscriber'` or require explicit sign-in before credential hydration.

### 🟡 Finding 2: False-Positive Dogfooding Lock on User Projects (`components/ScanRunnerView.tsx`)
- **Severity:** `HIGH` (Scanner Logic Flaw)
- **File:** `components/ScanRunnerView.tsx:81-83`
- **Root Cause:**
  ```ts
  project.name.toLowerCase().includes('shipguard') ||
  ['proj-nexus', 'proj-synthflow', 'proj-aura'].includes(project.id);
  ```
- **Impact:** If a real customer connects a GitHub repository that contains the substring `"shipguard"` in its name (e.g. `shipguard-bot`, `shipguard-integration`), `ScanRunnerView` mistakenly treats it as internal local self-audit and refuses to scan on production with: `⛔ Local workspace self-audit is available only in local development.`
- **Remediation:** Strictly identify local self-audits by `project.repoUrl === 'local' || project.id === 'proj-shipguard-self' || project.id === 'proj-preset-self'`.

### 🟡 Finding 3: Showcase Demo Project In-Place Mutation (`components/layout/Header.tsx`)
- **Severity:** `MEDIUM` (Usability & State Integrity)
- **File:** `components/layout/Header.tsx:63-76`
- **Root Cause:** When an anonymous guest types a new URL in the top search bar (e.g. `facebook/react`) and presses Enter, `Header.tsx` directly mutates `selectedProject.repoUrl` and `selectedProject.name` on `proj-saas-starter`.
- **Impact:** The curated 88/100 showcase template (`Next.js 15 SaaS Starter`) gets overwritten in memory and in `localStorage`, so guests can never return to the initial pristine demo without a full cache purge.
- **Remediation:** If the submitted URL does not match `selectedProject.repoUrl`, instantiate a new project or invoke `onAddNewProject` with a unique ID (`proj-${Date.now()}`), leaving the showcase demo uncorrupted.

### 🔵 Finding 4: Incomplete Storage & Key Clearance on Checkout Sign-Out (`app/checkout/page.tsx`)
- **Severity:** `LOW` (Storage Consistency)
- **File:** `app/checkout/page.tsx:62`
- **Root Cause:** When signing out on the `/checkout` page, only `localStorage.removeItem('shipguard_user')` was called, leaving `shipguard_license_key` active in storage.
- **Remediation:** Unify with `purgeShipguardStorage(true)` from `@/lib/storage`.

### 🔵 Finding 5: URL Query Parameter Synchronization (`hooks/useDashboardState.ts`)
- **Severity:** `LOW` (Usability & Deep Linking)
- **File:** `hooks/useDashboardState.ts:13-26`
- **Root Cause:** `searchParams.get('nav')` and `searchParams.get('auth')` were only read during initial state initialization (`useState`). Client-side transitions changing query parameters did not trigger navigation updates or open the AuthModal.
- **Remediation:** Add a reactive `useEffect` listening to `searchParams` to synchronize `activeNav` and `isAuthModalOpen`.

---

## 2. Phase 2 Specialist Work Breakdown (Minimum 3 Agents)

Once approved by the user, Phase 2 will execute with 3 specialist agents in parallel:

| Agent | Focus Area | Tasks |
| :--- | :--- | :--- |
| **`security-auditor`** | Auth & Storage Hardening | 1. Eliminate hardcoded PII in `useDashboardState.ts`.<br>2. Unify `purgeShipguardStorage` in `app/checkout/page.tsx`.<br>3. Verify zero secrets/PII across all client bundles. |
| **`frontend-specialist`** | State & UX Polish | 1. Fix showcase demo mutation in `Header.tsx` (spawn clean new project on search).<br>2. Add reactive `searchParams` listener in `useDashboardState.ts`.<br>3. Remove outdated dummy IDs (`proj-nexus`, etc.) in `ScanRunnerView.tsx`. |
| **`test-engineer`** | Automated Verification & E2E | 1. Create `scratch/test_bug_elimination.py` testing all 5 fixes.<br>2. Run `npx tsc --noEmit` and `npm run build`.<br>3. Sync to Desktop newday repo and push to GitHub `origin main`.<br>4. Run Playwright headless live browser QA. |

---

## 3. Acceptance Criteria & Verification Protocol

1. **Zero Hardcoded PII:** No developer personal emails or names in client state.
2. **Safe Project Names:** Projects with `"shipguard"` in name can be audited freely on production.
3. **Showcase Preservation:** Typing a URL in Header creates a new project; `Next.js 15 SaaS Starter` remains intact.
4. **Clean Compilation:** `npx tsc --noEmit` exits code 0 with 0 errors.
5. **Production Build:** `npm run build` succeeds for all 18 pages.
6. **100% Native English:** Zero Turkish strings in source code.
