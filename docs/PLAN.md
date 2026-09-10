# 🕵️‍♂️ SHIPGUARD / ZELSIS: COMPREHENSIVE INTERACTION, MODAL TRAP & STATE-MACHINE AUDIT MASTER PLAN
## Version 10.0.0 — Comprehensive Flaw Eradication & Interactive Resilience

> **Document Version:** 10.0.0-INTERACTION-TRAP-ERADICATION  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning Checkpoint)  
> **Target User Query:** "/orchestrate find these types of bugs"  
> **Author:** Master Orchestrator & Systems Architect  
> **Language Standard:** Strict 100% Native English in code, documentation, and technical specs  
> **Compliance Standard:** .agent/Project_Development_Guide.md (Zero AI Slop, WCAG 2.2 AA Accessibility, OWASP Top 10 Security Hardening)

---

## 1. Forensic Audit: Discovered Interaction Bugs & Traps

Through systematic AST analysis and state-machine inspection across all 24 routes and 45 components, we have identified **10 specific interaction bugs and traps** belonging to the exact same class of multi-step human interaction defects:

### 1.1 Modal & Drawer Traps (Missing Backdrop Click & Escape Dismissal)
1. **`components/layout/ConnectTargetModal.tsx`**:
   - *Bug:* The repository/target URL connection modal lacks backdrop click dismissal (`onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}`) and lacks a `keydown` Escape listener. Users clicking outside or pressing Escape are trapped.
2. **`components/findings/BulkFixModal.tsx`**:
   - *Bug:* The unified patch generator modal lacks backdrop click dismissal and lacks a `keydown` Escape listener.
3. **`components/FeaturedWork.tsx`**:
   - *Bug:* The case study preview modal on the landing page has an Escape listener but is missing the backdrop click dismissal handler on the outer overlay.
4. **`components/ProjectsView.tsx`**:
   - *Bug:* `isQuotaModalOpen` (Free Tier Project Limit Reached) modal has NO backdrop click handler and NO Escape key listener.
5. **`components/VibeCareView.tsx`**:
   - *Bug:* `showPdfGateModal` (White-Label PDF Certificate Gate) modal has NO backdrop click handler and NO Escape key listener.
6. **`components/ProjectSettingsView.tsx`**:
   - *Bug:* `isDeleteModalOpen` (GDPR Data Deletion Confirmation) modal has an Escape listener but is missing the backdrop click dismissal handler on the outer overlay.
7. **`components/layout/Sidebar.tsx`**:
   - *Bug:* Mobile drawer navigation menu has backdrop click, but lacks a window `Escape` key dismissal listener.
8. **`components/Navbar.tsx`**:
   - *Bug:* Mobile menu overlay on the landing page lacks a window `Escape` key dismissal listener.
9. **`components/layout/Header.tsx`**:
   - *Bug:* User Profile dropdown menu listens for `mousedown` outside, but lacks an `Escape` key listener for keyboard accessibility.

### 1.2 Countdown / Timer Deadlock in ScanRunnerView
10. **`components/ScanRunnerView.tsx`**:
    - *Bug:* After a scan completes, the banner displays `"Auto-opening report in {countdownSeconds}s..."` and counts down 3 -> 2 -> 1 -> 0. However, when `countdownSeconds === 0`, no effect actually invokes `onCompleteScanRef.current(scanResult)`. The UI remains stuck at `"Auto-opening report in 0s..."` indefinitely unless the user clicks the button manually.

### 1.3 Nested AuthModal Isolation in CheckoutView
11. **`components/checkout/CheckoutView.tsx`**:
    - *Bug:* When used standalone, `CheckoutView` renders an internal `AuthModal` that lacks the double-guard `isOpen={isInternalAuthModalOpen && !currentUser?.isLoggedIn}` and does not clean up `?auth` parameters upon closing.

---

## 2. Phase 2 Implementation Packages (Multi-Agent Roster)

In strict compliance with the `/orchestrate` protocol (Minimum 3 specialized agents executing upon user approval):

### Package 1: Modal & Overlay Universal Trap Eradication (`frontend-specialist`)
- **Target Files:**
  - `components/layout/ConnectTargetModal.tsx`
  - `components/findings/BulkFixModal.tsx`
  - `components/FeaturedWork.tsx`
  - `components/ProjectsView.tsx`
  - `components/VibeCareView.tsx`
  - `components/ProjectSettingsView.tsx`
  - `components/layout/Sidebar.tsx`
  - `components/Navbar.tsx`
  - `components/layout/Header.tsx`

### Package 2: Scanner Timer Auto-Transition & State Hardening (`backend-specialist`)
- **Target Files:**
  - `components/ScanRunnerView.tsx`
  - `components/checkout/CheckoutView.tsx`

### Package 3: Automated Simulation & Production Verification (`test-engineer`)
- **Target Actions:**
  - Create and run `scratch/test_all_ux_traps.py`.
  - TypeScript compilation (`npx tsc --noEmit`).
  - Production build (`npm run build`).
  - Synchronize to Desktop repo, commit, push to GitHub `origin main`, and verify live deployment on Vercel.

---

## 3. Verification & Acceptance Criteria
1. All modals, drawers, and popovers across the app must close on outside click and Escape key.
2. The ScanRunnerView countdown must cleanly and automatically transition to the audit report when reaching 0.
3. 100% Native English in code and commit messages.
4. Clean TypeScript compilation (0 errors) and Next.js build (24/24 routes).
5. Live production deployment verified.
