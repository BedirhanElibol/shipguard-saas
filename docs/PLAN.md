# 🕵️‍♂️ SHIPGUARD / ZELSIS: AUTONOMOUS USER-JOURNEY SIMULATION & FLAW ERADICATION MASTER PLAN
## Version 9.0.0 — Comprehensive Multi-Agent State-Machine Audit & Flaw Prevention

> **Document Version:** 9.0.0-AUTONOMOUS-JOURNEY-SIMULATION  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning Checkpoint)  
> **Target User Query:** "/orchestrate neden bunları tek tek ben buluyorum"  
> **Author:** Project Planner & Systems Architect  
> **Language Standard:** Strict 100% Native English in code, documentation, and technical specs  
> **Compliance Standard:** .agent/Proje_Gelistirme_Rehberi.md (Zero AI Slop, WCAG 2.2 AA Accessibility, OWASP Top 10 Security Hardening)

---

## 1. Root Cause Analysis: Why Did the User Have to Find These Manually?

### 1.1 The Static-Verification Gap
Previous verification suites focused on **unit-level and static structural criteria**:
- Did TypeScript compile (`npx tsc --noEmit`)? -> YES (0 errors)
- Did Next.js build all routes (`npm run build`)? -> YES (24/24 static/server routes)
- Did all endpoints return HTTP 200 OK? -> YES (all routes OK)

**The Defect:** Static tests and HTTP status checks do NOT simulate **human state-transition journeys** across multiple routes over time. For example:
- *Step 1:* User logs in on `/dashboard` -> state stored in `localStorage`.
- *Step 2:* User navigates to `/` (Landing). Does the landing header recognize the user? (Previously NO, it showed static "Sign In").
- *Step 3:* User clicks "Sign In" from the landing page. It navigates to `/dashboard?auth=signin`.
- *Step 4:* Does the dashboard notice the user is already logged in? (Previously NO, it opened the sign-in modal over the active session).
- *Step 5:* Is the URL query parameter cleaned up? (Previously NO, it lingered indefinitely).

### 1.2 The Paradigm Shift: Autonomous User-Journey Simulation
We will no longer rely solely on build/static tests. We are implementing an **Autonomous User-Journey State-Machine Simulation** where agents programmatically traverse, stress-test, and validate all possible user flows, ensuring that zero interaction bugs reach the user.

---

## 2. The 6 Core User-Journey Simulation Suites

### Suite 1: Cross-Route State Handshake Journey
- Validate that navigation across `/`, `/landing`, `/dashboard`, `/checkout`, `/privacy`, `/terms`, `/cookies` maintains 100% synchronized auth and user profile state.
- Ensure that entering any route with query params (`?auth=...`, `?nav=...`, `?checkout_id=...`) consumes the param once and sanitizes the URL without lingering or causing modal locks.

### Suite 2: Authentication & Session Lifecycle Journey
- Guest Mode: Landing and Dashboard present flawless demo states with zero PII leaks.
- Sign In / Sign Up: Successful authentication smoothly transitions the entire application into authenticated mode.
- Logged-in State: Re-clicking any login/signup button or route parameter NEVER opens redundant auth modals.
- Sign Out: Full purge of `zelsis_user`, `shipguard_user`, license keys, and cookies; immediately resets all UI elements to clean guest mode.

### Suite 3: Repository Audit & Scanner Journey
- Input Edge Cases: Test URLs with prefixes (`https://`, `http://`), trailing slashes (`/`), repository suffixes (`.git`), and shorthand (`org/repo`).
- Non-Destructive Projects: Scanning external repositories must create a new project object (`proj-${Date.now()}`) without mutating the demo showcase starter.
- Scanner Resilience: Failed scans, network timeouts, or rate limits must render actionable, clean error states without infinite spinners.

### Suite 4: Subscription, Pricing & Checkout Gate Journey
- Plan Selection: Verify clicking "Get Started" or "Upgrade" from Pricing on `/` or inside Dashboard correctly passes the selected plan (`zelsis-core` vs `vibecare`) to Checkout.
- Polar Checkout Return: Returning from Polar (`?checkout_id=...`) triggers server-side verification without exposing client-side bypasses.
- Ambient Countdown Visibility: Verify `lib/subscription-utils.ts` accurately computes remaining days, renewal dates, and urgency color coding in Header, Sidebar, and Settings.

### Suite 5: UI Interactivity, Modals & Drawer Resilience Journey
- All application modals (AuthModal, StripeCheckoutModal, RuleConfig, PenTest, Badge, KB) must have:
  1. Responsive, visible 'X' close button (min 44x44px touch target).
  2. Backdrop / overlay click-to-close behavior.
  3. Keyboard `Escape` key dismissal listener.
  4. Non-locking layout (no stuck overlays).

### Suite 6: Edge Case, Corrupted Storage & 404 Recovery Journey
- Corrupted or outdated localStorage entries automatically self-heal and fallback to defaults without throwing uncaught exceptions.
- 404 page provides direct, functional navigation back to `/dashboard` and `/`.
- Multi-tab synchronization via `window.addEventListener('storage')`.

---

## 3. Multi-Agent Orchestration Roster (Phase 2 Parallel Execution)

In compliance with the /orchestrate protocol (Minimum 3 specialized agents required):

- **Agent 1: `project-planner`**: Master State-Machine & Flow Mapping (`docs/PLAN.md`).
- **Agent 2: `frontend-specialist`**: UI Interaction Resilience, modal backdrop/escape handlers across all views.
- **Agent 3: `backend-specialist`**: Route query sanitization, API edge cases, and session persistence hardening.
- **Agent 4: `test-engineer`**: Automated User-Journey Simulator Script (`scratch/simulate_all_user_journeys.py`).

---

## 4. Verification Plan

1. Execute `python scratch/simulate_all_user_journeys.py` (Asserting all 6 journey suites).
2. Execute `npx tsc --noEmit` (0 errors).
3. Execute `npm run build` (24/24 static & dynamic routes).
4. Verify live routes on `https://shipguard-saas.vercel.app`.
