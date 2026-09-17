# Master Orchestration Plan (v23.0.0)
## Autonomous Full-Stack User Journey Simulation, Defect Hunting & Production Hardening

### Executive Directive & Purpose
**Directive:** Complete autonomous relief for the user ("tukendim biraz da sen yardim et"). The AI orchestrator assumes full ownership of discovering, analyzing, and eradicating hidden flaws, rough edges, and friction points across the entire Zelsis platform without placing the cognitive burden on the user.

---

## 1. End-to-End Autonomous Inspection Matrix (6 Touchpoints)

### Touchpoint 1: Landing Page & Instant Scan Trigger (`/` & `/landing`)
- **Friction Points Audited:**
  - Hero quick-scan input with popular repositories (`expressjs/express`, `supabase/supabase`, `facebook/react`).
  - Seamless redirection from `/` to `/dashboard?repo=...&scan=true` without race conditions or swallowed params.
  - Navbar links, mobile navigation drawer, and smooth-scroll anchors.

### Touchpoint 2: Live Scanner Terminal & Progress Engine (`/dashboard` & `ScanRunnerView.tsx`)
- **Friction Points Audited:**
  - Real-time terminal log streamer across 7,850+ rules + new SCA dependency rules.
  - 3-second auto-transition to findings table upon countdown completion.
  - Graceful fallback when GitHub API rate-limits or when a repository is private/unreachable (clean actionable prompt to enter a GitHub Personal Access Token instead of unhandled crash).

### Touchpoint 3: Findings Table, Unified Git Diffs & Drawer (`FindingsTable.tsx`, `FindingDetailModal.tsx`)
- **Friction Points Audited:**
  - Category filters: Security, SCA Dependencies, Infra & DB, VibePolish UI, Legal Compliance.
  - Copy-paste Unified Git Diff rendering with line highlighting.
  - Executive PDF generation (`generateAuditPdfReport`), RFC 4180 CSV export, and JSON scorecard payload export.

### Touchpoint 4: CI/CD & Pipeline Integration Hub (`DeploymentManifestModal.tsx`)
- **Friction Points Audited:**
  - Seamless switching between GitHub Actions, GitLab CI, Pre-Commit (Husky), Docker Compose, and Kubernetes.
  - 1-click clipboard copy and `.yml` download buttons.
  - Snyk-grade PR status check markdown table generation.

### Touchpoint 5: Webhooks, Edge Telemetry & Settings (`NotificationSettingsModal.tsx`, `GeoIpTracker.tsx`)
- **Friction Points Audited:**
  - Serverless webhook test dispatch (`/api/v1/test-webhook`) without CORS or CSP blocks.
  - Edge GeoIP telemetry (`/api/v1/geo`) displaying real edge nodes.
  - Project deletion modal with confirmation safeguard.

### Touchpoint 6: Monetization, License Generation & Checkout (`/checkout`, `CheckoutView.tsx`)
- **Friction Points Audited:**
  - Transparent plan limits (Starter, Pro $29, Enterprise $99).
  - Deterministic cryptographic license key generation & verification (`lib/stripe-checkout.ts`).
  - Strict production hiding of developer sandbox simulator buttons.

---

## 2. Phase 2 Implementation Team (Minimum 3 Specialist Agents)

| Agent | Domain | Role & Core Tasks |
| :--- | :--- | :--- |
| **Agent 1: `frontend-specialist`** | UI/UX & Interaction | Audit all modals, drawers, tooltips, responsive viewports, empty state fallbacks, and micro-interactions. |
| **Agent 2: `backend-specialist`** | API & Data Engine | Audit `/api/v1/gate-check`, `/api/v1/github-proxy`, SCA dependency parser, SSRF guardrails, and error resilience. |
| **Agent 3: `test-engineer`** | QA & Verification | Stress-test diverse repositories, run TypeScript compile (`tsc --noEmit`), execute Antigravity master checklist (`checklist.py`), sync Desktop and push to GitHub. |

---

## 3. Acceptance Criteria for Zero-Defect Handover
1. **0 Unhandled Errors:** Any bad input, invalid repo, or network failure displays a helpful, polite, actionable message.
2. **0 Modal / Backdrop Traps:** Every overlay, drawer, and modal closes cleanly on Escape or backdrop click.
3. **100/100 Self-Audit Score:** Zero critical, high, medium, or low findings on our own repository.
4. **0 TypeScript Errors:** `npx tsc --noEmit` exits with code 0.
5. **6/6 Master Checklist:** `checklist.py` returns all 6 checks PASSED.
6. **100% Dual-Repo Sync:** All changes synchronized between Desktop repo and worktree, committed and pushed to GitHub main.
