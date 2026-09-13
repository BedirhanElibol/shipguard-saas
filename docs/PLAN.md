# Master Orchestration Plan (v18.0.0)
## Autonomous Browser Testing & Multi-Repository Stress-Audit

### Executive Summary
The user requested: `"/orchestrate /browser edip app'i rasgele repolarda deneyelim çalışma prensibimizde buglar var mı"`
This plan establishes an end-to-end autonomous stress-testing and browser validation protocol for the Zelsis SaaS application (`https://shipguard-saas.vercel.app` and local runtime).
The objective is to systematically test the repository scanning lifecycle on real, diverse, and randomly selected open-source GitHub repositories to uncover edge cases, architectural bottlenecks, API proxy rate limits, UI state locks, and rule engine evaluation defects.

---

## 1. Test Matrix: Selected Public GitHub Repositories

To thoroughly stress-test all operational dimensions, we define a 5-tier repository test matrix:

| # | Target Repository | Domain / Language | Scale & Characteristics | Purpose |
|---|---|---|---|---|
| **R1** | `expressjs/express` | Node.js / JavaScript | Established mature web framework (~100 source files, middleware, route handlers) | Verify JS/Node backend rule triggers, auth patterns, and AST traversal. |
| **R2** | `pallets/flask` | Python / WSGI | Core Python microframework (~40 Python modules, WSGI routing, CLI) | Verify Python enterprise rules, packaging patterns, and decorators. |
| **R3** | `facebook/react` (sub-package / core) | TypeScript / React Web | Modern frontend component architecture (hooks, JSX, fiber reconciler) | Verify VibePolish, UI/UX accessibility, and React best practice rules. |
| **R4** | `octocat/Hello-World` | Minimal / Git test | Micro-scale single README repository (1-2 files) | Verify boundary conditions: empty code trees, minimal file handling, clean zero-crash completion. |
| **R5** | `vercel/next.js` (or sample Next.js template) | Fullstack Next.js App Router | Modern React 19, Server Components, edge routes, middleware | Verify Next.js App Router specific rules, edge security, and middleware analysis. |

---

## 2. Core Functional Dimensions to Validate

### A. Repository Ingestion & Validation
1. **URL Sanitization & Parsing**: Validate `sanitizeTargetUrl` and `parseGithubUrl` against shorthand formats (`owner/repo`), SSH URLs (`git@github.com:...`), trailing slashes, and branch deep-links (`/tree/main/...`).
2. **Modal Connection Flow**: Validate `ConnectTargetModal` state transitions, error messages on invalid input, and reactive addition to the project drawer.

### B. GitHub Proxy & Live Tree Fetching (`/api/v1/github-proxy`)
1. **Tree API Chunking**: Test recursive Git tree retrieval (`/git/trees/{branch}?recursive=1`) and 25-file chunked raw content streaming.
2. **Rate Limit Resilience**: Verify graceful fallback behavior when unauthenticated GitHub API encounters HTTP 403 / secondary rate limits (`x-ratelimit-remaining: 0`).
3. **Binary / Non-Code Exclusion**: Ensure lockfiles, media, binaries, and giant artifacts are strictly excluded from the scan payload.

### C. Static Scan Execution Across 7,850 Rules (`ScanRunnerView.tsx` & `scanner-engine.ts`)
1. **Rule Engine Execution**: Run all 7,850 active rules (`SECURITY`, `UI_UX`, `LEGAL_COMPLIANCE`, `INFRA_DATABASE`) against real ingested source files.
2. **Log Streaming & Animation**: Verify real-time log terminal formatting, time replacement, progress bar (0% -> 100%), and background tab throttling resilience.
3. **Score & Status Calculation**: Ensure `calculateReadinessScore` and `calculateGateStatus` produce mathematically sound, non-negative scores (0-100) and proper gate statuses (`PASSED`, `WARNING`, `FAILED`).

### D. Audit Completion & View Transition
1. **Countdown Auto-Transition**: Verify that when `countdownSeconds` reaches 0, `onCompleteScanRef.current(scanResult)` is reliably invoked without UI lockup.
2. **Report View Population**: Verify that the findings list, severity counts (Critical, High, Medium, Low), and remediation diff patches render properly for the selected repository.

---

## 3. Phase 2 Implementation Work Breakdown (3+ Specialized Agents)

Upon user approval, the following agents will execute concurrently:

### Agent 1: `browser` (Automated Browser UI & End-to-End Journey Verification)
- Navigate `https://shipguard-saas.vercel.app` in automated browser context.
- Open `Connect Target` modal, input target repositories from the test matrix.
- Initiate live scans, capture UI screenshots of scan progression, log streamer, and final audit report view.
- Audit browser DevTools console for uncaught exceptions, unhandled Promise rejections, or network failures.

### Agent 2: `backend-specialist` (GitHub Proxy & Ingestion Hardening)
- Audit `lib/github-api.ts` and `app/api/v1/github-proxy/route.ts` against network timeouts, rate limit starvation, and oversized repository payloads.
- Implement enhanced fallback handling for repos without default `main` branch (e.g. `master`, `dev`) and large file truncation guards.
- Ensure 100% Native English in all logs and error messages.

### Agent 3: `test-engineer` (Automated Repository Stress Runner & Assertions)
- Create `scratch/stress_test_random_repos.ts` executing end-to-end API and engine scans across all 5 test matrix repositories.
- Assert that every repository completes within acceptable time bounds (<30s), produces valid `ScanResult` schema, and experiences zero unhandled crashes.
- Run `checklist.py`, `security_scan.py`, `tsc --noEmit`, and `npm run build`.

---

## 4. Acceptance Criteria
- [ ] At least 4 distinct public GitHub repositories successfully ingested and scanned.
- [ ] Zero unhandled exceptions or infinite loading states during scan runs.
- [ ] Scan runner cleanly transitions to the completed audit report with exact finding counts.
- [ ] GitHub proxy handles rate limits gracefully with informative user guidance.
- [ ] All quality gates pass: 0 TypeScript errors, 100% Native English, 26/26 Next.js routes building cleanly.
