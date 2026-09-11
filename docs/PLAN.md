# 🕵️‍♂️ SHIPGUARD / ZELSIS: REAL-WORLD GITHUB REPOSITORY AUDIT & DEFECT ERADICATION
## Version 13.0.0 — Stress Testing Against Real Public GitHub Repositories & Engine Hardening

> **Document Version:** 13.0.0-REAL-WORLD-AUDIT-ERADICATION  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning Checkpoint)  
> **Target User Query:** "/orchestrate /browser edip birkaç adet github reposu bulup çalıştıralım bug var mı bakalım ."  
> **Author:** Master Orchestrator & Systems Security Architect  
> **Language Standard:** Strict 100% Native English in code, documentation, and technical specs; Turkish in user-facing status messages.  
> **Target Repositories Evaluated:** `shadcn-ui/taxonomy`, `vercel/next-learn`, `expressjs/express`, `vercel/next.js`

---

## 1. Executive Summary & Forensic Audit of Real-World Scans

In response to the user directive to test real-world GitHub repositories and hunt for bugs, crashes, edge cases, and engine flaws, we audited 4 diverse open-source repositories through our live production API endpoints (`/api/v1/gate-check`, `/api/v1/github-proxy`) and local scanner pipeline:

| Target Repository | Ecosystem / Type | Files Analyzed | Gate Status | Score | Issues Detected & Anomalies |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`shadcn-ui/taxonomy`** | Next.js 14 / Tailwind / Prisma SaaS | 139 files | WARNING | **0/100** | Score collapsed to 0 despite 0 critical blockers; 36 false positives on nested layouts missing repeated OpenGraph tags. |
| **`vercel/next-learn`** | Next.js Tutorial & Starter Apps | 150 files | FAILED | **0/100** | Correctly identified real unconsented Facebook SDK tracker (COMPL-02); 38 high CVE findings across archived 2020 starters. |
| **`expressjs/express`** | Node.js Backend Framework | 150 files | WARNING | **20/100** | Flagged `test/res.cookie.js` as a GDPR Cookie Consent dark pattern; duplicate `UI-48: UI-48:` title prefix. |
| **`vercel/next.js`** | Monorepo / Framework Presets | 150 files | WARNING | **0/100** | `.vscode/settings.json` flagged as a High UI-48 template injection defect; score collapsed to 0. |

---

## 2. Discovered Flaws & Vulnerabilities to Eradicate

### 🚨 DEFECT-19: Flat Linear Score Collapse on Real-World Repositories
- **Location:** `lib/scanner-engine.ts` (lines 1381–1389)
- **Defect:** `calculateReadinessScore` subtracts `critical * 30 + high * 15 + medium * 5 + low * 1`. On realistic codebases with 100+ files, having 7 High or 20 Medium non-blocking issues drops the score to 0/100 even when `gateStatus` is `WARNING` (zero critical vulnerabilities).
- **Impact:** Misleading UX; users see a yellow `WARNING` badge but a completely destroyed `0/100` score.
- **Remediation:** Implement a bounded, weighted logarithmic decay formula that preserves score proportionality based on repository size, ensuring non-critical issues cannot collapse the score to 0 unless true critical blockers exist.

### 🚨 DEFECT-20: Title Prefix Duplication and Non-English Strings in AST Rules
- **Location:** `lib/scanner-engine.ts` (lines 812, 836, 860, 883, 907, 932, 956, 979, 1026, 1047, 1070, 1085, 1093, 1116, 1139, 1162, 1184, 1208, 1232)
- **Defect:** Multiple rule titles contain redundant duplicated codes (e.g. `UI-48: UI-48: Dynamic Variable Injection Missing Fallback`, `UI-117: UI-117: Uncleaned Event Listener`). Furthermore, lines 1085 and 1093 contain raw Turkish phrases (`// VibePolish UI-121: Streaming Olmadan Bekletmek` and `UI-121: Streaming Olmadan Senkron Bekletme`), violating the mandatory 100% Native English rule.
- **Impact:** Degraded UI aesthetics, unprofessional reporting, and violation of the project language protocol.
- **Remediation:** Clean all rule titles to single canonical format (`UI-48: Dynamic Variable Injection Missing Fallback`) and translate all Turkish comments/titles to professional Native English.

### 🚨 DEFECT-21: False Positive Explosions on Config, Test, and Hidden Files
- **Location:** `lib/scanner-engine.ts`, `lib/rules/frontend-rules.ts` (lines 165–185), `lib/rules/compliance-rules.ts` (lines 168–180)
- **Defect:** 
  1. Config files (`.vscode/settings.json`) are evaluated by frontend prompt template rules like `UI-48`.
  2. Test files (`test/`, `*.test.js`, `*.spec.ts`) are evaluated by legal cookie consent rules (`COMPL-03`), causing Express's `res.cookie()` unit tests to be flagged as GDPR violations.
  3. Nested Next.js App Router sub-layouts and sub-pages are flagged as missing OpenGraph metadata (`UI-SEO-01`), ignoring the fact that metadata is inherited from root `app/layout.tsx`.
- **Impact:** Generates noise and false positives, eroding developer trust in the audit engine.
- **Remediation:** Exclude `.vscode/`, `test/`, `tests/`, `spec/`, `__tests__/`, and dotfiles from UI and compliance rules; update `UI-SEO-01` to only enforce OpenGraph requirements on root layouts and pages that explicitly export metadata.

### 🚨 DEFECT-22: Server-Side Relative Fetch Crash and Missing GITHUB_TOKEN Fallback
- **Location:** `lib/github-api.ts` (lines 70–80) & `app/api/v1/github-proxy/route.ts` (lines 64–76)
- **Defect:** `fetchGithubRepositoryData` performs `fetch('/api/v1/github-proxy...')`. When called within server routes (e.g. `/api/v1/gate-check`), Node.js throws an `Invalid URL` exception because relative URLs are not supported server-side. Additionally, neither `github-api.ts` nor `github-proxy` reads `process.env.GITHUB_TOKEN` from the server environment, unnecessarily subjecting public repository scans to GitHub's harsh 60 req/hr unauthenticated IP rate limit.
- **Impact:** Inefficient double-fetch fallback on the server and frequent `RATE_LIMIT_EXCEEDED` errors when auditing public repositories.
- **Remediation:** Detect environment (`typeof window === 'undefined'`) in `github-api.ts` and bypass the internal HTTP proxy on the server. Inject `process.env.GITHUB_TOKEN` as a default Authorization header on the server to unlock 5,000 req/hr rate limits.

### 🚨 DEFECT-23: Repository Shorthand ("owner/repo") Input Failure in NewProjectModal
- **Location:** `components/projects/NewProjectModal.tsx` (lines 27–31)
- **Defect:** When a user enters a GitHub repository shorthand like `shadcn-ui/taxonomy` or `facebook/react`, `handleSubmitNew` prepends `https://` resulting in `https://shadcn-ui/taxonomy`. `isValidGithubUrl` then returns `false` because the domain is not `github.com`.
- **Impact:** Users are prevented from connecting repositories using the convenient shorthand format (`owner/repo`), even though the backend parser explicitly supports it.
- **Remediation:** Normalize input in `NewProjectModal.tsx`: if format matches `^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`, prepend `https://github.com/` before validating.

### 🚨 DEFECT-24: Tree File Chunking Optimization to Prevent Gateway Timeouts
- **Location:** `app/api/v1/github-proxy/route.ts` (lines 141–172)
- **Defect:** `github-proxy` slices up to 300 blobs and fetches them from `raw.githubusercontent.com`. In large repositories, this risks exceeding Vercel's 10s/15s serverless execution timeout.
- **Impact:** HTTP 504 Gateway Timeout during repository proxy fetch.
- **Remediation:** Standardize slice cap to 150 top-priority application source files (prioritizing `app/`, `src/`, `components/`, `lib/`, `pages/`, `package.json`), ensuring fast, reliable scans under 6 seconds.

---

## 3. Implementation Work Packages (Phase 2 Multi-Specialist Plan)

### 📦 Package 1: Scanner Engine & AST Rule Hardening (`backend-specialist`)
- Normalize `calculateReadinessScore` to prevent artificial score collapse on large repositories.
- Clean all duplicate rule title prefixes (`UI-XX: UI-XX:` -> `UI-XX:`).
- Eliminate all Turkish comments and strings in `lib/scanner-engine.ts` (100% Native English).
- Filter out `.vscode/`, `test/`, `spec/`, and dotfiles from UI/compliance rule evaluations.
- Refactor `UI-SEO-01` in `lib/rules/frontend-rules.ts` to prevent false positive metadata warnings on nested sub-routes.

### 📦 Package 2: GitHub API Proxy & Serverless Resilience (`backend-specialist`)
- Update `lib/github-api.ts` to detect server execution and use direct API fetching without relative URL failure.
- Add `process.env.GITHUB_TOKEN` server-side token fallback in `github-proxy` and `github-api.ts` for 5,000 req/hr rate limit headroom.
- Optimize file tree filtering and limit chunk fetching to 150 prioritized source files to guarantee sub-8s response times.

### 📦 Package 3: Modal UX & Input Normalization (`frontend-specialist`)
- Fix `components/projects/NewProjectModal.tsx` shorthand repository normalization (`owner/repo` -> `https://github.com/owner/repo`).
- Verify `ScanRunnerView.tsx` error logging and failure feedback when repositories are private or rate-limited.
- Ensure 0 console warnings or broken state transitions during scan lifecycle.

### 📦 Package 4: QA, Verification & Deployment (`test-engineer`)
- Build comprehensive automated verification script `scratch/test_v13_real_repos.py` testing live GitHub repos (`shadcn-ui/taxonomy`, `vercel/next-learn`, `expressjs/express`).
- Run `checklist.py`, `npx tsc --noEmit`, and `npm run build`.
- Sync all modifications to `C:\Users\Bedirhan\Desktop\newday`.
- Commit with message: `fix(engine): harden AST scanner against false positives, fix score collapse, and optimize GitHub proxy for real-world repos`.
- Push to GitHub `origin main` and verify live Vercel deployment.

---

## 4. Acceptance Criteria
1. ✅ `calculateReadinessScore` reflects realistic health (non-zero score for repositories with 0 critical blockers).
2. ✅ Zero Turkish strings or duplicate prefixes in rule titles or comments.
3. ✅ Zero false positives on config files (`.vscode/settings.json`) or test files (`test/res.cookie.js`).
4. ✅ Shorthand repository inputs (`shadcn-ui/taxonomy`) successfully validate and connect in `NewProjectModal`.
5. ✅ Full test suite passes, `checklist.py` passes 6/6, `npx tsc --noEmit` returns 0 errors, and live Vercel deployment returns healthy responses.
