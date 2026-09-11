# 🕵️‍♂️ SHIPGUARD / ZELSIS: REAL-WORLD GITHUB REPOSITORY AUDIT & ENGINE HARDENING
## Version 15.0.0 — Trending Multi-Language Repo Audit, Engine Defect Eradication & API HTTP Semantics

> **Document Version:** 15.0.0-TRENDING-REPO-AUDIT-HARDENING  
> **Status:** Production Deployed & Verified  
> **Target User Query:** "/orchestrate rasgele /browser edip github reposu bul 3 adet ve onları da deneyelim sorunumuz var mı yok mu varsa genel olarak tüm sorunları çıkar"  
> **Author:** Master Orchestrator & Systems Security Architect  
> **Language Standard:** Strict 100% Native English in code, documentation, and technical specs; Turkish in user-facing chat communication.  
> **Target Repositories Evaluated:** `requarks/wiki` (Node.js/JS), `harry0703/MoneyPrinterTurbo` (Python), `glanceapp/glance` (Go)

---

## 1. Executive Summary & Forensic Audit of Target Repositories

We discovered 3 diverse, real-world repositories from GitHub Trending:
1. **`requarks/wiki`** — JavaScript / Node.js (Open source wiki platform)
2. **`harry0703/MoneyPrinterTurbo`** — Python (Automated video generator using LLMs)
3. **`glanceapp/glance`** — Go (Self-hosted dashboard application)

We performed end-to-end audits using the live ShipGuard scanner engine (`https://shipguard-saas.vercel.app/api/v1/gate-check`).

### Forensic Scan Results (Initial v14.0.0 Baseline)

| Target Repository | Ecosystem / Stack | Files Analyzed | Gate Status | Readiness Score | Findings (C / H / M / L) | Initial HTTP Status | Key Findings & Discovered Defects |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`requarks/wiki`** | Node.js / JavaScript | 150 files | FAILED | **45/100** | 1 C / 12 H / 0 M / 0 L | 422 | 1. Commented-out Helm sample DB URI flagged as CRITICAL.<br>2. UI-117 flagged lifelong browser bootstrap listeners.<br>3. Accurate: Root Dockerfile, vulnerable dependencies, Markdown tabset XSS. |
| **`harry0703/MoneyPrinterTurbo`** | Python / AI Pipelines | 145 files | FAILED | **14/100** | 2 C / 6 H / 3 M / 0 L | 422 | 1. UI-48 false positive on `test/` files because path started with `test/` without leading `/`.<br>2. Accurate: Missing LLM budget circuit breaker, unbounded token consumption, missing RAG guardrail, Root Dockerfile. |
| **`glanceapp/glance`** | Go / HTML Templates | 136 files | WARNING | **48/100** | 0 C / 27 H / 6 M / 0 L | 422 | 1. UI-48 flagged 8 Go files due to Go template syntax `{{ .Field }}` and `template` package imports.<br>2. UI-PERF-01 flagged 15 Go server-rendered HTML templates as HIGH with Next.js `<Image>` advice.<br>3. Accurate: Root Dockerfile, unescaped `innerHTML` DOM mutation at `page.js:L754` and `templating.js:L113`. |

---

## 2. Discovered Deficiencies & Flaws Eradicated in v15.0.0

### 🚨 DEFECT-30: API Returned HTTP 422 for Valid Completed Audits
- **Location:** `app/api/v1/gate-check/route.ts` (lines 159–161)
- **Defect:** When `gateStatus !== 'PASSED'`, the endpoint returned HTTP 422 (Unprocessable Entity) despite returning a complete, successful JSON response body with findings and scores.
- **Impact:** Standard HTTP client libraries (`urllib`, `axios`, `fetch`) threw unhandled exceptions on HTTP 422, causing API integrations to discard the audit payload.
- **Remediation:** Changed default response status to HTTP 200 OK for all successfully executed scans. Added an optional `?failOnBlock=true` query parameter for strict CI/CD pipelines that require non-zero exit codes on blocked releases.

---

### 🚨 DEFECT-31: UI-48 False Positive on Go Template Syntax and Backend Languages
- **Location:** `lib/scanner-engine.ts` (lines 804–827)
- **Defect:** UI-48 regex `/\{[a-zA-Z0-9_]+\}/` matched Go template syntax `{{ .Field }}` and Go format strings in `.go` files when the file mentioned `template`. Go is a statically typed language that does not possess JavaScript's `??` nullish coalescing operator.
- **Impact:** Erroneously flagged 8 standard Go files in `glanceapp/glance` as missing nullish coalescing.
- **Remediation:** 
  1. Excluded non-JS backend languages (`.go`, `.rs`, `.c`, `.cpp`, `.java`, `.kt`, `.cs`, `.swift`, `.rb`, `.sh`, `.ps1`) from UI-48 prompt template checks.
  2. Required variable placeholders to be strictly single-braced via negative lookbehind/lookahead `/(?<!\{)\{[a-zA-Z0-9_]+\}(?!\})/` to reject double-braced template syntax.

---

### 🚨 DEFECT-32: UI-48 Path Check Missed Test Files Starting with `test/`
- **Location:** `lib/scanner-engine.ts` (lines 805–807)
- **Defect:** `isTestOrDocFile` checked `lowerFilePath.includes('/test/')`. Files whose paths started with `test/` (e.g. `test/services/test_llm.py`) lacked a leading `/` and were not excluded.
- **Impact:** Test mock files in `harry0703/MoneyPrinterTurbo` triggered UI-48 findings.
- **Remediation:** Expanded test file path recognition to:
  `lowerFilePath.startsWith('test/') || lowerFilePath.startsWith('tests/') || lowerFilePath.startsWith('spec/') || /(?:^|\/)(?:test_[^/]+|[^/]+_test)\.[a-zA-Z0-9]+$/i.test(lowerFilePath) || /\.(?:test|spec)\.[a-zA-Z0-9]+$/i.test(lowerFilePath)`.

---

### 🚨 DEFECT-33: UI-PERF-01 Over-Severity and Irrelevant Next.js Advice on Pure HTML Templates
- **Location:** `lib/rules/frontend-rules.ts` (lines 109–150)
- **Defect:** UI-PERF-01 flagged every `<img>` tag in server-rendered Go/Django HTML templates as HIGH severity, instructing developers to use Next.js `next/image` `<Image>` components inside non-Next.js projects.
- **Impact:** 15 high-severity false alarms on `glanceapp/glance` template files.
- **Remediation:**
  1. For pure HTML files (`isHtml && !isJsxTsx`), only flag if `<img>` lacks both explicit dimensions (`width`/`height`) and lazy loading (`loading="lazy"`), or contains heavy base64 data URIs.
  2. Adjusted severity for HTML templates to LOW (or MEDIUM for heavy base64) with standards-compliant HTML remediation (`width`, `height`, `loading="lazy"`).
  3. Preserved HIGH severity and `next/image` guidance specifically for JSX/TSX React components.

---

### 🚨 DEFECT-34: INFRA-03 Flagged Commented-Out Sample DB URIs and Dev Defaults
- **Location:** `lib/rules/infra-rules.ts` (lines 160–185)
- **Defect:** RULE 3003 flagged commented-out sample URIs in Helm `values.yaml` (`#   databaseURL: postgresql://postgres:postgres@...`) as active CRITICAL database leaks.
- **Impact:** Erroneously blocked releases for standard Helm chart documentation samples.
- **Remediation:**
  1. Check if the matched line starts with a comment marker (`#`, `//`, `*`, `--`) and skip commented-out samples.
  2. Skip common local development default credentials (`postgres:postgres`, `root:root`, `admin:admin`, `test:test`).
  3. Ensure authentic, un-commented production credentials in active configuration code are strictly caught with CRITICAL severity.

---

### 🚨 DEFECT-35: UI-117 Event Listener Rule Triggered on App Bootstraps and Vendor Libs
- **Location:** `lib/scanner-engine.ts` (lines 1064–1092)
- **Defect:** UI-117 flagged `addEventListener()` without `removeEventListener()` in library files (`prism.js`) and app entry files (`client-app.js`, `boot.js`) where window listeners are intentionally lifelong.
- **Impact:** Memory leak warnings on legitimate top-level application initialization scripts.
- **Remediation:** Scoped UI-117 to component lifecycles and hooks (`/components/`, `/hooks/`, `/views/`, or files using `useEffect`/`componentDidMount`), while explicitly excluding vendor/library paths and top-level bootstrap entry scripts (`boot`, `client-app`, `main`, `index`).

---

## 3. Verification & Quality Assurance Suite

All fixes were rigorously verified through our automated testing suite:

1. **Unit Test Suite (`scratch/test_local_engine_v15.ts`):**
   - Test 1: Go template in `.go` file does NOT trigger UI-48 → **PASSED**
   - Test 2: Test file `test/services/test_llm.py` does NOT trigger UI-48 → **PASSED**
   - Test 3: Commented-out DB URI in YAML does NOT trigger INFRA-03 → **PASSED**
   - Test 4: Active production DB URI with password STILL flagged CRITICAL → **PASSED**
   - Test 5: Pure HTML template `<img>` flagged as LOW with HTML attributes advice → **PASSED**
   - Test 6: Next.js JSX raw `<img>` tag flagged as HIGH with Next.js Image advice → **PASSED**

2. **TypeScript Compilation:**
   - `npx tsc --noEmit` → **0 errors**

3. **Production Next.js Build:**
   - `npm run build` → **26/26 routes compiled cleanly**

4. **Antigravity Master Checklist:**
   - `python .agent/scripts/checklist.py .` → **6/6 checks PASSED** (Security, Lint, Schema, Test, UX, SEO)
