# 🕵️‍♂️ SHIPGUARD / ZELSIS: FORENSIC AUDIT & DEEP DEFECT ERADICATION PLAN
## Version 12.0.0 — Forensic Audit & Eradication of Flaws, Vulnerabilities & Placebo Controls (Round 2)

> **Document Version:** 12.0.0-DEEP-DEFECT-ERADICATION  
> **Status:** Phase 1 Master Architecture Plan (Sequential Planning Checkpoint)  
> **Target User Query:** "/orchestrate olan ve iyi şeyleri boşver kötülere bakalım onları araştırıp çözelim" & "/orchestrate devam et araştırmaya"  
> **Author:** Master Orchestrator & Systems Security Architect  
> **Language Standard:** Strict 100% Native English in code, documentation, and technical specs; Turkish in user-facing status messages.  
> **Compliance Standard:** OWASP Top 10 2025, CWE-287, CWE-918 (SSRF), CWE-200, WCAG 2.2 AA, Zero AI Slop

---

## 1. Forensic Audit: Discovered Flaws & Vulnerabilities (The "Bad Things")

In strict accordance with the user directive (*"Never mind the good and working things, let's look at the bad things, research them and solve them"*), we conducted an exhaustive forensic investigation across authentication flows, edge proxies, webhook receivers, background telemetry, and interactive modals. Here are the **10 genuine, high-severity defects** identified:

### 🚨 VULN-09: Unauthenticated Webhook Forgery in Polar Webhook Route (CRITICAL)
- **Location:** `app/api/v1/polar-webhook/route.ts` (lines 19–45)
- **Defect:** The webhook endpoint receives subscription lifecycle events (`subscription.created`, `subscription.updated`, `subscription.canceled`, `order.created`) and directly elevates or revokes user tiers in Supabase using `SUPABASE_SERVICE_ROLE_KEY`. However, it performs **zero HMAC signature verification**. `process.env.POLAR_WEBHOOK_SECRET` is never checked.
- **Impact:** Any attacker on the internet can craft and POST a JSON payload to `/api/v1/polar-webhook` and grant themselves or any arbitrary account an instant Enterprise tier in the Supabase database.
- **Remediation:** Implement standard HMAC-SHA256 signature verification matching Polar's webhook protocol (using `POLAR_WEBHOOK_SECRET`), reject unverified or spoofed requests with 401/403.

### 🚨 VULN-10: Server-Side Request Forgery (SSRF) in Live Website Gate Check (CRITICAL)
- **Location:** `app/api/v1/gate-check/route.ts` (lines 112–116) & `lib/website-scanner.ts` (lines 64–79)
- **Defect:** When `POST /api/v1/gate-check` audits a web target (`isWebTarget`), it calls `fetchWebsiteAuditData(rawRepoUrl)` on the server. `isValidWebUrl` only checks if the string contains a dot and starts with http(s). Unlike `/api/v1/proxy`, `gate-check` does NOT validate the target against `validateSafeTargetUrl` (the SSRF guard).
- **Impact:** An attacker can provide internal IPs (`127.0.0.1`, `169.254.169.254`, `10.0.0.1`, `metadata.google.internal`) to `/api/v1/gate-check`, forcing the serverless backend to request cloud metadata endpoints or private internal microservices.
- **Remediation:** Enforce `validateSafeTargetUrl` in `gate-check` before invoking `fetchWebsiteAuditData`, returning 403 Forbidden on SSRF attempt.

### 🚨 VULN-11: Data Leakage via Public Third-Party CORS Proxies & Placebo HTML (HIGH)
- **Location:** `lib/website-scanner.ts` (lines 84–118)
- **Defect:** If a direct fetch fails, `lib/website-scanner.ts` falls back to transmitting customer target URLs to public unverified proxy services (`api.allorigins.win` and `corsproxy.io`). Furthermore, if fetching fails completely, it fabricates a fake HTML document in memory and runs security audits on the fake document.
- **Impact:** Leaks proprietary client deployment targets to untrusted third parties, and generates placebo findings on fake HTML when real sites are down.
- **Remediation:** Completely remove public proxy fallbacks (`allorigins.win`, `corsproxy.io`). Use the hardened first-party `/api/v1/proxy` (with SSRF protection). If unreachable, report an authentic `UNREACHABLE_HOST` diagnostic error instead of fabricating fake HTML.

### 🚨 VULN-12: Unauthenticated Subscription & Customer Email Enumeration (HIGH)
- **Location:** `app/api/v1/subscription/sync/route.ts` (lines 24–45)
- **Defect:** The sync route accepts `{ email: string }` without requiring an authenticated user session JWT. It queries Polar API and Supabase and returns the user's active tier and expiration date.
- **Impact:** Anyone can run a dictionary attack or query arbitrary emails to enumerate which individuals are paid customers of the SaaS and inspect their renewal dates.
- **Remediation:** Require a verified Supabase JWT Bearer token via `supabase.auth.getUser(token)`, ensuring callers can only query the subscription associated with their own verified account.

### 🚨 VULN-13: Sliding-Window Rate Limiter Bypass via Spoofed Header (HIGH)
- **Location:** `lib/rate-limiter.ts` (lines 53–70)
- **Defect:** `getClientIp` reads `req.headers.get('x-client-ip')` first. Because `X-Client-IP` is an arbitrary client-settable HTTP request header, an attacker can supply random `X-Client-IP: 1.1.1.X` headers with each request, completely neutralizing the rate limiter on `/api/v1/gate-check`, `/api/v1/proxy`, and `/api/v1/badge`.
- **Impact:** Unrestricted brute force and Denial of Service (DoS) vulnerability.
- **Remediation:** Prioritize trusted edge proxy headers (`cf-connecting-ip`, `x-real-ip`, or `x-forwarded-for`) and ignore unverified client-sent `x-client-ip` headers.

### ⚠️ DEFECT-14: Placebo License Key Generation & Client-Side Bypass Trap (MEDIUM)
- **Location:** `lib/stripe-checkout.ts` (lines 34–67) & `components/checkout/CheckoutView.tsx` (lines 546–575)
- **Defect:** `verifyLicenseKey` accepts ANY key matching a simple regex pattern as valid 1-year Pro/Enterprise without cryptographic checksum or server validation. In addition, `CheckoutView.tsx` exposes a public "Simulate Instant Upgrade" button on the live checkout page that calls `activateUserTier` without payment.
- **Impact:** Any user can generate a fake key or click the instant sandbox button on production to gain Pro access for free.
- **Remediation:** Gate the sandbox simulation button strictly to development mode (`process.env.NODE_ENV !== 'production'`), and implement cryptographic HMAC checksum verification for license keys.

### ⚠️ DEFECT-15: Scan History Desynchronization & Placebo Baseline Audit Comparison (MEDIUM)
- **Location:** `components/ScanHistoryView.tsx` (lines 18–55) & `components/dashboard/AuditCompareModal.tsx` (lines 32–40)
- **Defect:** `ScanHistoryView` displays static hardcoded entries (`SCAN-8092`, `SCAN-8091`, `SCAN-8090`). Real scans completed in `ScanRunnerView` are never added to scan history. `AuditCompareModal` compares current audits against a hardcoded fake baseline from `24 Aug 2026, 18:30`.
- **Impact:** Broken data plumbing; users cannot inspect their actual past audits or compare real sequential progress.
- **Remediation:** Record real completed scans into project state (`scanHistory`), render authentic scan logs in `ScanHistoryView`, and dynamically compare against the true previous scan in `AuditCompareModal`.

### ⚠️ DEFECT-16: CSP Violation & Hardcoded Fallback on Dashboard GeoIP Tracker (MEDIUM)
- **Location:** `components/dashboard/GeoIpTracker.tsx` (lines 19–38) & `middleware.ts` (line 59)
- **Defect:** `GeoIpTracker` attempts to fetch `https://get.geojs.io/v1/ip/geo.json`, but `https://get.geojs.io` is NOT in CSP `connect-src`. The browser blocks the request with a CSP error on every dashboard view, causing it to always drop into `.catch()` and display fake fallback data (`Frankfurt, Germany`).
- **Impact:** Red CSP console error on dashboard load and 100% fake location telemetry.
- **Remediation:** Provide an internal `/api/v1/geo` endpoint using edge request headers (`x-vercel-ip-country`, `x-vercel-ip-city`) or proxy the request securely without leaking client IP to third parties.

### ⚠️ DEFECT-17: Client-Side Webhook Test Fails Due to Browser CORS & CSP (MEDIUM)
- **Location:** `components/dashboard/NotificationSettingsModal.tsx` (lines 78–89) & `lib/notifications.ts` (lines 71, 108)
- **Defect:** `NotificationSettingsModal` executes direct client-side `fetch()` to Slack and Discord webhook URLs. Slack webhook endpoints block browser CORS, and CSP blocks `hooks.slack.com`. The "Send Test Alert" button fails 100% of the time with `ERROR: Could not dispatch webhook`.
- **Impact:** Users cannot test or verify notification integrations from the dashboard.
- **Remediation:** Route test webhook dispatches through an internal server endpoint `/api/v1/test-webhook` with server-side fetch and SSRF protection.

### ⚠️ DEFECT-18: Broken Preset & String Matching in Vulnerability Playground (LOW/POLISH)
- **Location:** `components/dashboard/VulnerabilityPlayground.tsx` (lines 28–30, 39–53)
- **Defect:** Preset #4 "Wildcard Access-Control-Allow-Origin" in `VulnerabilityPlayground` sets `origin: process.env.PRODUCTION_CLIENT_URL` instead of `origin: '*'`. Clicking the preset and running the scan reports `CLEAN CODE` instead of demonstrating the vulnerability.
- **Impact:** Broken interactive demo that contradicts its own label.
- **Remediation:** Fix the preset code snippet to `origin: '*'` and connect the sandbox runner to `runStaticCodeScan` for real AST analysis.

---

## 2. Phase 2 Implementation Packages (Multi-Agent Roster)

Upon user approval (`Y`), the following 4 specialized agents will execute in parallel:

### Package 1: Security & Webhook Hardening (`security-auditor`)
- **Target Files:**
  - `app/api/v1/polar-webhook/route.ts`: Implement HMAC-SHA256 signature verification using `POLAR_WEBHOOK_SECRET`. Reject forged or missing signatures with 401/403.
  - `app/api/v1/gate-check/route.ts`: Add `validateSafeTargetUrl` SSRF protection before auditing website targets. Validate webhook URLs before running scans.
  - `lib/rate-limiter.ts`: Prioritize trusted edge headers (`cf-connecting-ip`, `x-real-ip`, `x-forwarded-for`) over unverified client-supplied `x-client-ip`.
  - `app/api/v1/subscription/sync/route.ts`: Enforce Supabase JWT Bearer token authentication to prevent email enumeration.

### Package 2: Scanner Integrity & Network Resilience (`backend-specialist`)
- **Target Files:**
  - `lib/website-scanner.ts`: Remove third-party public CORS proxies (`allorigins.win`, `corsproxy.io`). Rely exclusively on the hardened internal `/api/v1/proxy`. Eliminate fake HTML fallback and return honest diagnostic errors.
  - `app/api/v1/geo/route.ts` [NEW]: Create edge-compatible geolocation endpoint reading Vercel geo headers (`x-vercel-ip-country`, `x-vercel-ip-city`, `x-real-ip`).
  - `app/api/v1/test-webhook/route.ts` [NEW]: Create server-side test webhook dispatcher with SSRF validation to fix browser CORS/CSP blocks.

### Package 3: UI Truth, Data Plumbing & Sandbox Integrity (`frontend-specialist`)
- **Target Files:**
  - `components/checkout/CheckoutView.tsx`: Restrict instant sandbox upgrade button to non-production environments (`process.env.NODE_ENV !== 'production'`).
  - `lib/stripe-checkout.ts`: Implement cryptographic HMAC checksum for license key generation and validation.
  - `app/dashboard/page.tsx` & `hooks/useDashboardState.ts`: Record real scan executions into project `scanHistory`.
  - `components/ScanHistoryView.tsx`: Render real historical scan records with live timestamps, scores, and gate statuses.
  - `components/dashboard/AuditCompareModal.tsx`: Compare current audits against the authentic previous scan from history.
  - `components/dashboard/GeoIpTracker.tsx`: Switch from `get.geojs.io` to `/api/v1/geo`.
  - `components/dashboard/NotificationSettingsModal.tsx`: Dispatch test webhooks through `/api/v1/test-webhook`.
  - `components/dashboard/VulnerabilityPlayground.tsx`: Fix wildcard CORS preset code and connect to real AST scanner engine.

### Package 4: Automated Verification & Production Deployment (`test-engineer`)
- **Target Actions:**
  - Create comprehensive integration test `scratch/test_v12_defects.py`.
  - Verify TypeScript compiles with 0 errors (`npx tsc --noEmit`).
  - Run Next.js production build (`npm run build`).
  - Synchronize all changes to Desktop repo (`C:\Users\Bedirhan\Desktop\newday`).
  - Git commit & push to GitHub `origin main`.
  - Verify live deployment on Vercel (`https://shipguard-saas.vercel.app`).

---

## 3. Sequential Approval Gate (Socratic Protocol)

In accordance with `/orchestrate` Tier 0 Socratic Gate:
- **Phase 1 Complete:** Forensic flaw discovery and Version 12.0.0 master plan synthesized.
- **Action Required:** Await explicit user confirmation before modifying application code or spawning subagents.
