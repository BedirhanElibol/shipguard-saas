# Plan: Frontend AI Slop Refactoring, Self-Scan Dogfooding & Honest Rules Expansion

## Overview
Transform Zelsis from a noisy, generic "AI slop" appearance into an ultra-clean, high-density, industrial "dark luxury" engineering platform (Linear/Raycast inspired). Simultaneously execute a full dogfooding AST self-scan of the Zelsis codebase to establish an honest baseline, and blueprint the expansion of our AST rule library across multi-framework injection and secret leaks without synthetic sentinels.

## Project Type
**WEB** (Next.js 15 App Router, React 19, Tailwind CSS v4, Lucide Icons, TypeScript)

## Success Criteria
1. **AI Slop Elimination:** Remove flashy gradients, oversized generic bento cards, redundant marketing badges, and unnecessary sparkle/gimmick elements across both Landing Page (`SaasHero`, `LandingView`, `FeatureHighlights`) and Dashboard views.
2. **Industrial Dark Luxury UI:** Implement crisp 1px borders (`border-white/10`), JetBrains Mono for telemetry metrics, strict dark canvas (`#0A0A0A` / elevated `#141414`), and high-density, purposeful information hierarchy.
3. **Self-Scan Baseline (Dogfooding):** Run the complete Zelsis AST static scanner directly on the Zelsis project codebase (`BedirhanElibol/shipguard-saas`), extract raw findings, and generate a baseline remediation scorecard.
4. **Honest Multi-Framework Rules Research & Expansion:** Detail 10+ deterministic AST patterns covering real Python FastAPI, Next.js 15, Go, and Node.js injections & secrets.
5. **Phase X Verification:** Pass 100% of unit/integration test suites (108+ tests), lint checks, and WCAG 2.2 AA accessibility standards.

## Tech Stack
- Frontend: Next.js 15.5, React 19, Tailwind CSS v4, Framer Motion, Lucide React
- Backend / Engine: Next.js Route Handlers, TypeScript AST scanners, Supabase Postgres
- Architecture: Zero-retention static analysis, streaming evaluation, deterministic rule matcher

## Affected File Structure
```
components/
├── saas/
│   ├── SaasHero.tsx           # Refactor: Strip AI slop, simplify hero command bar & presets
│   └── SaasFeatureMatrix.tsx  # Refactor: High-density industrial capability table
├── layout/
│   ├── Header.tsx             # Polish: Minimalist telemetry bar & breadcrumbs
│   └── Navigation.tsx         # Polish: Clean linear active tab indicators
├── findings/
│   └── FindingsTable.tsx      # Refactor: Streamline data density & action buttons
├── ScanRunnerView.tsx         # Polish: Minimalist progress & terminal telemetry
lib/
└── scanner-engine.ts          # Dogfooding: Run self-audit on local Zelsis workspace files
docs/
└── honest-rules-expansion.md  # Research: Concrete deterministic AST rule specs
```

## Task Breakdown

### Task 1: Landing Page & Hero De-Slop Refactor
- **Agent:** `frontend-specialist`
- **Priority:** P1
- **Input:** Existing `components/saas/SaasHero.tsx` and `app/page.tsx`
- **Output:** Clean, monolithic, Linear-inspired hero section. Eliminate clichéd AI badges, noisy hotspot overlays, and fake testimonials. Focus directly on the interactive command bar, repository scan trigger, and real engineering metrics.
- **Verify:** Page loads with crisp `#0A0A0A` background, zero purple/neon gradients, 1px subtle borders, responsive layout.

### Task 2: Dashboard & Findings Density Streamline
- **Agent:** `frontend-specialist`
- **Priority:** P1
- **Input:** `components/findings/FindingsTable.tsx`, `components/ScanRunnerView.tsx`, `components/InfraAuditView.tsx`
- **Output:** Unified high-density tabular view with JetBrains Mono numbers, clear severity hierarchy (CRITICAL/HIGH/MEDIUM/LOW), minimal border-radius, and one-click quick inspect/remediate actions.
- **Verify:** WCAG 2.2 AA color contrast compliant, zero layout shift (CLS < 0.1), no redundant decorative icons.

### Task 3: Execute Self-Scan (Dogfooding Zelsis on Zelsis)
- **Agent:** `backend-specialist`
- **Priority:** P0
- **Input:** Workspace files of the current Zelsis project via `lib/scanner-engine.ts`
- **Output:** Run `runStaticCodeScan()` on the project codebase, capture all generated findings into a clean baseline report artifact (`docs/self-scan-baseline.md`).
- **Verify:** Report lists exact rule matches, lines of code, and remediation guidance with 0 fake sentinels.

### Task 4: Multi-Language & Framework Honest Rules Blueprint
- **Agent:** `security-auditor`
- **Priority:** P2
- **Input:** Industry benchmarks (Semgrep, Bandit, Gosec, Sonar)
- **Output:** Create `docs/honest-rules-expansion.md` documenting deterministic AST detection algorithms for Next.js Server Action auth bypass, Python FastAPI SQLi via f-string/Session.execute, Go unescaped template execution, and high-entropy secret detection.
- **Verify:** Rules specify exact AST nodes, zero synthetic checks, and test fixtures.

## Phase X: Verification Checklist
- [ ] `npx tsx tests/test_suite.ts` passes with 100% rate (>= 108 tests)
- [ ] No purple / violet neon gradients in modified views
- [ ] All inputs maintain explicit `id`, `name`, and accessible names
- [ ] Self-scan baseline report is generated and verified
- [ ] Vercel build succeeds without errors
