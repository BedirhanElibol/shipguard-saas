# Master Orchestration Plan (v19.0.0)
## High-Conversion SaaS Product Landing Architecture & AI Slop Eradication

### Executive Strategic Summary
The user requested:
> `"/orchestrateson düzlükteyiz app'in satması için çalışma durumlarını komple gözden geçir landingpage sanki çok ai slop duruyor albenisi yok gibi /ui-ux-designer geri alınabilecek şekilde çalışmalar yapalım sadece benim eklettiğim görseller app'in çalışma durumları olduğu için koruyabilirsin."`

ShipGuard / Zelsis is a production release gate platform ($29–$99/month SaaS) engineered with 148 multi-pillar security and deployment rules. However, the current landing page (`app/page.tsx`) was modeled after a boutique design agency ("Client Work 2026", "Services Grid", "Our Approach Manifesto", "Mouse-Following Insights"). This creates a fatal dissonance: buyers and engineering leads looking for automated security, compliance, and CI/CD pre-flight gates are greeted by agency portfolio tropes. The real, high-value product screens uploaded by the user are buried inside mock case studies.

This plan executes a complete transformation from "Agency AI Slop" to an **Authoritative, High-Converting Developer SaaS** (comparable to Linear, Vercel, Supabase, Raycast) that highlights the 5 real product screenshots as empirical proof of the working engine. All modifications are modular, isolated, and fully reversible.

---

## 1. Product Screenshots Showcase Architecture (Preserved & Prominently Featured)

The 5 real application state screenshots in `public/images/` represent the core pillars of the value proposition and will be elevated to the center of the customer journey:

| Screenshot | Current Location | New High-Converting Role | Key Value Proposition Shown |
|---|---|---|---|
| `dashboard_overview.png` | Buried / Unused in Hero | **Hero Product Centerpiece Frame** | Real-time release clearance gauge, active audit scores, live project health telemetry, instant scan triggers. |
| `security_rules.png` | FeaturedWork / Services modal | **Pillar 1: 148 Multi-Pillar Gate Catalog** | Transparent rule inventory (OWASP Top 10, Docker root privilege, PostgreSQL RLS, Next.js 15 App Router). |
| `audit_findings.png` | Services / FeaturedWork modal | **Pillar 2: Deep Vulnerability Triage & AST Diffs** | Precise line-by-line vulnerability highlights, code context, and 1-click AI remediation prompts. |
| `vulnerability_sandbox.png` | FeaturedWork modal | **Pillar 3: Interactive Zero-Install Sandbox** | Live in-browser AST regex & security playground for instant proof without onboarding friction. |
| `bundle_profiler.png` | FeaturedWork / Insights modal | **Pillar 4: Core Web Vitals & Container Profiling** | Deep performance profiling, asset weight distribution, CLS/LCP metrics, and Kubernetes/Docker limits. |

---

## 2. Re-architecting `app/page.tsx` (Eliminating AI Slop)

### A. What We Eradicate ("AI Slop" & Agency Tropes)
- ❌ **"Services" (Agency Consulting trope)**: Replace with **Product Architecture & Capabilities**.
- ❌ **"Client Work (2026)" (Boutique Agency trope)**: Replace with **Real Interactive Feature Showcases** featuring the 4 screenshots.
- ❌ **"Our Approach Manifesto" (Word Scrub trope)**: Replace with **"How It Works in 3 Steps"** technical workflow.
- ❌ **"Editorial Insights" (Mock Blog trope)**: Replace with **Hard Comparison Matrix** (ShipGuard vs. Traditional Linters vs. Heavy Enterprise Scanners).
- ❌ **"Let's Build Something Together" (Freelancer Contact Form)**: Replace with **High-Converting Free Trial / Live Demo CTA** with zero-credit-card commitment.

### B. New High-Converting SaaS Structure
1. **Tactical Global Header & Navigation**:
   - Dynamic sticky bar: Brand, Live Rules Count (148 Gates), Capabilities, Pricing, Security/Privacy, and Direct "Open Dashboard" CTA.
2. **Hero Section (`Hero.tsx` / `SaasHero.tsx`)**:
   - **Commanding Swiss / Obsidian Typography**: "Zero-Day Release Clearance for Production Code."
   - **Immediate Value Subtitle**: Instant OWASP, UI/UX performance, and cloud container auditing before code merges.
   - **Dual Action Bar**: Primary CTA `[ Launch Free Audit ]` + Secondary `[ Explore 148 Rules ]`.
   - **Social Proof / Tech Matrix**: Next.js 15, TypeScript, Python, Go, Docker, Kubernetes, Supabase, Stripe.
   - **Ambient Product Frame**: High-resolution browser window framing `dashboard_overview.png` with interactive pulse badges highlighting the real readiness gauges.
3. **Interactive 3-Step Production Workflow (`WorkflowSteps.tsx`)**:
   - **Step 1: Ingest & Parse (0s)**: Shorthand GitHub URL or local files. Zero-retention privacy (code scanned in-memory, never stored).
   - **Step 2: 148 Multi-Pillar Verification (<3s)**: AST pattern matching, security secrets, Docker root defense, and WCAG accessibility.
   - **Step 3: Signed Clearance & 1-Click Remediation**: Exportable release manifest, SOC 2/ISO 27001 readiness audit, and direct PR remediation diffs.
4. **Deep Product Capabilities Matrix (`ProductCapabilities.tsx`)**:
   - 4-quadrant architectural showcase utilizing the user's 4 remaining images:
     - Card A (`security_rules.png`): "148 Production Release Gates & Rule Engine".
     - Card B (`audit_findings.png`): "Surgical AST Finding Triage & 1-Click Fix Prompts".
     - Card C (`vulnerability_sandbox.png`): "Interactive Browser Sandbox & Rule Tester".
     - Card D (`bundle_profiler.png`): "Core Web Vitals & Container Resource Profiler".
5. **The Uncompromising Comparison Table (`ComparisonTable.tsx`)**:
   - Clear contrast table: **Traditional Linters (ESLint/Prettier)** vs. **Enterprise Scanners (SonarQube/Snyk - $500+/mo)** vs. **ShipGuard**.
   - Highlights: Scan Speed (<3s vs 10min), Multi-Pillar (Security + UI/UX + Cloud vs Security only), Friction (Zero setup vs heavy agent), Pricing ($29/mo vs thousands).
6. **Transparent Developer Pricing (`PricingView.tsx`)**:
   - Direct monthly/yearly toggle, clear tier quotas (Free 3 Scans, Pro Unlimited, Enterprise Team), Polar checkout integration.
7. **Security, Privacy & Architecture FAQ (`FaqSection.tsx`)**:
   - Direct answers to the questions developers and CTOs care about: "Do you store my code?", "Does it work with private repos?", "How does it fit into GitHub Actions CI/CD?".
8. **Final High-Converting Action Terminal**:
   - Quick repo URL paste bar with instant scan trigger.

---

## 3. Reversibility & Modular Architecture

To satisfy the user's requirement (`"geri alınabilecek şekilde çalışmalar yapalım"`):
- All existing agency components (`Services.tsx`, `FeaturedWork.tsx`, `About.tsx`, `Insights.tsx`, `Contact.tsx`) will be preserved in git history and kept intact in a `components/legacy/` archive or preserved alongside new components.
- The new SaaS architecture will be built with dedicated, clean components:
  - `components/saas/SaasHero.tsx`
  - `components/saas/WorkflowSteps.tsx`
  - `components/saas/ProductCapabilities.tsx`
  - `components/saas/ComparisonTable.tsx`
  - `components/saas/FaqSection.tsx`
- Switching back is as simple as toggling imports in `app/page.tsx` or a single git revert.

---

## 4. Design Commitment (Anti-Safe Harbor & Anti-AI Slop)

Following `@[agents/frontend-specialist]` and `@[skills/ui-ux-designer]`:
- **Style**: Obsidian Radar / Industrial Precision Developer Platform.
- **Strict Purple Ban**: 0 purple, violet, indigo, or magenta gradients. Only deep dark `#0A0A0A` / `#121212`, clean white `#EDEDED`, tactical emerald `#10B981`, alert amber `#F59E0B`, and crimson `#EF4444`.
- **No Floating Blobs / Mesh Gradients**: Clean, crisp borders (`border-white/10`), subtle dot-matrix grid backgrounds, high-contrast monospace typography.
- **Copy**: Crisp, concrete, developer-centric metrics (numbers, rules, seconds, standards). No marketing buzzwords like "Orchestrate", "Empower", "Elevate", "Seamless".

---

## 5. Phase 2 Implementation Work Breakdown (3 Specialized Agents)

Upon user approval of this plan, the following agents will execute in parallel:

### Agent 1: `frontend-specialist` (High-Converting SaaS Component Construction)
- Implement `components/saas/SaasHero.tsx` featuring `dashboard_overview.png` with interactive hotspot telemetry and direct repository scan input.
- Implement `components/saas/WorkflowSteps.tsx` (3-step interactive pipeline).
- Implement `components/saas/ProductCapabilities.tsx` showcasing `security_rules.png`, `audit_findings.png`, `vulnerability_sandbox.png`, and `bundle_profiler.png` in high-density cards.
- Implement `components/saas/ComparisonTable.tsx` and `components/saas/FaqSection.tsx`.
- Wire into `app/page.tsx`.

### Agent 2: `ui-ux-designer` (Visual Harmony, Responsive Rhythm & Micro-Interactions)
- Audit spacing, contrast ratios, and typography scale across mobile, tablet, and desktop viewports.
- Enforce strict Purple Ban and zero AI-slop visual artifacts.
- Implement subtle micro-interactions (hotspot pulse, copy-to-clipboard, tab switching).

### Agent 3: `test-engineer` (Verification, Quality Gates & Zero-Regression Sync)
- Audit all modified files for 100% Native English (zero Turkish characters in code/comments).
- Run `npx tsc --noEmit` and `npm run build` to guarantee clean compilation.
- Run `python .agent/skills/vulnerability-scanner/scripts/security_scan.py .`.
- Run Desktop sync script `scratch/sync_to_desktop.py`, stage, commit, push to GitHub, and verify live URL `https://shipguard-saas.vercel.app`.

---

## 6. Socratic Checkpoint & User Approval
Before touching code or executing Phase 2, we present this plan to the user for explicit review and validation.
