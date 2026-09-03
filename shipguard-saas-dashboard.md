# Implementation Plan: ShipGuard SaaS Dashboard (AI App Release Gate)

> **Document Status:** Phase 0 Implementation Plan  
> **Product Name:** ShipGuard (AI Release Gate SaaS)  
> **Target Goal:** Build a production-grade Web App SaaS Dashboard for auditing AI-built applications for security vulnerabilities (23 pre-flight checks), UI anti-patterns (30 VibePolish checks), and production sustainability (VibeCare monitoring).

---

## Executive Summary & Thesis

AI application generation tools (ChatGPT, Claude, Cursor, v0, Lovable) allow rapid code creation, but AI-generated code consistently lacks security hardening, proper authorization, cost controls, and custom UI design polish. ShipGuard provides the **"pickaxes and shovels"** for the AI app boom by acting as an automated release gate, auditing apps before production launch, providing interactive finding inspectors, and delivering copyable Claude/AI remediation prompts.

---

## PDF Requirements Mapping & Audit Checklists

### 1. Security Engine Taxonomy (23 Pre-flight Security Checks)
Derived directly from `YapılmasıGerekenGuvenlik.pdf`:

| # | Security Rule Name | OWASP / Domain Category | Key Risk & Audit Focus | Remediation Prompt Template |
|---|-------------------|------------------------|------------------------|-----------------------------|
| 01 | Secret & API Key Isolation | Secret Management | Hardcoded Stripe, OpenAI, Supabase keys in client bundle | Extract secrets to server `.env` & `.env.example` |
| 02 | Purge Secrets from Git History | Git Hygiene | Committed `.env` files remaining in git commit history | Step-by-step `git-filter-repo` / BFG removal commands |
| 03 | Row Level Security (RLS) & Storage Rules | Database Auth | Default `allow read, write: if true;` policies | Write restrictive RLS policies matching `user_id` |
| 04 | Server-Side Authorization Checks | Bypass Prevention | Buttons hidden in UI without backend API endpoint checks | Add server JWT/session role validation middleware |
| 05 | Rate Limiting & Abuse Prevention | DDoS / Rate Limit | Unrestricted login, register, and costly LLM endpoints | Implement Redis/memory rate limiter (5-10 req/min) |
| 06 | Server-Side Input Validation | Data Integrity | Unsanitized incoming API request payloads | Create Zod/Joi schemas for `body`, `query`, `params` |
| 07 | File Upload Security & MIME Limits | Upload Safety | Unrestricted file sizes and dangerous extensions (`.exe`, `.php`) | Enforce 5MB limit, magic byte MIME checks, UUID names |
| 08 | Restrict CORS to Production Domains | API Isolation | `Access-Control-Allow-Origin: *` in production | Restrict origin header to production/staging domain |
| 09 | HTTP Security Headers | Browser Security | Missing Helmet headers (CSP, HSTS, X-Frame-Options) | Add CSP, HSTS, `X-Frame-Options: DENY`, `nosniff` |
| 10 | Strict HTTPS & 301 Redirects | Traffic Encryption | HTTP endpoints accessible without SSL redirection | 301 permanent redirect to HTTPS and HSTS preload |
| 11 | Strong Password Hashing | Cryptography | Plaintext, MD5, or weak password hashes | Upgrade hashing to Argon2id or bcrypt (work factor >= 12) |
| 12 | Secure Session Cookies | Session Protection | Readable session cookies vulnerable to XSS | Set `HttpOnly: true`, `Secure: true`, `SameSite: Strict` |
| 13 | Production Error Masking | Information Leakage | Database schemas and stack traces sent to client | Return generic error response with unique `errorId` |
| 14 | Log Redaction & PII Sanitization | Privacy & GDPR | Tokens, passwords, credit card numbers in server logs | Mask sensitive fields in Winston/Pino logging pipe |
| 15 | Parameterized Queries (No SQLi) | OWASP #1 SQLi | String concatenation in SQL queries (`SELECT * FROM users WHERE id=` + id) | Convert all queries to prepared statements / ORM |
| 16 | XSS Sanitization & Safe DOM Rendering | XSS Defense | Unescaped user input rendered via `innerHTML` | Escape HTML output or sanitize with DOMPurify |
| 17 | Webhook Signature Verification | Payment Security | Stripe/LemonSqueezy webhooks accepting unverified payloads | Verify raw body HMAC-SHA256 signature with secret |
| 18 | Role-Based Access Control (RBAC) | Admin Authorization | Publicly accessible `/admin` endpoints | Enforce `role === 'ADMIN'` check and log audit events |
| 19 | Dependency Vulnerability Audit | Supply Chain | Known CVEs in third-party npm/pip dependencies | `npm audit` / `pip-audit` review & auto-upgrade plan |
| 20 | Automated Encrypted Backups & Recovery | Business Continuity | Missing daily database backups and un-tested restore | Daily encrypted S3 snapshot cron + restore verification script |
| 21 | True GDPR/KVKK Data Deletion | Compliance | Soft-delete `deleted: true` leaving PII in DB | Cascade delete script to anonymize PII and clear storage |
| 22 | Cloud & LLM Budget Alerts | Financial Control | Runaway LLM tokens or API spending loops | Set $50/80/100% budget thresholds & user consumption limits |
| 23 | Red Teaming & OWASP Attack Simulation | Pentest | Vulnerability to automated OWASP attack scripts | Execute 15-point attack simulation (IDOR, Injection, etc.) |

---

### 2. VibePolish Matrix (30 AI UI Anti-Patterns)
Derived directly from `YapılmasıGerekenUI.pdf`:

| Category | # | Anti-Pattern Cliché | Why It Feels Like Generic AI | ShipGuard Remedy / Design System Rule |
|----------|---|--------------------|-----------------------------|--------------------------------------|
| **Color & Background** | 01 | Harsh Linear Gradients | High-contrast raw linear gradients | Monochromatic tones, low-saturation mesh gradients |
| | 03 | Pure Stark White (#FFF) | Ham `#FFFFFF` background lacking depth | Warm off-whites (`#FAF9F6`, `#F8FAFC`) or subtle warm grays |
| | 04 | Rainbow Borders | Multi-colored rainbow spectrum borders | Restrict to 2 harmonious brand accent colors |
| | 20 | Purple-Black Neon Palette | Default `#000` + neon purple/indigo combo | Corporate color palettes (Navy, Emerald, Slate, Warm Earth) |
| | 22 | Blurred Radial Blur Glows | Floating massive radial blur circles | Structural subtle borders, clean line dividers |
| | 23 | CSS Dot Grid Backgrounds | Standard CSS dot pattern on every AI page | Clean flat background, subtle noise texture, asymmetrical accents |
| | 29 | Oversaturated Neon Accents | Eye-fatiguing neon green, cyan, and magenta | Muted, desaturated professional highlight tones |
| | 30 | Generic Pastel Cards | Cheap baby blue and powder pink cards | Deep neutral tones with structured contrast hierarchy |
| **Layout & Cards** | 05 | Overshadowing Everything | Heavy drop shadows on every card & input | 1px subtle borders (`border-subtle`) and flat surfaces |
| | 06 | Side-by-Side E-Equal 3 Cards | 3 identical equal-width feature boxes | Hierarchical multi-column grid, interactive tabs, timeline |
| | 08 | Excessive Glassmorphism | `backdrop-filter: blur()` & semi-transparent overlays | Solid opaque surfaces, high-contrast crisp text panels |
| | 11 | 4px Colored Left Accent Strip | Auto-added vertical 4px bar on card lefts | Background tone shifting or status pill badges |
| | 13 | Forced Bento Box Grids | Generic Apple-style bento grid crammed onto UI | Content-driven natural column layouts and structured lists |
| | 17 | Standard 3-Column Pricing Table | Enlarged middle "Popular" card with purple glow | Progressive slider or functional ROI calculator |
| | 19 | Over-rounded 999px Pills & 32px Cards | Extreme border radii on every element | Grounded modern 6px - 10px subtle corner radii |
| **Typography & Copy** | 09 | Em-Dash Addiction (—) | LLM habit of putting em-dashes in every text | Simple, clean sentence flow with concise punctuation |
| | 10 | Inter/Geist Font Lock-in | Default Inter, Geist, or Space Grotesk on every app | Custom brand font pairings (Plus Jakarta Sans, Outfit) |
| | 12 | Fake Testimonial Cards | "Loved by builders" / "Sarah K. - Head of Product" | Concrete verifiable metrics and quantitative evidence |
| | 15 | "Not X, but Y" Slogan Formula | "This is not a note app, it's your second brain" | Direct value proposition with honest benefit headers |
| | 16 | Green Checkmarks on Every Line | Green check SVG icon before every bullet point | Typographic hierarchy, clear subheadings, subtle tag badges |
| **Icons & Interactivity**| 02 | Lucide Icon Flooding | Same 10 Lucide SVG icons used everywhere | Specialized icon sets (Heroicons Solid, custom vector icons) |
| | 07 | Inline Emoji Spam | Rocket 🚀, Sparkle ✨, Flame 🔥 in headers | Remove emojis; use professional micro-icons or typography |
| | 14 | Fake Terminal Window Mockups | Irrelevant `npx create-app` terminal window | Real UI app screenshots, interactive flow previews |
| | 18 | Missing Real Product Visuals | Abstract "Watch Demo" buttons with grey boxes | High-res UI prototypes and interactive workflow visualizers |
| | 21 | Layout Shift on Loading | Empty white spaces jumping on data fetch | Shimmer/Skeleton loader states and reactive fallbacks |
| | 24 | Sparkle (✨) Icons on Every AI Button | 4-pointed sparkle badge attached to AI buttons | Actionable button text describing specific output |
| | 25 | Jittering / Bouncing Arrows | `->` arrows endlessly shifting left and right | Calm micro-interactions (subtle 2px hover translation) |
| | 26 | Missing Terms of Service | `href="#"` dead links in footer | Full, transparent Terms of Service legal framework page |
| | 27 | Missing Privacy Policy | Empty footer privacy link formalities | Comprehensive GDPR/KVKK compliant privacy policy page |
| | 28 | Excessive Hover Scaling | `scale(1.05)` hover chaos on all elements | Restrained border/color transitions without jitter |

---

## System Architecture & Tech Stack

```
ShipGuard Dashboard Architecture
│
├── 🎨 Design System & Styling
│   ├── Typography: Plus Jakarta Sans / Outfit (Google Fonts)
│   ├── Color Palette: Deep Slate (`#0B0F17`), Charcoal Gray (`#151C28`), Muted Cyan Accent (`#0EA5E9`), Emerald Green (`#10B981`), Crimson Warning (`#EF4444`)
│   ├── Design Tokens: CSS Custom Variables for theme, spacing, and crisp 1px borders
│   └── Iconography: Custom SVG Heroicons & custom vector badges (NO Lucide flooding)
│
├── ⚡ Core Engine & State Management (Phase 1)
│   ├── Mock Audit Engine: 100% typed evaluation engine covering all 23 Security + 30 UI Anti-Patterns
│   ├── Release Gate Evaluator: Computes Pass/Warn/Fail state based on Critical/High findings
│   ├── Scan Progress Simulator: Realistic step-by-step audit execution timeline with live log output
│   └── Remediation Auto-Fix Generator: Generates targeted Claude/AI prompts for each finding
│
└── 💻 View & UI Components
    ├── Navigation Sidebar: ShipGuard (Active), VibePolish (Preview), VibeCare (Roadmap)
    ├── Overview Dashboard: Overall Health Score, Gate Status (PASSED/FAILED), Metric Cards, Top Risks
    ├── Projects Manager: Connected repos, trigger scan modal, framework badges
    ├── Audit Scan Inspector: Real-time scan progression UI with category tabs and log stream
    ├── Findings Detail & Drawer Inspector: Code evidence, OWASP classification, step-by-step repro, copyable prompt
    ├── VibePolish Visual Inspector: Side-by-side anti-pattern matrix and visual comparison cards
    ├── VibeCare Health Center: Dependency drift timeline, SLO monitor, and monthly cost budget widgets
    └── Remediation Queue: Actionable checklist for developer fix validation
```

---

## Phase Roadmap & Progress

### Phase 0: Discovery & Implementation Plan (Completed)
- [x] Inspect workspace structure & local configuration
- [x] Extract full 23 security checks from `YapılmasıGerekenGuvenlik.pdf`
- [x] Extract full 30 UI anti-patterns from `YapılmasıGerekenUI.pdf`
- [x] Write `shipguard-saas-dashboard.md` plan artifact
- [ ] **PAUSE & WAIT FOR USER APPROVAL** before Phase 1 code implementation.

### Phase 1: ShipGuard Core SaaS MVP Dashboard (Next Step)
- [ ] Initialize clean React + TypeScript + Vite project (or modern Vanilla JS/TS architecture)
- [ ] Build Design System (CSS variables, Plus Jakarta Sans font, crisp dark mode palette, zero AI clichés)
- [ ] Implement Typed Security Data Models & 23 Rule Catalog with findings, evidence, & Claude auto-fix prompts
- [ ] Build Sidebar Navigation with ShipGuard, VibePolish, VibeCare slots
- [ ] Build Overview Dashboard Page (Health Score Gauge, Release Gate Banner, Priority Action Bar)
- [ ] Build Projects List & Connection Modal (GitHub repo connector / Vercel preview URL connector)
- [ ] Build Interactive Scan Runner Page with real-time audit log stream
- [ ] Build Security Findings Table & Slide-Over Inspector Drawer
- [ ] Build Remediation Queue with copyable prompt snippets

### Phase 2: VibePolish UI Audit Layer (Follow-up)
- [ ] Implement 30 UI Anti-Pattern Matrix Inspector
- [ ] Add side-by-side visual comparison preview components (AI Cliché vs ShipGuard Refactored)
- [ ] Add custom VibePolish audit prompt builder

### Phase 3: VibeCare Sustainability Layer (Follow-up)
- [ ] Implement Dependency Drift Tracker (npm/pip outdated CVE alerts)
- [ ] Build Cloud & LLM Budget Alert Monitor ($50/$80/$100% threshold gauge)
- [ ] Build Automated Backup Status & SLO uptime dashboard

---

## Verification Plan

### Automated Verification
1. Build & Type Check: Run `npm run build` or `tsc` to verify clean TypeScript compilation without errors.
2. Lint & Standard Compliance: Execute `.agent/scripts/checklist.py .` to ensure zero security vulnerabilities or linting errors.

### Dogfooding Manual Verification
1. **Security Pre-flight Check:** Verify that zero hardcoded secrets exist in client code, input forms have strict validation, error messages mask internal details, and cookies/headers follow production standards.
2. **VibePolish UI Check:** Verify that the UI uses custom Plus Jakarta Sans typography, non-standard corporate color palette (slate/navy/emerald), 1px subtle borders, no 999px pill overload, no Lucide icon flooding, no em-dashes, and clean micro-interactions.
