---
trigger: always_on
---

# UI_ENGINEERING_STANDARDS.md — Frontend & UI Quality Invariants

> **Scope:** Mandatory for all frontend components, layouts, pages, styles, and scans across Zelsis.  
> **Rule Level:** P0 Universal — Binding on all agents and human contributors.

---

## 1. Core Web Vitals & Rendering Performance (CWV)
- **Zero Layout Shift (CLS < 0.1):** All `<img>`, `<video>`, and Next.js `<Image>` tags must have explicit `width`/`height` or aspect-ratio wrapper containers.
- **Next.js Image Optimization:** Raw `<img>` tags without WebP/AVIF compression or lazy-loading are strictly forbidden in `.tsx`/`.jsx` files.
- **Font Display Swap:** Web fonts must specify `font-display: swap` to prevent Flash of Invisible Text (FOIT).
- **DOM Node Cap (<1500):** Single-page view DOM nodes must not exceed 1,500 elements. Tabular or card data exceeding 100 items must implement virtualization (`@tanstack/react-virtual`).
- **Client Component Leaf Rule:** Place `'use client'` strictly at interactive leaf nodes. Keep data fetching, layouts, and static content in React Server Components (RSC).
- **Dynamic Imports:** Heavy components (modals, syntax highlighters, charts, sandboxes) must use `next/dynamic` (`ssr: false`).
- **No Heavy Inline Base64:** Embedding Base64 data URIs exceeding 1,000 characters in JSX is prohibited.

---

## 2. Accessibility & WCAG 2.2 AA Standards (A11Y)
- **No Naked `outline-none`:** Stripping default browser focus indicators with `outline-none` is strictly forbidden unless immediately paired with `focus-visible:ring-2` or equivalent visible focus indicator.
- **Accessible Names:** Every `<button>`, `<a>`, and `<input>` must provide accessible text, an `aria-label`, or `aria-labelledby`.
- **Keyboard Escape Dismissal:** All dialogs, drawers, and overlay modals must dismiss cleanly on the `Escape` key.
- **Modal Focus Trapping:** Keyboard navigation (`Tab` / `Shift+Tab`) must be strictly constrained inside active modals and returned to the trigger element upon closing.
- **Touch Target Threshold (Min 44x44px):** All interactive buttons, icons, and tap triggers must have an effective hit target of at least 44x44 CSS pixels.
- **Color Independence:** Never convey state solely through color; status badges and alerts must include an icon or descriptive text label.
- **`prefers-reduced-motion`:** Respect user system accessibility settings by disabling or softening pulse effects, smooth scroll, and transforms when `prefers-reduced-motion: reduce` is active.

---

## 3. State Management & Data Fetching Integrity
- **Stale-While-Revalidate:** Serve cached data immediately while revalidating in the background.
- **AbortController on Re-Fetch:** All asynchronous API requests must attach an `AbortSignal` to cancel stale requests on component unmount or fast parameter changes.
- **Optimistic UI with Rollback:** User-toggled actions (e.g. resolve finding, bookmark, toggle status) must update the UI immediately and roll back gracefully on API failure.
- **URL Single Source of Truth:** Active search filters, sort criteria, pagination indexes, and active tab selections must sync to URL search parameters.
- **Clean Subscriptions:** Every `useEffect` subscribing to websockets, event listeners, observers, or interval timers must return an explicit cleanup function.

---

## 4. Form UX & Defensive Interactions
- **Double-Submit Lockout:** Submit buttons must disable and display a loading indicator immediately on click until the mutation resolves.
- **Instant Client Schema Validation:** Validate form inputs using strict Zod schemas on blur and change before submit.
- **Never Block Paste:** Disabling clipboard paste on passwords, API keys, or repository URLs is strictly forbidden.
- **Leading/Trailing Whitespace Auto-Trim:** Sanitize text inputs by automatically trimming whitespace on form submission.
- **Non-Destructive Confirmations:** Deleting projects, clearing logs, or resetting API keys must require typing the name or an explicit 2-step confirmation.

---

## 5. Error Boundaries & Fallbacks
- **Granular Error Boundaries:** Isolate risky widgets (charts, code sandboxes, external embeds) in individual `ErrorBoundary` containers to protect the main application shell.
- **Actionable Recovery:** Error states must provide a clear "Try Again" or "Reload Component" button that resets the error boundary state.
- **Zero Raw Stack Traces:** Never expose backend stack traces, raw database error strings, or sensitive internal paths in user-facing UI.
- **Avatar & Image Fallbacks:** All user and repository avatars must implement `onError` fallback handlers rendering initials or neutral SVGs.

---

## 6. Typography & Data Density
- **JetBrains Mono for Machine Data:** All CVE IDs, rule codes (`#SEC-...`), commit hashes, IP addresses, file paths, and telemetry metrics must use **JetBrains Mono** (`font-mono`).
- **Tabular Numerals:** Any changing numerical values, countdown timers, or financial metrics must specify `font-variant-numeric: tabular-nums`.
- **Line Length Ergonomics:** Paragraph copy and prose must maintain a maximum line width between 45 and 75 characters (`max-w-prose` / `max-w-[65ch]`).
- **Severity Badge Uniformity:** All severity/CVSS badges must adhere to standard dimensions (`min-w-[62px]`, `py-[3px]`, uppercase, centered alignment, `letter-spacing: 0.6px`).
- **1px Subtle Borders:** High-density enterprise interfaces must prioritize crisp 1px borders (`border border-white/10`) over fuzzy drop-shadows.

---

## 7. Interaction Design & Motion Lifecycles
- **Mandatory Unmount Cleanup:** All GSAP timelines, Lottie players, canvas requestAnimationFrames, and resize observers must call `kill()` or `revert()` on React unmount.
- **Sub-100ms Micro-Feedback:** Interactive elements must respond to hover and click states within 100ms via subtle background/border transitions.
- **Modal Backdrop Dismissal:** Modal scrims must dismiss when clicking outside the dialog window (`if (e.target === e.currentTarget) onClose()`).
- **Multi-Stage Scan Progress:** Never use a single flat progress bar for multi-step jobs; provide discrete stages (Connecting → Resolving → AST Analysis → Generating Report) with live percentage and stage status icons.
- **Synchronized Shimmer Skeletons:** All skeleton loading placeholders must share the synchronized 1.5s linear shimmer shader (`SkeletonLoader.tsx`).
- **Swiss/Linear Active Tab Indicators:** Active navigation tabs must feature an unmistakable visual indicator (e.g. left inset border `box-shadow: inset 2px 0 0 #3b82f6`).

---

## 8. Dark Luxury Color Palette & Visual Psychology
- **Base Canvas Palette:** Dark mode must use `#0A0A0A` for canvas background and `#141414` for elevated cards. Avoid harsh pure black `#000000`.
- **Purple Ban on Security Interfaces:** Avoid clichéd AI gradients (violet, purple neon glow); adhere strictly to industrial engineering palettes (emerald, amber, blue, zinc).
- **Semantic Color Exclusivity:** Red is reserved exclusively for critical vulnerabilities; amber for warnings; green for clean deployment gates; blue for telemetry/info.
- **Alpha-Blended Badges:** Severity badge backgrounds must use subtle 10–12% opacity tints paired with high-contrast text.
- **Neutral Undertone Discipline:** Never mix cool grays (slate), warm grays (stone), and neutral grays (zinc) within the same view.

---

## 9. Frontend Security & Defense-in-Depth
- **XSS Sanitization:** Any HTML rendered through `dangerouslySetInnerHTML` must be sanitized with `DOMPurify.sanitize()`.
- **Tab-Nabbing Defense:** All external anchor links (`target="_blank"`) must specify `rel="noopener noreferrer"`.
- **Zero Client Secrets:** Client bundles (`NEXT_PUBLIC_`) must never contain private tokens, service role keys, or database passwords.
- **Server Action Authorization:** All Next.js Server Actions invoked from client components must independently verify session authentication server-side.
- **Secure Link Targets:** All CVE IDs must link directly to authoritative NIST NVD records (`https://nvd.nist.gov/vuln/detail/CVE-...`) with external link indicators.

---

## 10. Anti-AI-Cliché & Brand Distinctiveness
- **Bento Grid Restraint:** Do not default to bento grids; choose layouts matching natural data hierarchy.
- **No Fake Testimonials or Terminal Gimmicks:** Eradicate fictitious user reviews and dummy terminal mockups; use real metrics and authentic UI previews.
- **No Random Sparkle Icons:** Do not place 4-pointed Lucide `Sparkles` icons on non-generative-AI buttons.
- **Dual Empty States:** Every data table or list must render two distinct empty states:
  1. *Clean State (Zero Data):* Reassuring green shield + *"You're clear to deploy"* + primary CTA.
  2. *Filtered State:* `SearchX` icon + *"Try clearing your filters"* 1-click reset action.
- **Zero Dead Links:** Every navigation link and footer element must point to a real functional route; placeholder `href="#"` links are strictly forbidden.
