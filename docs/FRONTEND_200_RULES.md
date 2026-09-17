# The Master Frontend Engineering Rulebook: 200 Production-Grade UI Rules

> **Compiled by:** Senior Frontend Specialist & Security Architect  
> **Target:** Enterprise Web Applications, B2B SaaS, and Code Scanners (Zelsis Engine)  
> **Standard:** Production-Grade 2026 (Next.js 15, React 19, WCAG 2.2 AA, Core Web Vitals)

---

## Index of Categories

- [1. Core Web Vitals, Rendering & Performance (Rules 1–20)](#1-core-web-vitals-rendering--performance-rules-120)
- [2. Accessibility & WCAG 2.2 AA Standards (Rules 21–40)](#2-accessibility--wcag-22-aa-standards-rules-2140)
- [3. State Management, Data Fetching & Caching (Rules 41–60)](#3-state-management-data-fetching--caching-rules-4160)
- [4. Form UX, Input Validation & Defensive Interactions (Rules 61–80)](#4-form-ux-input-validation--defensive-interactions-rules-6180)
- [5. Error Boundaries, Resilience & Recovery (Rules 81–100)](#5-error-boundaries-resilience--recovery-rules-81100)
- [6. Typography, Micro-Layout & Data Density (Rules 101–120)](#6-typography-micro-layout--data-density-rules-101120)
- [7. Interaction Design, Motion & Animation Lifecycles (Rules 121–140)](#7-interaction-design-motion--animation-lifecycles-rules-121140)
- [8. Dark Mode, Color Theory & Visual Psychology (Rules 141–160)](#8-dark-mode-color-theory--visual-psychology-rules-141160)
- [9. Frontend Security, Privacy & Defense-in-Depth (Rules 161–180)](#9-frontend-security-privacy--defense-in-depth-rules-161180)
- [10. Anti-AI-Cliché, Brand Polish & Engineering Rigor (Rules 181–200)](#10-anti-ai-cliché-brand-polish--engineering-rigor-rules-181200)

---

## 1. Core Web Vitals, Rendering & Performance (Rules 1–20)

1. **Explicit Dimensions on Images & Media:** All `<img>`, `<video>`, and Next.js `<Image>` tags must have explicit `width`/`height` or aspect-ratio containers to prevent Cumulative Layout Shift (CLS < 0.1).
2. **Raw HTML `<img>` Ban in Next.js:** Raw `<img>` tags without WebP/AVIF compression or lazy-loading are prohibited in favor of Next.js Image optimization.
3. **Font Display Swap Standard:** All web fonts (`@font-face` or Google Fonts) must specify `font-display: swap` to prevent Flash of Invisible Text (FOIT).
4. **DOM Node Count Threshold:** Total DOM nodes on any single route must not exceed 1,500 elements; maximum DOM depth must stay under 32 levels.
5. **Virtualization for Long Lists:** Any tabular or card list rendering more than 100 items must implement windowing/virtualization (`@tanstack/react-virtual`).
6. **Layout Thrashing Prevention:** Never interleave DOM style reads (`offsetWidth`, `getBoundingClientRect`) with DOM style writes in the same execution frame.
7. **CSS `content-visibility: auto` on Off-Screen Containers:** Heavy off-screen cards and tab panels must use `content-visibility: auto` with `contain-intrinsic-size` to skip initial off-screen rendering.
8. **Subresource Hinting:** Critical external CDNs and API origins must be declared in `<head>` via `<link rel="preconnect">` and `<link rel="dns-prefetch">`.
9. **Zero Heavy Base64 in JSX:** Inline Base64 image URIs exceeding 1,000 characters embedded in JSX bundles are prohibited to avoid parser blocking and bundle bloat.
10. **Client Component Boundary Minimization:** Mark components with `'use client'` only at the leaf nodes requiring state or events, keeping data fetching in Server Components.
11. **Dynamic Import for Modals & Drawers:** Heavy components (modals, charts, syntax highlighters) must be dynamically loaded with `next/dynamic` (`ssr: false`).
12. **Debounced Window & Scroll Observers:** Any scroll or resize event listener must be debounced or throttled with `requestAnimationFrame` to prevent main-thread choking.
13. **Web Worker Offloading for Heavy Compute:** Parsing large ASTs, diff calculations, or cryptographic hashing must be delegated to a Web Worker, not executed on the UI thread.
14. **CSS Hardware Acceleration Restraint:** Use `transform: translate3d(0,0,0)` and `will-change` selectively only on elements actively animating; never apply globally.
15. **Tree-Shaking Import Audit:** Import only specific named symbols from icon and utility libraries (e.g. `import { Search } from 'lucide-react'`), never namespace imports (`import * as Icons`).
16. **SVG Path Optimization:** SVG icons must be stripped of metadata, hidden layers, and unnecessary viewBox coordinates, keeping file size under 4KB per icon.
17. **React `memo` & `useCallback` on High-Frequency Children:** Components rendered inside high-frequency loops or chart wrappers must memoize callback references to avoid cascade re-renders.
18. **Hydration Mismatch Eradication:** Never render browser-only values (`window.location`, `new Date()`, `localStorage`) on the initial SSR pass without a hydration guard.
19. **Bundle Budget Hard Limit:** Main JS bundle chunks must not exceed 150KB (gzipped); total initial JS must stay under 300KB.
20. **Zero Synchronous Script Tags:** All third-party analytics, chat widgets, and telemetry scripts must load with `async` or `defer` (or via `next/script` with `strategy="lazyOnload"`).

---

## 2. Accessibility & WCAG 2.2 AA Standards (Rules 21–40)

21. **No Naked `outline-none`:** Stripping default browser focus indicators with `outline-none` is strictly forbidden unless paired with `focus-visible:ring-2` or equivalent.
22. **Accessible Name for All Interactive Elements:** Every `<button>`, `<a>`, and `<input>` must have visible text, an `aria-label`, or `aria-labelledby`.
23. **Minimum 4.5:1 Contrast Ratio:** Body text and technical data must meet WCAG AA contrast (4.5:1 for regular text, 3:1 for large text and UI components).
24. **Semantic HTML over Div Clickers:** Interactive clickable triggers must use native `<button>` or `<a>` elements; using `<div onClick>` without keyboard handling is banned.
25. **Form Input Label Binding:** Every form input must have a dedicated `<label htmlFor="...">` with matching `id`, or explicit `aria-label`.
26. **Escape Key Modal Dismissal:** All dialogs, drawers, and overlay popups must dismiss when the user presses the `Escape` key.
27. **Focus Trapping in Modals:** When a modal is open, keyboard focus (`Tab` / `Shift+Tab`) must be constrained strictly within the modal container.
28. **Focus Return on Dismissal:** When a modal or drawer closes, keyboard focus must return to the exact button or trigger that opened it.
29. **Screen Reader Live Regions (`aria-live`):** Dynamic feedback (toasts, scan progress alerts, real-time counters) must be wrapped in `aria-live="polite"` or `role="status"`.
30. **No Positive `tabIndex`:** Assigning `tabIndex > 0` is forbidden; navigation order must follow the natural DOM sequence or use `tabIndex={0}` / `tabIndex={-1}`.
31. **Touch Target Sizing (Min 44x44px):** All interactive buttons, links, and icons must have an effective click/touch target of at least 44x44 CSS pixels.
32. **Skip to Main Content Link:** Top-level layouts must provide a hidden "Skip to main content" link that becomes visible on first keyboard tab.
33. **Decorative Image Alt Tagging:** Purely decorative icons or illustrations must have `alt=""` and `aria-hidden="true"` so screen readers bypass them.
34. **Accordion & Dropdown State Binding:** Collapsible elements must reflect their state via `aria-expanded="true|false"` and reference content via `aria-controls`.
35. **Color Independence for Status:** Never convey state solely through color; pair red/green/amber badges with an icon, descriptive text, or textual status label.
36. **Table Header Scoping:** All data tables must use `<thead>`, `<tbody>`, and `<th scope="col">` / `<th scope="row">` to provide tabular navigation context.
37. **`prefers-reduced-motion` Media Query Respect:** All keyframe animations, pulsing effects, and smooth scrolls must be disabled or simplified when `prefers-reduced-motion: reduce` is active.
38. **Screen Reader Only Utility (`.sr-only`):** Contextual explanations needed by non-sighted users must be included in the DOM using an accessible `.sr-only` class.
39. **Error Announcement in Forms:** Form validation errors must be linked to their input via `aria-describedby="field-error-id"` and marked with `aria-invalid="true"`.
40. **Icon Font Deprecation:** Icon fonts (which can fail to render and lack semantic names) are prohibited in favor of inline SVG with accessible labels.

---

## 3. State Management, Data Fetching & Caching (Rules 41–60)

41. **Stale-While-Revalidate Caching:** Client-side query clients (React Query / SWR) must serve cached data instantly while refetching in the background.
42. **AbortController on Re-Fetch & Unmount:** All asynchronous `fetch()` requests must pass an `AbortSignal` to cancel orphaned requests on component unmount or input changes.
43. **Optimistic UI Updates with Instant Rollback:** Mutations that toggle states (e.g. resolve finding, bookmark) must update UI instantly and rollback cleanly if the API fails.
44. **Server State vs Client State Isolation:** Never duplicate remote server state into local `useState` unless specifically intended for offline editing.
45. **URL as Single Source of Truth for Filters:** Active search queries, tab selections, pagination indices, and filters must be synced to URL search parameters.
46. **Deduplication of Parallel Requests:** Identical API requests triggered by sibling components within 2000ms must be deduplicated into a single network call.
47. **Exponential Backoff on 5xx Failures:** Failed queries must retry using jittered exponential backoff (e.g. 1s, 2s, 4s), stopping after 3 attempts.
48. **Immutable State Transitions:** Never mutate objects or arrays in place; always produce new references or use Immer to guarantee re-render accuracy.
49. **Granular Selector Memoization:** When subscribing to global state (Zustand/Redux), select only the primitive slice required to prevent unnecessary re-renders.
50. **Form Draft Local Storage Auto-Save:** Long multi-field forms must persist drafts to `localStorage` with a 1000ms debounce to prevent data loss on accidental tab close.
51. **Stale Query Invalidation on Mutation:** Any mutation (e.g., triggering a scan, updating an API key) must explicitly invalidate relevant query keys in cache.
52. **Non-Blocking Background Revalidation:** Tab focus revalidation (`revalidateOnFocus`) must never cause visible layout shifts or loading spinners.
53. **Infinite Scroll Pagination Bounds:** Infinite scroll lists must enforce a maximum in-memory threshold (e.g., 500 items) or unmount top items to preserve RAM.
54. **Payload Serialization Safety:** Never store non-serializable objects (functions, class instances, DOM references) inside state stores or localStorage.
55. **Clean Unsubscribe Pattern:** Every `useEffect` subscribing to websockets, event emitters, or timers must return a cleanup function.
56. **Waterfalls Prevention in Nested Fetching:** Sibling or parent-child components must not chain dependent fetch waterfalls; prefer parallel `Promise.all` or unified server endpoints.
57. **Cache Eviction & TTL Hard Caps:** Cache entries stored in indexedDB or browser storage must have an explicit time-to-live (TTL) and eviction policy.
58. **Offline Detection & Fallback Banner:** Application must listen to `navigator.onLine` and display an unobtrusive offline badge when disconnected.
59. **Session Expiry Non-Destructive Intercept:** When an auth token expires mid-session, prompt with a re-auth modal without wiping unsubmitted form data.
60. **Idempotency Key Header on Write Requests:** Destructive mutations (e.g., billing, scans, deletions) must include an `Idempotency-Key` UUID header to prevent duplicate execution.

---

## 4. Form UX, Input Validation & Defensive Interactions (Rules 61–80)

61. **Double-Submit Lockout:** Submit buttons must be disabled and display a loading indicator immediately upon initial click until the promise resolves.
62. **Instant Client-Side Schema Validation:** Forms must validate inputs against a strict schema (Zod) on blur or change, not only on submit.
63. **Contextual Inline Error Placement:** Error messages must appear directly below the failing input with red accent and icon, never in a generic popup banner.
64. **No Auto-Focus on Mobile:** Do not programmatically auto-focus inputs on mobile devices, as it causes abrupt virtual keyboard popups and layout shifts.
65. **HTML5 `inputMode` Specification:** Numeric fields (PINs, CVSS scores, ports) must declare `inputMode="numeric"` or `inputMode="decimal"` for appropriate mobile keyboards.
66. **No Paste Blocking:** Never disable copy/paste functionality on password, token, or repository URL inputs.
67. **Auto-Scroll to First Invalid Input:** When a form submission fails validation, smoothly scroll the viewport to the first invalid field and focus it.
68. **Clear Destructive Action Confirmation:** Deleting a project, clearing scan history, or revoking API keys must require typing the name or an explicit 2-step confirmation.
69. **Unsaved Changes Warning (`beforeunload`):** If a user attempts to navigate away with dirty form state, trigger a native or custom prompt warning of data loss.
70. **Password & Token Visibility Toggle:** Any masked password or secret key input must provide an accessible eye icon button to toggle plain-text visibility.
71. **Leading/Trailing Whitespace Auto-Trim:** Sanitize string inputs by automatically trimming accidental leading and trailing whitespace on submit.
72. **Accessible Custom Select Component:** Custom dropdown selects must support keyboard arrow navigation, `Enter` selection, and `Escape` closing.
73. **Search Input Debounce (300ms):** Real-time filter and search inputs must debounce typing by at least 300ms before triggering heavy filter pipelines.
74. **Drag-and-Drop Visual Boundary Feedback:** File dropzones must provide clear dashed border color changes and visual feedback when a valid file is hovered over.
75. **File Upload Client-Side Size & Type Check:** Validate file extensions and maximum byte sizes in the browser before attempting upload to backend storage.
76. **Autofill / Autocomplete Standard Attributes:** Form inputs must specify standard `autoComplete` attributes (e.g., `email`, `current-password`, `new-password`, `organization`).
77. **Character Counter on Constrained Fields:** Textareas with character limits must display an active counter (`240 / 500 characters`) with warning colors as limit approaches.
78. **Interactive Form Input Focus Ring:** Every text input, checkbox, and select must show a crisp 2px colored focus ring on active focus.
79. **Radio & Segmented Control Default Selection:** Segmented button controls or radio groups must always have a pre-selected default option.
80. **One-Click Clear Input Button:** Search inputs must include a subtle `✕` button to clear text in a single click without holding backspace.

---

## 5. Error Boundaries, Resilience & Recovery (Rules 81–100)

81. **Granular Component-Level Error Boundaries:** Wrap high-risk widgets (charts, code diff view, third-party embeds) in individual `ErrorBoundary` wrappers to prevent full-page crashes.
82. **Actionable "Try Again" Recovery CTA:** Every error boundary UI must provide a "Try Again" or "Reload Component" button that resets the error boundary state.
83. **Unique Correlation ID Display:** Production errors must display a traceable incident or correlation ID (e.g., `Ref: err_9f82a1`) for user support lookup.
84. **Zero Raw Stack Traces in Production:** Never expose backend stack traces, SQL error strings, or internal file paths in user-facing UI.
85. **Fallback Avatar on Image Failure:** User and project avatars must automatically render initials or a neutral fallback icon via `onError` event handler.
86. **Silent Telemetry Error Dispatch:** Client-side exceptions caught by error boundaries must be automatically logged to telemetry (Sentry/Datadog) without sensitive PII.
87. **Corrupted LocalStorage Auto-Recovery:** Wrap `JSON.parse(localStorage.getItem(...))` in `try/catch`; on corruption, purge the stale key and recover with defaults.
88. **Feature Flag Fallback Default:** When a feature flag provider fails or times out, the application must silently fall back to the safe default state without breaking.
89. **API 429 Rate Limit Countdown:** When encountering an HTTP 429 response, display a user-friendly countdown timer reflecting the `Retry-After` header.
90. **Intelligent 404 Route Suggestions:** 404 pages must offer links to the dashboard, recent projects, and documentation rather than a dead-end page.
91. **Network Timeout Fallback:** Every fetch request must enforce a strict timeout (e.g. 10 seconds) with an explicit "Network timed out" friendly error message.
92. **Safe Deep Property Access:** Avoid unhandled `TypeError: Cannot read property of undefined` by enforcing optional chaining (`?.`) and nullish coalescing (`??`).
93. **Graceful Degradation for WebGL / Canvas:** If hardware-accelerated Canvas or WebGL is unsupported or crashes, fall back to SVG or static images.
94. **Clipboard Permission Fallback:** If `navigator.clipboard.writeText()` is rejected by browser permissions, fall back to a hidden textarea `document.execCommand('copy')`.
95. **Mock Sandbox Fallback for Demo Users:** When backend microservices are unreachable or user is in demo mode, serve static mock audit fixtures seamlessly.
96. **Storage Quota Exceeded Handling:** Catch `DOMException: QuotaExceededError` on local storage writes and clear non-critical caches before failing.
97. **Uncaught Promise Rejection Listener:** Attach a global `unhandledrejection` window listener to capture and report silent background failures.
98. **Broken Dependency Graceful UI:** When an external dependency (e.g. CDN script) fails to load, disable the dependent action and inform the user cleanly.
99. **Contextual Help Link on Systematic Errors:** When a scan fails due to invalid git credentials or private repo access, link directly to documentation.
100. **State Reset on Route Change:** Clear lingering error states and notifications when the user navigates to a different page or project.

---

## 6. Typography, Micro-Layout & Data Density (Rules 101–120)

101. **Monospace Standardization for Machine Data:** All CVE IDs, rule codes, SHA hashes, IP addresses, file paths, and metrics must use **JetBrains Mono** (`font-mono`).
102. **Tabular Numerals for Dynamic Counters:** Any changing numerical values, countdowns, or financial metrics must use `font-variant-numeric: tabular-nums` to prevent horizontal jitter.
103. **Line Length Constraint (45–75 Characters):** Prose and paragraph text must have a maximum width of `65ch` or `max-w-prose` for optimal reading ergonomics.
104. **Typographic Scale Ratio:** Maintain a disciplined typographic hierarchy (e.g. 11px, 12px, 14px, 16px, 20px, 24px, 32px), avoiding random intermediate pixel sizes.
105. **Fluid Typography with `clamp()`:** Headings and banner displays must use fluid sizing (e.g., `clamp(1.5rem, 4vw, 2.5rem)`) for seamless responsive adaptation.
106. **Heading Hierarchy Sequencing:** Headings must follow strict semantic order (`<h1>` → `<h2>` → `<h3>`); never skip levels for styling purposes.
107. **Proportional Line-Height:** Body copy must have a line-height between `1.4` and `1.6`; headings must have tighter line-height between `1.1` and `1.25`.
108. **Large Heading Tracking Tightening:** Headings above 24px must apply negative letter-spacing (`tracking-tight` or `-0.02em`) to avoid sprawling letters.
109. **Uppercase Badge Tracking Expansion:** Uppercase text and pill labels must apply positive letter-spacing (`tracking-[0.6px]` or `0.05em`) for legibility.
110. **Truncation with Accessible Tooltip:** Any single-line truncated text (`truncate`) must include a `title` attribute or tooltip showing the full unclipped string.
111. **Strict Border-Radius Scale:** Never mix arbitrary border radii; strictly adhere to a 3-tier token system (e.g. `rounded` 4px, `rounded-lg` 8px, `rounded-xl` 12px).
112. **Vertical Rhythm Rhythm Baseline:** Spacing between sections and components must follow an 8pt grid (8px, 16px, 24px, 32px, 48px, 64px).
113. **Disciplined Z-Index Scale:** Eliminate arbitrary z-index numbers (`z-[9999]`); use semantic levels: base (0), dropdown (10), sticky (20), modal (50), toast (100).
114. **1px Subtle Borders over Heavy Shadows:** High-density enterprise interfaces must use subtle 1px borders (`border border-white/10`) rather than fuzzy drop-shadows.
115. **Balanced Headline Wrapping:** Use CSS `text-wrap: balance` on hero titles and modal headers to eliminate awkward single-word lines.
116. **Orphan Prevention on Paragraphs:** Apply `text-wrap: pretty` to body text blocks to prevent typographic orphan words on the final line.
117. **Icon and Label Baseline Centering:** When pairing an icon with text in a flex container, always use `items-center` and specify explicit icon dimensions.
118. **Severity Badge Dimension Equality:** All CVSS/Severity badges must share uniform minimum dimensions (`min-w-[62px]`, `py-[3px]`) and centered alignment.
119. **Custom Scrollbar Styling:** Custom scrollbars must match the dark enterprise theme (`w-1.5`, track transparent, thumb `rgba(255,255,255,0.15)`).
120. **Zero Pure Black (#000) for UI Text:** In dark mode, primary body text must be soft white (`#EDEDED`) and secondary text zinc (`#A1A1AA`) to reduce eye strain.

---

## 7. Interaction Design, Motion & Animation Lifecycles (Rules 121–140)

121. **Mandatory Animation Cleanup on Unmount:** All GSAP timelines, Lottie players, and canvas loops must call `kill()` or `revert()` on React unmount to prevent memory leaks.
122. **Sub-100ms Hover & Active Feedback:** Interactive buttons and table rows must respond to cursor hover and click within 100ms through subtle border/bg transitions.
123. **Modal Backdrop Click Dismissal:** Modal scrims must handle backdrop click dismissal (`if (e.target === e.currentTarget) onClose()`).
124. **Smooth Scroll Restraint:** Do not force `scroll-behavior: smooth` globally on `html` as it degrades keyboard navigation and automated test reliability.
125. **Synchronized Skeleton Shimmer:** All skeleton loader instances visible in the viewport must share the same synchronized 1.5s linear CSS shimmer animation.
126. **Physical Cubic-Bezier Transitions:** Use high-end physical easing curves (`cubic-bezier(0.16, 1, 0.3, 1)`) for sheets and modals; avoid linear motion.
127. **Toast Duration Proportional to Content:** Toast notifications must auto-dismiss dynamically based on word count (minimum 3000ms, plus 500ms per 10 words).
128. **Mobile Swipe-to-Dismiss Threshold:** Touch drawers must require at least 30% drag distance or high velocity before triggering a dismiss action.
129. **Pull-to-Refresh Haptic Feedback:** Mobile touch interfaces implementing pull-to-refresh must trigger subtle haptic vibration (`navigator.vibrate`) on release.
130. **Cursor Pointer Only on Interactive Elements:** Do not place `cursor-pointer` on static containers, card backgrounds, or disabled buttons.
131. **Interactive Element Touch Clearance:** Sibling interactive buttons must have at least an 8px visual gap to prevent accidental misclicks.
132. **Tooltip Hover Delay (200ms):** Tooltips must wait 200ms before appearing to prevent distracting screen flickering when moving the mouse across elements.
133. **Multi-Stage Scan Progress Visualization:** Never display a single flat progress bar for multi-step jobs; provide discrete stages with state badges.
134. **Drag-and-Drop Ghost Element:** Interactive drag-and-drop elements must render a semi-transparent ghost preview and clear target drop-zone indicators.
135. **Accordion Smooth Height Interpolation:** Collapsible accordions must animate height smoothly without content clipping or abrupt snap jumps.
136. **Zero Auto-Playing Audio:** Audio feedback must never play automatically; provide an explicit toggle for sound effects.
137. **Keyboard Accessible Drag Reordering:** Drag-and-drop lists must provide alternative keyboard shortcuts (e.g. `Space` to pick up, `Arrows` to move, `Enter` to drop).
138. **Context Preservation on Route Transition:** Persist scroll position and tab selection when navigating back from a detail inspection view.
139. **Click-Outside Listener Cleanup:** Custom dropdown and popover click-outside listeners must be detached immediately when the dropdown closes.
140. **Active Tab Linear Indicator:** Active navigation tabs must render a solid high-contrast indicator (e.g. `inset 2px 0 0 #3b82f6`) along with text highlight.

---

## 8. Dark Mode, Color Theory & Visual Psychology (Rules 141–160)

141. **Dark Luxury Base Background Palette:** Dark themes must use deep gray `#0A0A0A` for canvas and `#141414` for cards; avoid harsh pitch black `#000000`.
142. **Purple Ban on AI Interfaces:** Avoid clichéd AI gradients (violet, purple neon glow); use industrial engineering palettes (emerald, amber, blue, zinc).
143. **Semantic Color Exclusivity:** Reserve red strictly for critical vulnerabilities, amber for warnings, green for clean deployment gates, and blue for info.
144. **CSS Root Variable Tokens:** Color codes must be abstracted into semantic CSS custom properties (`--color-critical`, `--color-high`, etc.).
145. **Subtle Alpha-Blended Badges:** Status badge backgrounds must use subtle 10–12% opacity tints (`rgba(239, 68, 68, 0.12)`) paired with high-contrast text.
146. **Disabled State Visual Distinction:** Disabled elements must show `opacity-50`, `pointer-events-none`, and `cursor-not-allowed` to convey unavailability.
147. **Color-Blind Accessible Chart Palettes:** Data visualizations and severity charts must use color palettes distinguishable by users with Deuteranopia and Protanopia.
148. **Ambient Glow Restraint:** Eliminate sprawling 200px blurred gradient bubbles; rely on clean 1px borders and structured lighting focus points.
149. **Neutral Gray Undertone Consistency:** Do not mix cool grays (slate), warm grays (stone), and neutral grays (zinc) within the same view.
150. **High Contrast Mode Support:** Ensure borders and interactive elements remain distinct when Windows High Contrast Mode or forced colors are active.
151. **Soothing Pulsing Frequency:** Ambient status indicator pulses (`animate-pulse`) must cycle at a calm 2s to 3s cadence, never frantic flashing.
152. **Modal Scrim Blur & Opacity:** Modal backdrop overlays must combine 60–75% black opacity with subtle `backdrop-blur-sm` to maintain focus without disorientation.
153. **Dark Mode Image Inversion Protection:** Never apply CSS color inversion filters to content images, photos, or corporate customer logos.
154. **Subtle Hover Contrast Differential:** Button and card hover states in dark mode must increase background luminance by no more than 4–8%.
155. **Zero Low-Contrast Gray on Dark:** Informative secondary text must never fall below `#71717A` (zinc-500) to ensure readability against `#0A0A0A`.
156. **White Border Alpha Stacking:** Use stacked white alphas (`border-white/5` for dividers, `border-white/10` for cards, `border-white/20` for active items).
157. **System Theme Preference Detection:** App must respect `prefers-color-scheme: dark` by default, while supporting explicit manual override.
158. **Alert Banner Contrast Hierarchy:** Error and warning alert banners must pair light-tinted backgrounds with solid borders and saturated icons.
159. **Chart Tooltip Dark Styling:** Data charts must render dark tooltips with 1px border and monospace numbers, never generic white browser tooltips.
160. **Brand Accent Restraint:** The primary brand accent color must be applied to key CTAs and active states, not splashed across every header and icon.

---

## 9. Frontend Security, Privacy & Defense-in-Depth (Rules 161–180)

161. **XSS Sanitization for Rendered HTML:** Any HTML rendered via `dangerouslySetInnerHTML` must be sanitized with DOMPurify (`DOMPurify.sanitize()`).
162. **Reverse Tab-Nabbing Prevention:** All external anchor tags (`target="_blank"`) must include `rel="noopener noreferrer"`.
163. **Zero Secrets in Client Bundles:** Environment variables exposed to the frontend (`NEXT_PUBLIC_`) must never contain private tokens, secret keys, or passwords.
164. **Server Action Authentication Verification:** Next.js Server Actions invoked from client forms must authenticate and authorize the session server-side.
165. **Client-Side Supabase RLS Awareness:** Frontend code must assume client queries can be inspected; rely on Row Level Security (RLS) on the database.
166. **Strict Content Security Policy (CSP):** Serve robust CSP HTTP headers prohibiting `unsafe-inline` scripts and restricting `connect-src` to approved APIs.
167. **Clickjacking Defense:** Prevent embedding inside malicious third-party iframes via `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`.
168. **Secure Cookie Configuration:** Authentication cookies must be flagged `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`).
169. **Sensitive Parameter Stripping from URLs:** Access tokens, temporary secrets, and PII must never be stored in URL search parameters.
170. **Local Storage Token Avoidance:** Store sensitive access tokens in `HttpOnly` session cookies rather than `localStorage` to mitigate XSS exfiltration.
171. **Clipboard Memory Auto-Clear:** Ephemeral secrets copied to clipboard (e.g. 2FA recovery codes) must ideally be cleared from memory after 60 seconds.
172. **Sandboxed Iframe Attributes:** Any embedded third-party iframe must specify `sandbox="allow-scripts allow-same-origin"`.
173. **Dependency CVE Audit in CI:** Automated builds must fail if `npm audit` or Zelsis SCA detects high/critical vulnerabilities in package dependencies.
174. **Subresource Integrity (SRI) on CDNs:** Any external script or stylesheet loaded from an external CDN must include an `integrity` hash and `crossorigin`.
175. **SVG Upload XML Entity Sanitization:** User-uploaded SVGs must be parsed to strip malicious `<script>`, `onload`, and XML entity injection payloads.
176. **Open Redirect Validation:** When redirecting via a `returnUrl` or `redirect` query parameter, validate that the destination is on the same origin.
177. **Client-Side Exponential Backoff on 401/403:** Avoid hammering backend auth endpoints in tight loops when credentials are rejected.
178. **PII Masking in Client Error Logs:** Automatically redact credit cards, bearer tokens, and email addresses before forwarding logs to Sentry/Datadog.
179. **Disable Autocomplete on Sensitive Credentials:** Banking or sensitive PIN fields must specify `autoComplete="off"` where appropriate.
180. **Defense Against Prototype Pollution:** Freeze or validate deeply merged JSON payloads before mutating global runtime configurations.

---

## 10. Anti-AI-Cliché, Brand Polish & Engineering Rigor (Rules 181–200)

181. **Bento Grid Overuse Prohibition:** Do not default to Apple-style bento grids for every dashboard; choose layouts based on natural data flow.
182. **Elimination of Fake Testimonials:** Replace generic stock photos and fictitious quotes ("Loved by builders — Sarah K.") with verifiable metrics.
183. **Hero Split (Left/Right) Avoidance:** Break away from generic "Title on left, screenshot on right" layouts; experiment with centered narratives and live interactive demos.
184. **Ban on Arbitrary Sparkle Icons:** Do not attach the 4-pointed Lucide `Sparkles` icon to every button; reserve it exclusively for genuine generative AI features.
185. **"Not X, but Y" Copywriting Ban:** Eradicate formulaic AI marketing headlines (e.g., *"Not just a code scanner, your deployment superpower"*); write honest value propositions.
186. **Em-Dash (—) Addiction Eradication:** Eliminate excessive em-dashes inserted by LLMs; use clean, structured sentence flows with standard punctuation.
187. **9999px Pill Button Restraint:** Avoid stadium/pill buttons (`rounded-full`) across all enterprise tools; use refined 6px to 10px rounded corners.
188. **Meaningless Glassmorphism Removal:** Replace washed-out semi-transparent frosted glass layers with solid, high-contrast, readable surfaces.
189. **Fake Terminal Mockup Ban:** Do not insert dummy black terminal mockups running `npx create-app` on unrelated product screens; show real UI interfaces.
190. **Verifiable Social Proof Formatting:** Avoid vague claims like "Join 10,000+ engineers" unless backed by live telemetry and specific numbers.
191. **High-Fidelity Product Previews:** Use real interactive component previews or high-resolution UI captures instead of abstract placeholder wireframes.
192. **Dual Empty State Pattern:** Every data view must provide distinct states for "Zero Data Available" (clean reassuring state) vs "Filtered Out" (SearchX reset).
193. **Deep-Linking to Authoritative Sources:** Technical findings must link directly to official vulnerability records (NVD CVE, NIST, OWASP, GitHub Advisory).
194. **Multi-Stage Scanning Disclosure:** Long operations must communicate internal phases (Connecting → Resolving → AST Analysis → Generating Report).
195. **Zero Dead Links (`href="#"`):** Every link in navigation and footers must point to a real functional route; dead placeholder hash links are banned.
196. **Real Legal & Privacy Framework:** Footers must link to complete, transparent Terms of Service and GDPR/KVKK-compliant Privacy Policy pages.
197. **Subtle Micro-Hover Scaling:** Restrict hover transforms to subtle 2px translations; avoid frantic `scale(1.05)` bounces on every card.
198. **Persistent UI State (Storage Sync):** User workspace preferences (sidebar collapsed, active tab, table density) must persist across reloads.
199. **Contextual Command Palette (Cmd+K):** Provide a global keyboard shortcut palette for power users to navigate, search findings, and run actions instantly.
200. **Strict Swiss/Linear Active Tab Indicators:** Active navigation states must render an unambiguous physical indicator (e.g. left inset border) for instant orientation.
