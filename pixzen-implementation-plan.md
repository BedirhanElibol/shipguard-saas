# Implementation Plan: PIXZEN x ShipGuard Elite Editorial Web Landing Page

Build **PIXZEN x ShipGuard** — a world-class, award-winning futuristic AI agency & SaaS landing page with an ultra-clean monochrome editorial aesthetic, massive Satoshi typography, Lenis smooth scrolling, GSAP ScrollTrigger word scrub manifesto, mouse-following cursor reveal, elastic magnetic buttons, and sticky stacked case study cards.

---

## Generated Visual Assets Inventory

| Asset Name | Path | Purpose |
| :--- | :--- | :--- |
| **Hero Circuit Backdrop** | `public/images/hero_circuit_board.png` | Hero section background architectural render |
| **Security Audit Preview** | `public/images/security_audit_preview.png` | 23 OWASP pre-flight audit rules sticky preview |
| **VibePolish UI Preview** | `public/images/vibepolish_ui_preview.png` | 30 UI Anti-Pattern Matrix linter sticky preview |
| **VibeCare Health Preview** | `public/images/vibecare_health_preview.png` | LLM budget guardrails & server telemetry preview |

---

## Component Architecture & Structure

```
components/
├── SmoothScroll.tsx                  # Lenis smooth scrolling provider (lerp: 0.05)
├── Navbar.tsx                        # Floating blur header, PIXZEN logo, hover scale-x underline, Let's Talk CTA
├── Hero.tsx                          # Full-screen editorial hero, circuit backdrop, dynamic typing text ("Building Tomorrow", "Shaping Futures", "Driving Growth")
├── TrustedBrands.tsx                 # Infinite scrolling marquee of AI partners (Cursor, Bolt, Lovable, v0, Supabase, Next.js)
├── Services.tsx                      # 12-column grid layout (5/7 split) with sticky framer-motion media crossfade preview
├── FeaturedWork.tsx                  # Sticky stacked cards deck with useScroll scale-down & case study modal overlay
├── About.tsx                         # GSAP ScrollTrigger word scrub manifesto text reveal & infinite values marquee
├── Insights.tsx                      # Editorial table with mouse-following thumbnail cursor reveal via GSAP
├── PricingView.tsx                   # 3-tier pricing section with confetti explosion & NumberFlow price counters
├── Contact.tsx                       # Elastic magnetic button effect ("Start a Project" / "Launch SaaS Dashboard")
└── Footer.tsx                        # Multi-column directory footer

app/
├── layout.tsx                        # Root layout with Satoshi font CDN & global #grain-overlay SVG noise
└── page.tsx                          # Main entry unifying all PIXZEN x ShipGuard sections
```

---

## Step-by-Step Implementation Roadmap

1. Update `app/globals.css` & `app/layout.tsx` to include Satoshi font from Fontshare, `#grain-overlay` SVG noise texture, and Lenis CSS.
2. Build `SmoothScroll.tsx` (Lenis provider).
3. Build `Navbar.tsx` with scroll backdrop-blur and mobile menu drawer.
4. Build `Hero.tsx` with high-res `hero_circuit_board.png` layer, halftone dot pattern overlay, dynamic typing text, and CTA buttons.
5. Build `TrustedBrands.tsx` with infinite CSS marquee.
6. Build `Services.tsx` with 12-column grid and sticky media preview using generated assets (`security_audit_preview.png`, `vibepolish_ui_preview.png`, `vibecare_health_preview.png`).
7. Build `FeaturedWork.tsx` with sticky stacked project cards deck and case study modal overlay.
8. Build `About.tsx` with SSR-safe GSAP ScrollTrigger word scrub manifesto text reveal.
9. Build `Insights.tsx` with mouse-following cursor reveal.
10. Build `Contact.tsx` with elastic magnetic button effect.
11. Build `Footer.tsx` directory footer.
12. Test complete build with `npx next build` and test server output.
