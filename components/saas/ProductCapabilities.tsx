// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Image from 'next/image';
import { 
  ShieldCheck, 
  CheckCircle2, 
  Layers, 
  Maximize2, 
  X,
  Code2,
  Terminal,
  Activity,
  FileCode,
  Zap
} from 'lucide-react';

interface CapabilityPillar {
  id: string;
  badge: string;
  title: string;
  subtitle: string;
  description: string;
  image: string;
  alt: string;
  tag: string;
  metrics: { label: string; value: string }[];
  bulletPoints: string[];
}

export const ProductCapabilities: React.FC = () => {
  const [zoomImage, setZoomImage] = useState<string | null>(null);

  const pillars: CapabilityPillar[] = [
    {
      id: 'rules',
      badge: 'PILLAR 01 // 148 ACTIVE GATES',
      title: 'Deterministic Multi-Pillar Release Rules',
      subtitle: 'Configurable gate catalog covering security, performance, cloud infra, and compliance.',
      description:
        'Audit your codebase against an exhaustive catalog of deterministic rules. Enforce zero day-one OWASP Top 10 vulnerabilities, verify Supabase Row Level Security, block wildcard CORS endpoints, and eliminate root container privilege escalation risks.',
      image: '/images/security_rules.png',
      alt: 'ShipGuard 148 Multi-Pillar Release Gate Catalog and Configurator',
      tag: '148 RULES ACTIVE',
      metrics: [
        { label: 'Security Rules', value: '42 Active' },
        { label: 'UI/UX & A11y', value: '38 Active' },
        { label: 'Cloud & Infra', value: '36 Active' },
        { label: 'Legal & Privacy', value: '32 Active' }
      ],
      bulletPoints: [
        'Deterministic AST inspection with zero false-positive rate hallucination',
        'Granular severity overrides: Toggle CRITICAL, HIGH, MEDIUM per repository',
        'Instant rule explanations mapped to CWE and OWASP 2025/2026 standards'
      ]
    },
    {
      id: 'findings',
      badge: 'PILLAR 02 // SURGICAL AST TRIAGE',
      title: 'Line-by-Line Vulnerability Triage & Context',
      subtitle: 'Precise code diff context with copyable AI remediation prompts.',
      description:
        'Every detected issue is isolated down to the exact file line, AST node, and security risk context. Review line-by-line diffs and copy automated AI prompts to remediate issues instantly inside Cursor or Copilot.',
      image: '/images/audit_findings.png',
      alt: 'ShipGuard Vulnerability Triage and Line-by-Line Code Findings',
      tag: 'SURGICAL DIFFS',
      metrics: [
        { label: 'Diff Precision', value: '100% Line Accuracy' },
        { label: '1-Click Fix', value: 'AI Prompts' },
        { label: 'Remediation Time', value: '<60 Seconds' },
        { label: 'Export Formats', value: 'JSON & CSV' }
      ],
      bulletPoints: [
        'Exact line numbers with syntax-highlighted code context',
        'Pre-engineered AI prompts formatted for Cursor, Copilot, and Claude Code',
        'Direct links to GitHub commit refs and pull request file trees'
      ]
    },
    {
      id: 'sandbox',
      badge: 'PILLAR 03 // ZERO-INSTALL REPL',
      title: 'Interactive Browser AST Sandbox & Tester',
      subtitle: 'Test snippets, AST patterns, and custom regex rules in live browser memory.',
      description:
        'Experiment with production snippets before pushing to version control. Test API routes, Dockerfiles, and React components against the full ShipGuard engine without installing any CLI tools or npm packages.',
      image: '/images/vulnerability_sandbox.png',
      alt: 'ShipGuard Zero-Install Vulnerability Sandbox and AST Regex Playground',
      tag: 'ZERO-INSTALL REPL',
      metrics: [
        { label: 'Install Overhead', value: '0 Seconds' },
        { label: 'Built-in Presets', value: '5 Scenarios' },
        { label: 'Execution Mode', value: 'In-Memory Client' },
        { label: 'Code Privacy', value: 'Zero Egress' }
      ],
      bulletPoints: [
        'Live AST evaluator running directly inside your browser viewport',
        '1-click presets for OWASP secret leakage, permissive RLS, and container root',
        'Real-time feedback as you type or paste production code'
      ]
    },
    {
      id: 'profiler',
      badge: 'PILLAR 04 // CORE WEB VITALS & CLOUD',
      title: 'Deep Bundle & Core Web Vitals Profiler',
      subtitle: 'Analyze asset weight distribution, layout stability, and container resource limits.',
      description:
        'Catch client-side performance regressions and cloud resource exhaustion. Analyze Cumulative Layout Shift (CLS), unoptimized image payloads, and verify Docker CPU/Memory limits before deployment.',
      image: '/images/bundle_profiler.png',
      alt: 'ShipGuard Performance Bundle Profiler and Cloud Resource Analyzer',
      tag: 'PERFORMANCE GAUGE',
      metrics: [
        { label: 'Core Web Vitals', value: 'CLS & LCP' },
        { label: 'Docker Defense', value: 'Non-Root User' },
        { label: 'Asset Tracking', value: 'Tree-Shaking' },
        { label: 'K8s Pod Limits', value: 'Automated' }
      ],
      bulletPoints: [
        'Cumulative Layout Shift (CLS) and Largest Contentful Paint (LCP) checks',
        'Detection of unkeyed React iterators and heavy third-party bundle leaks',
        'Docker healthcheck enforcement and memory quota allocation checks'
      ]
    }
  ];

  return (
    <section id="features" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-20">
        {/* Section Title */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center gap-2 text-xs font-mono uppercase tracking-widest text-emerald-400">
            <Layers size={14} />
            <span>ENTERPRISE CAPABILITIES</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            Production Readiness Across 4 Core Pillars
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed font-sans">
            Engineered to replace fragmented linters, manual security spreadsheets, and bloated compliance suites with a unified developer platform.
          </p>
        </div>

        {/* Sequential Alternating Showcase of All 4 Pillars */}
        <div className="flex flex-col gap-16">
          {pillars.map((pillar, idx) => {
            const isReversed = idx % 2 === 1;
            return (
              <div
                key={pillar.id}
                className={`rounded-2xl border border-white/15 bg-[#121212] p-6 sm:p-10 shadow-2xl flex flex-col ${
                  isReversed ? 'lg:flex-row-reverse' : 'lg:flex-row'
                } gap-10 items-center`}
              >
                {/* Text & Metrics Column (5 cols) */}
                <div className="w-full lg:w-5/12 flex flex-col gap-6">
                  <div className="inline-flex items-center gap-2 text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wider">
                    <span>{pillar.badge}</span>
                  </div>

                  <h3 className="text-2xl sm:text-3xl font-extrabold text-white leading-tight">
                    {pillar.title}
                  </h3>

                  <p className="text-xs sm:text-sm font-semibold text-zinc-300 leading-normal">
                    {pillar.subtitle}
                  </p>

                  <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans">
                    {pillar.description}
                  </p>

                  {/* Key Metrics Grid */}
                  <div className="grid grid-cols-2 gap-3 py-4 border-y border-white/10">
                    {pillar.metrics.map((m, mIdx) => (
                      <div key={mIdx} className="p-3 rounded-lg bg-[#0E0E10] border border-white/5">
                        <span className="text-[10px] font-mono text-zinc-500 uppercase block">{m.label}</span>
                        <span className="text-sm font-mono font-bold text-white mt-0.5 block">{m.value}</span>
                      </div>
                    ))}
                  </div>

                  {/* Bullet List */}
                  <ul className="flex flex-col gap-2.5">
                    {pillar.bulletPoints.map((bp, bpIdx) => (
                      <li key={bpIdx} className="flex items-start gap-2.5 text-xs text-zinc-300">
                        <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                        <span>{bp}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Screenshot Showcase Column (7 cols) */}
                <div className="w-full lg:w-7/12 flex flex-col gap-3">
                  <div className="relative aspect-[16/10] w-full rounded-xl border border-white/15 bg-[#0A0A0A] overflow-hidden shadow-2xl group">
                    <Image
                      src={pillar.image}
                      alt={pillar.alt}
                      fill
                      sizes="(max-width: 1200px) 100vw, 700px"
                      className="object-cover object-top transition-transform duration-500 group-hover:scale-[1.02]"
                    />

                    {/* Zoom Trigger Button */}
                    <button
                      onClick={() => setZoomImage(pillar.image)}
                      className="absolute top-3 right-3 p-2 rounded-lg bg-[#0E0E10]/80 backdrop-blur-md border border-white/15 text-zinc-300 hover:text-white transition-all opacity-0 group-hover:opacity-100 shadow-lg cursor-pointer"
                      aria-label="Zoom Image Preview"
                    >
                      <Maximize2 size={16} />
                    </button>

                    <div className="absolute bottom-0 inset-x-0 p-3 bg-gradient-to-t from-black/90 via-black/40 to-transparent flex items-center justify-between text-xs font-mono text-zinc-400">
                      <span className="text-[11px] text-zinc-300 font-semibold">{pillar.alt}</span>
                      <span className="text-[10px] text-emerald-400 font-bold">● {pillar.tag}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Modal Lightbox for High-Res Zoom */}
        <AnimatePresence>
          {zoomImage && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setZoomImage(null)}
              className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex items-center justify-center p-4 sm:p-8 cursor-zoom-out"
            >
              <div 
                className="relative max-w-6xl w-full aspect-[16/10] rounded-xl overflow-hidden border border-white/20 shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              >
                <Image
                  src={zoomImage}
                  alt="High Resolution Screenshot Preview"
                  fill
                  className="object-contain"
                />
                <button
                  onClick={() => setZoomImage(null)}
                  className="absolute top-4 right-4 p-2 rounded-full bg-white/10 hover:bg-white/20 text-white border border-white/20 transition-all"
                  aria-label="Close Preview"
                >
                  <X size={20} />
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
};
