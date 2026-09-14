// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Image from 'next/image';
import { 
  ShieldCheck, 
  Search, 
  Terminal, 
  Gauge, 
  CheckCircle2, 
  ArrowUpRight, 
  Lock,
  Layers,
  Code2,
  ExternalLink,
  Maximize2,
  X
} from 'lucide-react';

interface CapabilityPillar {
  id: string;
  badge: string;
  title: string;
  subtitle: string;
  description: string;
  image: string;
  alt: string;
  metrics: { label: string; value: string }[];
  bulletPoints: string[];
}

export const ProductCapabilities: React.FC = () => {
  const [activePillarId, setActivePillarId] = useState('rules');
  const [zoomImage, setZoomImage] = useState<string | null>(null);

  const pillars: CapabilityPillar[] = [
    {
      id: 'rules',
      badge: 'PILLAR 1 // GATE CATALOG',
      title: '148 Multi-Pillar Release Gates',
      subtitle: 'Transparent, configurable rule engine covering security, performance, infra, and compliance.',
      description:
        'Audit your codebase against an exhaustive catalog of deterministic rules. Enforce zero day-one OWASP Top 10 vulnerabilities, verify Supabase Row Level Security, block wildcard CORS endpoints, and eliminate root container risks.',
      image: '/images/security_rules.png',
      alt: 'ShipGuard 148 Multi-Pillar Release Gate Catalog and Configurator',
      metrics: [
        { label: 'Security Rules', value: '42' },
        { label: 'UI/UX & A11y', value: '38' },
        { label: 'Cloud & Infra', value: '36' },
        { label: 'Legal & Privacy', value: '32' }
      ],
      bulletPoints: [
        'Deterministic AST inspection with zero false-positive rate hallucination',
        'Custom severity overrides: Toggle CRITICAL, HIGH, MEDIUM per repository',
        'Instant rule explanations with mapped CWE and OWASP 2025/2026 standards'
      ]
    },
    {
      id: 'findings',
      badge: 'PILLAR 2 // AST TRIAGE',
      title: 'Surgical Vulnerability Triage & Line Context',
      description:
        'Every detected issue is isolated down to the exact file line, AST node, and security risk context. Review line-by-line diffs and copy automated AI prompts to remediate issues instantly.',
      subtitle: 'Line-by-line code context with copyable AI remediation prompts.',
      image: '/images/audit_findings.png',
      alt: 'ShipGuard Vulnerability Triage and Line-by-Line Code Findings',
      metrics: [
        { label: 'Diff Precision', value: '100%' },
        { label: '1-Click Fix', value: 'Enabled' },
        { label: 'Remediation Time', value: '<60s' },
        { label: 'Export Format', value: 'JSON / CSV' }
      ],
      bulletPoints: [
        'Exact line numbers with syntax-highlighted code context',
        'Pre-engineered AI prompts for Cursor, Copilot, and Claude Code',
        'Direct links to GitHub commit refs and pull request file trees'
      ]
    },
    {
      id: 'sandbox',
      badge: 'PILLAR 3 // INSTANT REPL',
      title: 'Interactive Zero-Install Browser Sandbox',
      subtitle: 'Test snippets, AST patterns, and custom regex rules in live browser memory.',
      description:
        'Experiment with production snippets before pushing to version control. Test API routes, Dockerfiles, and React components against the full ShipGuard engine without installing any CLI tools or packages.',
      image: '/images/vulnerability_sandbox.png',
      alt: 'ShipGuard Zero-Install Vulnerability Sandbox and AST Regex Playground',
      metrics: [
        { label: 'Install Overhead', value: '0 sec' },
        { label: 'AST Presets', value: '5 Built-in' },
        { label: 'Execution Mode', value: 'Client Web' },
        { label: 'Privacy', value: 'Zero Egress' }
      ],
      bulletPoints: [
        'Live AST evaluator directly inside your browser viewport',
        '1-click presets for OWASP secret leakage, permissive RLS, and container root',
        'Real-time feedback as you type or paste production code'
      ]
    },
    {
      id: 'profiler',
      badge: 'PILLAR 4 // BUNDLE & INFRA',
      title: 'Deep Bundle & Core Web Vitals Profiler',
      subtitle: 'Analyze asset weight distribution, layout stability, and container resource limits.',
      description:
        'Catch client-side performance regressions and cloud resource exhaustion. Analyze Cumulative Layout Shift (CLS), unoptimized image payloads, and verify Docker CPU/Memory limits before deployment.',
      image: '/images/bundle_profiler.png',
      alt: 'ShipGuard Performance Bundle Profiler and Cloud Resource Analyzer',
      metrics: [
        { label: 'Core Web Vitals', value: 'CLS & LCP' },
        { label: 'Docker Hardening', value: 'Non-Root' },
        { label: 'Asset Tracking', value: 'Tree-shaking' },
        { label: 'K8s Pod Limits', value: 'Automated' }
      ],
      bulletPoints: [
        'Cumulative Layout Shift (CLS) and Largest Contentful Paint (LCP) checks',
        'Detection of unkeyed React iterators and heavy third-party bundle leaks',
        'Docker healthcheck enforcement and memory quota allocation checks'
      ]
    }
  ];

  const currentPillar = pillars.find((p) => p.id === activePillarId) || pillars[0];

  return (
    <section id="features" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-16">
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

        {/* Pillar Navigation Tabs */}
        <div className="flex flex-wrap items-center justify-center gap-2 p-1.5 rounded-2xl bg-[#141414] border border-white/10 max-w-3xl mx-auto">
          {pillars.map((pillar) => (
            <button
              key={pillar.id}
              onClick={() => setActivePillarId(pillar.id)}
              className={`px-4 sm:px-6 py-2.5 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-2 ${
                activePillarId === pillar.id
                  ? 'bg-white text-black shadow-md'
                  : 'text-zinc-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span>{pillar.title.split(' ')[0]}</span>
              <span className="hidden sm:inline opacity-60">({pillar.metrics[0].value})</span>
            </button>
          ))}
        </div>

        {/* Active Pillar Full Showcase Card */}
        <div className="rounded-2xl border border-white/15 bg-[#121212] p-6 sm:p-10 shadow-2xl flex flex-col lg:flex-row gap-10 items-center">
          {/* Left Description Column (5 cols) */}
          <div className="w-full lg:w-5/12 flex flex-col gap-6">
            <div className="inline-flex items-center gap-2 text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wider">
              <span>{currentPillar.badge}</span>
            </div>

            <h3 className="text-2xl sm:text-3xl font-extrabold text-white leading-tight">
              {currentPillar.title}
            </h3>

            <p className="text-xs sm:text-sm font-semibold text-zinc-300 leading-normal">
              {currentPillar.subtitle}
            </p>

            <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans">
              {currentPillar.description}
            </p>

            {/* Key Metrics Grid */}
            <div className="grid grid-cols-2 gap-3 py-4 border-y border-white/10">
              {currentPillar.metrics.map((m, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-[#0E0E10] border border-white/5">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase block">{m.label}</span>
                  <span className="text-sm font-mono font-bold text-white mt-0.5 block">{m.value}</span>
                </div>
              ))}
            </div>

            {/* Bullet List */}
            <ul className="flex flex-col gap-2.5">
              {currentPillar.bulletPoints.map((bp, i) => (
                <li key={i} className="flex items-start gap-2.5 text-xs text-zinc-300">
                  <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                  <span>{bp}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Right Screenshot Showcase Column (7 cols) */}
          <div className="w-full lg:w-7/12 flex flex-col gap-3">
            <div className="relative aspect-[16/10] w-full rounded-xl border border-white/15 bg-[#0A0A0A] overflow-hidden shadow-2xl group">
              <Image
                src={currentPillar.image}
                alt={currentPillar.alt}
                fill
                sizes="(max-width: 1200px) 100vw, 700px"
                className="object-cover object-top transition-transform duration-500 group-hover:scale-[1.02]"
              />

              {/* Zoom Trigger Button */}
              <button
                onClick={() => setZoomImage(currentPillar.image)}
                className="absolute top-3 right-3 p-2 rounded-lg bg-[#0E0E10]/80 backdrop-blur-md border border-white/15 text-zinc-300 hover:text-white transition-all opacity-0 group-hover:opacity-100 shadow-lg"
                aria-label="Zoom Image Preview"
              >
                <Maximize2 size={16} />
              </button>

              <div className="absolute bottom-0 inset-x-0 p-3 bg-gradient-to-t from-black/90 via-black/40 to-transparent flex items-center justify-between text-xs font-mono text-zinc-400">
                <span className="text-[11px] text-zinc-300 font-semibold">{currentPillar.alt}</span>
                <span className="text-[10px] text-emerald-400">● LIVE RUNTIME</span>
              </div>
            </div>
          </div>
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
