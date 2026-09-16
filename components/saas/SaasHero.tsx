'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheck, 
  ArrowRight, 
  Terminal, 
  Play, 
  CheckCircle2, 
  ExternalLink,
  Lock
} from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { normalizeRepoUrl } from '@/lib/github-api';

interface SaasHeroProps {
  onOpenDashboard?: (repoUrl?: string) => void;
}

export const SaasHero: React.FC<SaasHeroProps> = ({ onOpenDashboard }) => {
  const router = useRouter();
  const [repoInput, setRepoInput] = useState('expressjs/express');
  const [activeHotspot, setActiveHotspot] = useState<number | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const sampleRepos = [
    { label: 'Express.js', value: 'expressjs/express' },
    { label: 'Flask', value: 'pallets/flask' },
    { label: 'React Core', value: 'facebook/react' },
    { label: 'Next.js App', value: 'vercel/next.js' }
  ];

  if (sampleRepos.length === 0) return null;

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = repoInput.trim();
    if (!clean || isScanning) return;
    setIsScanning(true);
    const normalized = normalizeRepoUrl(clean);
    if (onOpenDashboard) {
      onOpenDashboard(normalized);
    } else {
      router.push(`/dashboard?repo=${encodeURIComponent(normalized)}&scan=true`);
    }
  };

  const hotspots = [
    {
      id: 1,
      x: '18%',
      y: '32%',
      title: '94/100 Release Readiness Gauge',
      description: 'Comprehensive mathematical health evaluation synthesized across security, performance, and cloud rules.'
    },
    {
      id: 2,
      x: '52%',
      y: '22%',
      title: 'Deep Rule Inventory',
      description: 'Continuous checks covering OWASP Top 10, Supabase RLS, WCAG 2.1 AA, and Docker privilege escalation.'
    },
    {
      id: 3,
      x: '82%',
      y: '48%',
      title: 'Surgical PR Remediation',
      description: 'Exportable JSON release manifests and 1-click AI prompt patches tailored for GitHub Copilot & Cursor.'
    }
  ];

  return (
    <section className="relative min-h-[90vh] flex flex-col justify-start pt-28 sm:pt-36 pb-20 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="relative z-10 max-w-6xl mx-auto w-full flex flex-col items-center text-center">
        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-[#EDEDED] tracking-tight leading-[1.06] max-w-5xl mb-6"
        >
          The Pre-Flight Release Gate for <br className="hidden sm:inline" />
          <span className="text-white">Modern Web &amp; Cloud Applications.</span>
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="text-base sm:text-lg lg:text-xl text-[#A1A1AA] max-w-3xl mx-auto leading-relaxed mt-6 mb-10 font-sans font-normal"
        >
          Stop fatal production regressions before they merge. Zelsis automatically evaluates critical OWASP security vulnerabilities, database RLS leaks, UI/UX accessibility, and cloud container configurations in memory before code reaches production.
        </motion.p>

        {/* Direct Repository Scan Command Bar */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="w-full max-w-2xl mb-4"
        >
          <form 
            onSubmit={handleStartScan}
            className="flex flex-col sm:flex-row items-stretch gap-2 p-1.5 rounded-xl bg-[#141414] border border-white/15 shadow-2xl focus-within:border-white/40 transition-all"
          >
            <div className="flex items-center gap-2.5 px-3 py-2 flex-1 min-w-0">
              <Terminal size={18} className="text-emerald-400 shrink-0" />
              <span className="text-xs font-mono text-zinc-500 hidden sm:inline">github.com/</span>
              <input
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                placeholder="owner/repository or public git URL"
                className="w-full bg-transparent text-sm font-mono text-[#EDEDED] placeholder-zinc-500 focus:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1"
                aria-label="GitHub Repository to Scan"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning}
              className="px-6 py-3 rounded-lg text-xs font-bold font-mono uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 shrink-0 shadow-sm active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              <span>Scan Repository</span>
              <ArrowRight size={14} />
            </button>
          </form>
          <div className="flex flex-wrap items-center justify-center gap-2 mt-3 text-xs">
            <span className="text-zinc-500 text-[11px] font-mono uppercase">Quick Presets:</span>
            {sampleRepos.map((r) => (
              <button
                key={r.value}
                type="button"
                onClick={() => setRepoInput(r.value)}
                className={`text-[11px] font-mono px-2.5 py-0.5 rounded-md border transition-all ${
                  repoInput === r.value
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                    : 'border-white/10 bg-white/[0.02] text-zinc-400 hover:text-zinc-200 hover:border-white/20'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.25 }}
          className="flex flex-wrap items-center justify-center gap-6 mt-4 mb-16 text-xs text-zinc-400 font-mono"
        >
          <span>Zero-Retention Privacy (Code Never Stored)</span>
          <span className="hidden sm:inline text-zinc-700">•</span>
          <span>5,000+ Deep Web &amp; Cloud Rules</span>
          <span className="hidden sm:inline text-zinc-700">•</span>
          <span>In-Memory Stream Evaluation</span>
        </motion.div>

        {/* Hero Showcase Centerpiece: Real Application State (dashboard_overview.png) */}
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.3 }}
          className="w-full max-w-5xl relative rounded-2xl border border-white/15 bg-[#121212] shadow-2xl overflow-hidden text-left"
        >
          {/* Browser Window Chrome Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-[#0E0E10] border-b border-white/10">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
              <div className="ml-3 px-3 py-1 rounded-md bg-white/[0.04] border border-white/5 text-[11px] font-mono text-zinc-400 flex items-center gap-1.5">
                <Lock size={11} className="text-emerald-400" />
                <span>app.zelsis.com/dashboard/eval/express-prod-gate</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span>Clearance: Passed (94/100)</span>
              </span>
              <button
                onClick={() => {
                  if (onOpenDashboard) onOpenDashboard();
                  else router.push('/dashboard');
                }}
                className="text-xs font-mono text-zinc-300 hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span>Open Dashboard</span>
                <ExternalLink size={12} />
              </button>
            </div>
          </div>

          {/* Screenshot Container with Interactive Hotspots */}
          <div className="relative aspect-[16/10] sm:aspect-[16/9] w-full bg-[#0A0A0A] overflow-hidden group">
            <Image
              src="/images/dashboard_overview.png"
              alt="Zelsis Production Readiness and Security Dashboard Overview"
              fill
              priority
              sizes="(max-width: 1200px) 100vw, 1200px"
              className="object-cover object-top transition-transform duration-500 group-hover:scale-[1.01]"
            />

            {/* Interactive Hotspots */}
            {hotspots.map((hs) => (
              <div
                key={hs.id}
                style={{ left: hs.x, top: hs.y }}
                className="absolute z-20 -translate-x-1/2 -translate-y-1/2"
              >
                <button
                  onClick={() => setActiveHotspot(activeHotspot === hs.id ? null : hs.id)}
                  onMouseEnter={() => setActiveHotspot(hs.id)}
                  onMouseLeave={() => setActiveHotspot(null)}
                  className="relative group/btn p-2 focus:outline-none cursor-pointer"
                  aria-label={hs.title}
                >
                  <span className="relative flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500 text-black font-mono font-bold text-xs shadow-lg border border-white">
                    {hs.id}
                  </span>
                </button>

                {/* Hotspot Tooltip */}
                <AnimatePresence>
                  {activeHotspot === hs.id && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95, y: 10 }}
                      animate={{ opacity: 1, scale: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95, y: 10 }}
                      transition={{ duration: 0.15 }}
                      className="absolute left-1/2 -translate-x-1/2 bottom-full mb-3 w-64 p-3 rounded-xl bg-[#141414] border border-white/20 shadow-2xl z-30 pointer-events-none"
                    >
                      <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold block mb-1">
                        Verified Area #{hs.id}
                      </span>
                      <h4 className="text-xs font-bold text-white mb-1">
                        {hs.title}
                      </h4>
                      <p className="text-[11px] text-zinc-400 leading-normal font-sans">
                        {hs.description}
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>

          {/* Footer Ribbon inside Frame */}
          <div className="px-5 py-3 bg-[#0E0E10] border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-zinc-400">
            <div className="flex items-center gap-4">
              <span>AST Engine: <strong className="text-zinc-200">Continuous Stream</strong></span>
              <span>Memory Isolation: <strong className="text-zinc-200">Zero Retention</strong></span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-emerald-400">●</span>
              <span>All 4 Pillars Calibrated for Deployment</span>
            </div>
          </div>
        </motion.div>

        {/* Supported Stacks Band */}
        <div className="w-full mt-16 pt-8 border-t border-white/10 flex flex-col items-center gap-4">
          <span className="text-xs font-mono uppercase tracking-widest text-zinc-500">
            Calibrated for Enterprise Production Stacks
          </span>
          <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-10 text-xs font-mono text-zinc-400">
            <span className="hover:text-white transition-colors">Next.js 15 (App Router)</span>
            <span className="text-zinc-700">•</span>
            <span className="hover:text-white transition-colors">TypeScript 5.x</span>
            <span className="text-zinc-700">•</span>
            <span className="hover:text-white transition-colors">Python / FastAPI</span>
            <span className="text-zinc-700">•</span>
            <span className="hover:text-white transition-colors">Go Microservices</span>
            <span className="text-zinc-700">•</span>
            <span className="hover:text-white transition-colors">Docker &amp; K8s</span>
            <span className="text-zinc-700">•</span>
            <span className="hover:text-white transition-colors">Swift &amp; Kotlin (Mobile)</span>
          </div>
        </div>
      </div>
    </section>
  );
};
