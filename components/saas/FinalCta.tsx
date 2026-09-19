'use client';

import React from 'react';
import { ArrowRight, Terminal, ShieldCheck, Play } from 'lucide-react';
import { useRouter } from 'next/navigation';

export const FinalCta: React.FC = () => {
  const router = useRouter();

  return (
    <section className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-amber-500/[0.05] blur-[140px] rounded-full pointer-events-none" />

      <div className="max-w-5xl mx-auto rounded-3xl border-t border-t-amber-500/40 border-x border-b border-white/20 bg-gradient-to-b from-[#141418] to-[#0E0E12] p-8 sm:p-16 shadow-[0_25px_80px_-20px_rgba(0,0,0,0.9),0_0_50px_rgba(245,158,11,0.06)] relative z-10 flex flex-col items-center text-center">
        {/* Release Status Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs font-mono mb-6">
          <ShieldCheck size={14} className="text-amber-400" />
          <span className="uppercase tracking-wider font-semibold text-[11px]">Immediate Pre-Flight Deployment</span>
        </div>

        {/* Big Headline */}
        <h2 className="text-3xl sm:text-5xl lg:text-6xl font-extrabold text-[#EDEDED] tracking-tight max-w-3xl leading-[1.1]">
          Never Ship An Unvetted Line Of Code To Production Again.
        </h2>

        {/* Subtitle */}
        <p className="text-base sm:text-lg text-[#A1A1AA] max-w-2xl mx-auto mt-6 mb-10 font-sans leading-relaxed">
          Test your repository against deterministic release rules in real time. Instant in-memory AST stream, zero code stored.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto">
          <button
            onClick={() => router.push('/dashboard')}
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-zinc-950 transition-all flex items-center justify-center gap-2.5 shadow-[0_0_25px_rgba(245,158,11,0.3)] active:scale-[0.98] cursor-pointer"
          >
            <Play size={14} fill="#09090b" />
            <span>Launch Full Audit Engine</span>
          </button>

          <a
            href="#pricing"
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider text-white hover:text-white bg-white/5 hover:bg-sky-500/10 border border-white/10 hover:border-sky-500/30 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <span>View Pricing &amp; Plans</span>
            <ArrowRight size={14} />
          </a>
        </div>

        {/* Footnote */}
        <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-8 mt-8 text-xs font-mono text-zinc-500">
          <span>Instant Self-Serve Setup</span>
          <span>100% In-Memory Privacy</span>
          <span>Comprehensive Rule Taxonomies</span>
        </div>
      </div>
    </section>
  );
};
