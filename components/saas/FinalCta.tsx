'use client';

import React from 'react';
import { ArrowRight, Terminal, ShieldCheck, Play } from 'lucide-react';
import { useRouter } from 'next/navigation';

export const FinalCta: React.FC = () => {
  const router = useRouter();

  return (
    <section className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] relative">
      <div className="max-w-5xl mx-auto rounded-3xl border border-white/20 bg-gradient-to-b from-[#141414] to-[#0E0E10] p-8 sm:p-16 shadow-2xl relative z-10 flex flex-col items-center text-center">
        {/* Release Status Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md border border-white/10 bg-white/[0.03] text-zinc-300 text-xs font-mono mb-6">
          <ShieldCheck size={14} className="text-emerald-400" />
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
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center justify-center gap-2.5 shadow-lg active:scale-[0.98] cursor-pointer"
          >
            <Play size={14} fill="#0A0A0A" />
            <span>Launch Full Audit Engine</span>
          </button>

          <a
            href="#pricing"
            className="w-full sm:w-auto px-8 py-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider text-white hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <span>View Pricing &amp; Plans</span>
            <ArrowRight size={14} />
          </a>
        </div>

        {/* Footnote */}
        <div className="flex flex-wrap items-center justify-center gap-6 mt-8 text-xs font-mono text-zinc-500">
          <span>✓ Instant Self-Serve Setup</span>
          <span className="text-zinc-700">•</span>
          <span>✓ 100% In-Memory Privacy</span>
          <span className="text-zinc-700">•</span>
          <span>✓ Comprehensive Rule Taxonomies</span>
        </div>
      </div>
    </section>
  );
};
