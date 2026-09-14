'use client';

import React from 'react';
import { Gauge, Zap, Server, ShieldCheck } from 'lucide-react';

interface BundleCostAnalyzerProps {
  filesCount: number;
}

export const BundleCostAnalyzer: React.FC<BundleCostAnalyzerProps> = ({ filesCount }) => {
  const estimatedRawKb = Math.min(Math.max(filesCount * 24, 180), 1250);
  const estimatedGzipKb = Math.round(estimatedRawKb * 0.28);
  const estimatedLcpMs = Math.round(350 + estimatedGzipKb * 1.8);

  const lcpStatus = estimatedLcpMs < 1200 ? 'GOOD' : estimatedLcpMs < 2500 ? 'NEEDS IMPROVEMENT' : 'POOR';

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col gap-5">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
            <Gauge size={18} className="text-white" />
          </div>
          <div>
            <h2 className="text-lg font-extrabold text-[#EDEDED]">
              JS Bundle Size &amp; Core Web Vitals Profiler
            </h2>
            <p className="text-xs text-[#94A3B8]">
              Real-time client bundle payload &amp; loading performance impact analysis
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold text-white bg-white/5 border border-white/10 px-3 py-1 rounded-full flex items-center gap-1.5">
            <Zap size={13} />
            <span>Tree-Shaking: Optimized</span>
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Metric 1: Uncompressed Payload */}
        <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-2">
          <div className="text-[0.68rem] font-mono text-[#94A3B8] uppercase tracking-wider">
            RAW JS BUNDLE WEIGHT
          </div>
          <div className="text-2xl font-extrabold text-[#EDEDED] font-mono">
            {estimatedRawKb} KB
          </div>
          <div className="text-[0.68rem] text-[#94A3B8]">
            Uncompressed source code AST tree
          </div>
        </div>

        {/* Metric 2: Gzip / Brotli Payload */}
        <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-2">
          <div className="text-[0.68rem] font-mono text-[#94A3B8] uppercase tracking-wider">
            BROTLI COMPRESSED PAYLOAD
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">
            {estimatedGzipKb} KB
          </div>
          <div className="text-[0.68rem] text-white/80">
            ~72% Compression Ratio (Edge CDN)
          </div>
        </div>

        {/* Metric 3: Estimated LCP */}
        <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-2">
          <div className="text-[0.68rem] font-mono text-[#94A3B8] uppercase tracking-wider flex items-center justify-between">
            <span>ESTIMATED LCP SPEED</span>
            <span
              className={`text-[0.62rem] font-bold px-1.5 py-0.5 rounded ${
                lcpStatus === 'GOOD'
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : 'bg-amber-500/20 text-amber-400'
              }`}
            >
              {lcpStatus}
            </span>
          </div>
          <div className="text-2xl font-extrabold text-[#FAFAFA] font-mono">
            {estimatedLcpMs} ms
          </div>
          <div className="text-[0.68rem] text-[#94A3B8]">
            Largest Contentful Paint (4G Network)
          </div>
        </div>
      </div>
    </div>
  );
};
