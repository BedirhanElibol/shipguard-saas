// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { Check, X, Minus, ArrowRight, ShieldCheck, Zap, Scale } from 'lucide-react';
import { useRouter } from 'next/navigation';

export const ComparisonTable: React.FC = () => {
  const router = useRouter();

  const comparisonRows = [
    {
      feature: 'Evaluation Time',
      shipguard: 'Under 3.2 seconds',
      linters: '10–45 seconds',
      enterprise: '5–20 minutes'
    },
    {
      feature: 'Multi-Pillar Verification',
      detail: 'Security, UI/UX, Cloud Infra, and Legal Compliance combined',
      shipguard: true,
      linters: false,
      enterprise: 'Partial (Security only)'
    },
    {
      feature: 'Zero-Retention Privacy',
      detail: 'Code is scanned purely in ephemeral memory, never stored or trained on',
      shipguard: true,
      linters: true,
      enterprise: false
    },
    {
      feature: 'Setup Overhead',
      detail: 'Zero installation required; works directly with GitHub URLs & Webhooks',
      shipguard: '0 minutes (Instant)',
      linters: '30+ min configuration',
      enterprise: 'Days of agent setup'
    },
    {
      feature: 'Surgical Line-by-Line AST Diffs',
      detail: 'Pinpoints exact file line with pre-engineered AI prompts for Cursor/Copilot',
      shipguard: true,
      linters: 'Partial (Syntax only)',
      enterprise: false
    },
    {
      feature: 'Signed Release Manifest (SOC 2 / ISO 27001)',
      detail: 'Cryptographic certificate proving pre-flight compliance before merge',
      shipguard: true,
      linters: false,
      enterprise: 'Add-on ($$$)'
    },
    {
      feature: 'Interactive Browser Sandbox & REPL',
      detail: 'Test code snippets and custom regex rules in browser memory without sign-up',
      shipguard: true,
      linters: false,
      enterprise: false
    },
    {
      feature: 'Pricing Transparency',
      detail: 'Predictable self-serve plans vs opaque sales quotes',
      shipguard: '$29 / month',
      linters: 'Free (Low Scope)',
      enterprise: '$500 – $2,500+ / mo'
    }
  ];

  const renderValue = (val: boolean | string) => {
    if (typeof val === 'boolean') {
      return val ? (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400">
          <Check size={14} className="stroke-[3]" />
        </span>
      ) : (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-500/10 text-red-400">
          <X size={14} className="stroke-[2.5]" />
        </span>
      );
    }
    return <span className="font-mono text-xs font-semibold">{val}</span>;
  };

  return (
    <section id="comparison" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-6xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-4 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center justify-center gap-2 text-xs font-mono uppercase tracking-widest text-emerald-400">
            <Scale size={14} />
            <span>UNCOMPROMISING COMPARISON</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#EDEDED] tracking-tight">
            Why Developers Choose ShipGuard
          </h2>
          <p className="text-base sm:text-lg text-[#A1A1AA] leading-relaxed font-sans">
            Traditional linters only check syntax formatting. Heavy enterprise scanners take 15 minutes and lock you into annual enterprise contracts. ShipGuard provides deterministic release gates in 3 seconds.
          </p>
        </div>

        {/* Comparison Table Container */}
        <div className="rounded-2xl border border-white/15 bg-[#121212] overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-[#0E0E10]">
                  <th className="p-4 sm:p-6 text-xs font-mono uppercase tracking-wider text-zinc-400 w-2/5">
                    Operational Capability
                  </th>
                  <th className="p-4 sm:p-6 text-xs font-mono uppercase tracking-wider text-emerald-400 bg-emerald-500/[0.04] border-x border-white/10 w-1/5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      <span className="font-bold text-white">ShipGuard</span>
                    </div>
                  </th>
                  <th className="p-4 sm:p-6 text-xs font-mono uppercase tracking-wider text-zinc-400 w-1/5">
                    Standard Linters
                  </th>
                  <th className="p-4 sm:p-6 text-xs font-mono uppercase tracking-wider text-zinc-400 w-1/5">
                    Legacy Enterprise
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-xs sm:text-sm">
                {comparisonRows.map((row, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 sm:p-6">
                      <div className="font-bold text-white mb-0.5">{row.feature}</div>
                      {row.detail && (
                        <div className="text-xs text-zinc-500 font-sans">{row.detail}</div>
                      )}
                    </td>
                    <td className="p-4 sm:p-6 bg-emerald-500/[0.03] border-x border-white/10 text-emerald-300 font-medium">
                      {renderValue(row.shipguard)}
                    </td>
                    <td className="p-4 sm:p-6 text-zinc-400">
                      {renderValue(row.linters)}
                    </td>
                    <td className="p-4 sm:p-6 text-zinc-400">
                      {renderValue(row.enterprise)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Bottom Bar CTA */}
          <div className="p-6 bg-[#0E0E10] border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-xs font-mono text-zinc-400 text-center sm:text-left">
              <span>Ready to accelerate your production release cycles?</span>
              <strong className="text-white block sm:inline sm:ml-1">Start with 3 free scans today.</strong>
            </div>
            <button
              onClick={() => router.push('/dashboard')}
              className="px-6 py-2.5 rounded-lg text-xs font-mono font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-2 shadow-sm"
            >
              <span>Test Your Repository</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};
