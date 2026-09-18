'use client';

import React from 'react';
import { Shield, ArrowUpRight, Lock, CheckCircle2, Layers } from 'lucide-react';
import { UserTier, PlanUsageQuota } from '@/data/schema';

interface UsageGaugeProps {
  tier: UserTier;
  quota: PlanUsageQuota;
  projectsCount: number;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const UsageGauge: React.FC<UsageGaugeProps> = ({
  tier = 'Free',
  quota,
  projectsCount,
  onOpenCheckout
}) => {
  const isFree = tier === 'Free';
  const isPro = tier === 'Pro';
  const isEnterprise = tier === 'Enterprise';

  const scansUsed = quota?.scansUsed || 0;
  const scansLimit = isFree ? 3 : 999;
  const scanPercentage = isFree ? Math.min(100, Math.round((scansUsed / scansLimit) * 100)) : 100;

  const aiPromptsUsed = quota?.aiPromptsUsed || 0;
  const aiPromptsLimit = isFree ? 1 : 999;

  return (
    <div className="rounded-xl border border-white/10 bg-[#121216] p-3.5 flex flex-col gap-3 font-mono shadow-md">
      {/* Tier Header Bar */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield size={14} className={isFree ? 'text-zinc-400' : isPro ? 'text-blue-400' : 'text-emerald-400'} />
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-white">
            {tier} Plan
          </span>
        </div>
        <span
          className={`px-1.5 py-0.5 rounded text-[9px] font-bold tracking-widest uppercase border ${
            isFree
              ? 'bg-white/5 text-zinc-400 border-white/10'
              : isPro
              ? 'bg-blue-500/10 text-blue-300 border-blue-500/30'
              : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
          }`}
        >
          {isFree ? 'Starter' : isPro ? 'Verified' : 'Dedicated'}
        </span>
      </div>

      {isFree ? (
        <>
          {/* Progress Meter for Scans */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between text-[10px] text-zinc-400">
              <span>Monthly Scans</span>
              <span className={`font-bold ${scansUsed >= scansLimit ? 'text-rose-400' : 'text-white'}`}>
                {scansUsed} / {scansLimit}
              </span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-white/10 overflow-hidden">
              <div
                className={`h-full transition-all duration-300 rounded-full ${
                  scansUsed >= scansLimit
                    ? 'bg-rose-500'
                    : scansUsed >= 2
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
                style={{ width: `${scanPercentage}%` }}
              />
            </div>
          </div>

          {/* Sub-Quotas Grid */}
          <div className="grid grid-cols-2 gap-2 pt-1 border-t border-white/5 text-[10px]">
            <div className="flex flex-col">
              <span className="text-zinc-500">Connected Repos</span>
              <span className="font-bold text-zinc-300">{projectsCount} / 1 Max</span>
            </div>
            <div className="flex flex-col">
              <span className="text-zinc-500">AI Fix Prompts</span>
              <span className="font-bold text-zinc-300">{aiPromptsUsed} / {aiPromptsLimit} Trial</span>
            </div>
          </div>

          {/* Locked Pro Indicators */}
          <div className="flex items-center gap-3 text-[9px] text-zinc-500 pt-0.5">
            <span className="flex items-center gap-1">
              <Lock size={10} className="text-zinc-500" /> Private Repos
            </span>
            <span className="flex items-center gap-1">
              <Lock size={10} className="text-zinc-500" /> PDF Release Gate
            </span>
          </div>

          {/* Upgrade Action Button */}
          <button
            type="button"
            onClick={() => onOpenCheckout?.('Pro')}
            className="w-full py-2 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 transition-all font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shadow-sm mt-0.5"
          >
            <span>Upgrade to Pro ($19/mo)</span>
            <ArrowUpRight size={13} />
          </button>
        </>
      ) : (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-400 font-bold">
            <CheckCircle2 size={13} />
            <span>Uncapped Release Gates</span>
          </div>
          <div className="grid grid-cols-1 gap-1 text-[10px] text-zinc-400">
            <div className="flex items-center justify-between">
              <span>Scans &amp; Repos</span>
              <span className="font-bold text-white">Unlimited</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Private Repos &amp; Diffs</span>
              <span className="font-bold text-white">Unlocked</span>
            </div>
            <div className="flex items-center justify-between">
              <span>PDF Release Certificate</span>
              <span className="font-bold text-white">Included</span>
            </div>
          </div>
          {isPro && (
            <button
              type="button"
              onClick={() => onOpenCheckout?.('Enterprise')}
              className="w-full mt-1 py-1.5 px-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] font-bold text-zinc-300 hover:text-white flex items-center justify-center gap-1 transition-colors"
            >
              <span>Need Team SLA? View Enterprise</span>
              <ArrowUpRight size={11} />
            </button>
          )}
        </div>
      )}
    </div>
  );
};
