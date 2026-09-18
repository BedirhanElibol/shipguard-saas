'use client';

import React from 'react';
import { X, Check, Lock, Shield, ArrowRight, Zap, ExternalLink } from 'lucide-react';
import { UserTier } from '@/data/schema';

interface TierDetailsModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentTier?: UserTier;
  onSelectPlan: (plan: 'Pro' | 'Enterprise') => void;
}

export const TierDetailsModal: React.FC<TierDetailsModalProps> = ({
  isOpen,
  onClose,
  currentTier = 'Free',
  onSelectPlan
}) => {
  if (!isOpen) return null;

  const features = [
    {
      category: 'Scan Volume & Code Access',
      items: [
        { label: 'Monthly Live Audits', free: '3 Scans / mo', pro: 'Unlimited', enterprise: 'Unlimited' },
        { label: 'Private Repositories', free: 'Locked (Public only)', pro: 'Full Access (1-Click OAuth)', enterprise: 'Private + Air-Gapped / GHES' },
        { label: 'Connected Projects', free: '1 Active Repo', pro: 'Unlimited Repos', enterprise: 'Unlimited Repos & Teams' }
      ]
    },
    {
      category: 'Rule Engine & Analysis Depth',
      items: [
        { label: 'Security & Bug Inventory', free: '20 Core OWASP Rules', pro: 'All 7,850+ Production Rules', enterprise: 'All Rules + Custom Company Rules' },
        { label: 'Secret Detection & RLS', free: 'Basic Surface Check', pro: 'Deep AST & Vault Analysis', enterprise: 'Deep AST + Custom Token Regex' },
        { label: '1,000+ File Repositories', free: 'Standard Buffer', pro: 'Cooperative Event Loop Yielding', enterprise: 'High-Throughput Enterprise Stream' }
      ]
    },
    {
      category: 'AI Remediation & Patching',
      items: [
        { label: '1-Click Claude / Cursor Prompts', free: '1 Trial Prompt', pro: 'Unlimited 1-Click Fix Prompts', enterprise: 'Unlimited + Automated PR Bot' },
        { label: 'Unified Git Diff Patches', free: 'Locked', pro: 'Instant Unified Diffs', enterprise: 'Direct Branch Commit / Pull Request' }
      ]
    },
    {
      category: 'Executive Reports & Compliance',
      items: [
        { label: 'Official PDF Release Certificate', free: 'Locked', pro: 'Included (Instant Download)', enterprise: 'White-Label & Custom Branding' },
        { label: 'Jira Markdown & HTML Export', free: 'Locked', pro: 'Included', enterprise: 'Included' },
        { label: 'SOC2 & ISO27001 Readiness', free: 'Not Included', pro: 'Standard Checkpoints', enterprise: 'Full Statutory Audit Dossiers' }
      ]
    },
    {
      category: 'Support & Operations',
      items: [
        { label: 'Support Channel', free: 'Community', pro: '24-Hour Email Support', enterprise: '1-Hour Priority SLA & Slack' },
        { label: 'GitHub Actions / CI/CD Gate', free: 'Locked', pro: 'Automated PR Status Checks', enterprise: 'Custom Webhook Pipeline + Slack Bot' }
      ]
    }
  ];

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto animate-in fade-in duration-150"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-[#121216] border border-white/15 rounded-2xl w-full max-w-4xl p-5 sm:p-8 flex flex-col gap-6 shadow-2xl relative my-auto max-h-[90vh] overflow-y-auto font-mono text-[#EDEDED]">
        {/* Modal Header */}
        <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield size={18} className="text-white" />
              <h2 className="text-lg sm:text-xl font-extrabold text-white">
                Tier Comparison &amp; Capability Matrix
              </h2>
            </div>
            <p className="text-xs text-zinc-400">
              Clear breakdown of quotas, operational paywalls, and feature availability across Free, Pro, and Enterprise tiers.
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Pricing Cards Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Free Tier */}
          <div className="p-4 rounded-xl border border-white/10 bg-[#0E0E12] flex flex-col justify-between gap-3">
            <div>
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Free Starter</span>
              <div className="text-2xl font-extrabold text-white mt-1">$0</div>
              <p className="text-[11px] text-zinc-400 mt-1">For testing public repositories and open source projects.</p>
            </div>
            <div className="text-[11px] text-zinc-400 font-bold border-t border-white/5 pt-2">
              {currentTier === 'Free' ? 'Current Plan' : 'Free Baseline'}
            </div>
          </div>

          {/* Pro Tier */}
          <div className="p-4 rounded-xl border border-blue-500/40 bg-blue-500/5 flex flex-col justify-between gap-3 relative shadow-lg">
            <span className="absolute -top-2.5 right-4 px-2 py-0.5 rounded text-[9px] font-bold bg-blue-500 text-white uppercase tracking-wider">
              Most Popular
            </span>
            <div>
              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">Pro Developer</span>
              <div className="text-2xl font-extrabold text-white mt-1">$19 <span className="text-xs text-zinc-400 font-normal">/ month</span></div>
              <p className="text-[11px] text-zinc-300 mt-1">Unlimited scans, private repos, 1-click AI fixes &amp; PDF certificates.</p>
            </div>
            <button
              onClick={() => { onClose(); onSelectPlan('Pro'); }}
              className="w-full py-2 px-3 rounded-lg bg-white text-black hover:bg-neutral-200 font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
            >
              <span>{currentTier === 'Pro' ? 'Active Plan' : 'Upgrade to Pro'}</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {/* Enterprise Tier */}
          <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 flex flex-col justify-between gap-3">
            <div>
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">Enterprise Team</span>
              <div className="text-2xl font-extrabold text-white mt-1">$99 <span className="text-xs text-zinc-400 font-normal">/ month</span></div>
              <p className="text-[11px] text-zinc-400 mt-1">Custom company rules, multi-seat RBAC, and dedicated 1h SLA support.</p>
            </div>
            <button
              onClick={() => { onClose(); onSelectPlan('Enterprise'); }}
              className="w-full py-2 px-3 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
            >
              <span>View Enterprise</span>
              <ArrowRight size={13} />
            </button>
          </div>
        </div>

        {/* Feature Comparison Matrix Table */}
        <div className="space-y-6 pt-2">
          {features.map((cat, idx) => (
            <div key={idx} className="space-y-2">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider border-b border-white/10 pb-1 text-zinc-300">
                {cat.category}
              </h3>
              <div className="divide-y divide-white/5 text-xs">
                {cat.items.map((item, itemIdx) => (
                  <div key={itemIdx} className="grid grid-cols-1 md:grid-cols-4 py-2 gap-1 items-center">
                    <span className="text-zinc-300 font-medium md:col-span-1">{item.label}</span>
                    <span className="text-zinc-400 text-[11px] md:col-span-1 md:text-center">{item.free}</span>
                    <span className="text-blue-300 font-bold text-[11px] md:col-span-1 md:text-center">{item.pro}</span>
                    <span className="text-emerald-300 font-bold text-[11px] md:col-span-1 md:text-center">{item.enterprise}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
