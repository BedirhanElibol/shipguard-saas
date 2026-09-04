'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Lock, Zap, ShieldCheck } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface UpgradePaywallModalProps {
  isOpen: boolean;
  onClose: () => void;
  featureTitle?: string;
  featureDescription?: string;
  requiredTier?: 'Pro' | 'Enterprise';
}

export const UpgradePaywallModal: React.FC<UpgradePaywallModalProps> = ({
  isOpen,
  onClose,
  featureTitle = 'Automated Claude PR & Webhook Integration',
  featureDescription = 'Upgrade your plan to unlock automated Claude AI code fixes, unlimited security scans, and CI/CD webhook triggers.',
  requiredTier = 'Pro'
}) => {
  const router = useRouter();

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="max-w-xl w-full max-h-[85vh] overflow-y-auto p-6 sm:p-8 bg-[#141414] border border-white/10 rounded-2xl relative shadow-2xl flex flex-col gap-6"
        >
          {/* Close Button */}
          <button
            onClick={onClose}
            aria-label="Close upgrade modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
          >
            <X size={20} />
          </button>

          {/* Header */}
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-white text-xs font-mono font-bold uppercase tracking-wider w-fit">
              <Lock size={13} />
              <span>{requiredTier} Tier Required</span>
            </div>

            <h2 className="text-2xl sm:text-3xl font-extrabold text-[#EDEDED]">
              {featureTitle}
            </h2>

            <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed">
              {featureDescription}
            </p>
          </div>

          {/* Plan Comparison Box */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Pro Plan Card */}
            <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/20 flex flex-col justify-between gap-4">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-extrabold uppercase text-[#EDEDED]">Pro Plan</span>
                  <span className="text-xs font-mono font-bold text-white">$19/mo</span>
                </div>
                <ul className="mt-3 space-y-2 text-[0.75rem] text-[#A1A1AA]">
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>5 Active Repositories</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Unlimited Manual Scans</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Claude Auto-Fix PR</span>
                  </li>
                </ul>
              </div>

              <div className="flex flex-col gap-2">
                <a
                  href="https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-primary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 bg-white text-black hover:bg-neutral-200 transition-all shadow-sm font-mono cursor-pointer text-center"
                >
                  <span>Pay with Polar ($19/mo)</span>
                  <Zap size={13} />
                </a>
                <button
                  onClick={() => {
                    onClose();
                    router.push('/checkout?plan=shipguard-core&billing=annual');
                  }}
                  className="text-[10px] text-[#A1A1AA] hover:text-white text-center py-1 transition-colors"
                >
                  View Checkout &amp; Invoicing &rarr;
                </button>
              </div>
            </div>

            {/* Enterprise Plan Card */}
            <div className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 flex flex-col justify-between gap-4">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-extrabold uppercase text-[#EDEDED]">Enterprise</span>
                  <span className="text-xs font-mono font-bold text-white">$49/mo</span>
                </div>
                <ul className="mt-3 space-y-2 text-[0.75rem] text-[#A1A1AA]">
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Unlimited Repositories</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>CI/CD Webhook Triggers</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-white/40">·</span>
                    <span>Red Team Attack Payload</span>
                  </li>
                </ul>
              </div>

              <div className="flex flex-col gap-2">
                <a
                  href="https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary w-full py-2.5 text-xs uppercase tracking-wider font-extrabold rounded-lg flex items-center justify-center gap-1.5 border border-white/20 text-[#EDEDED] hover:bg-white/5 transition-all shadow-sm font-mono cursor-pointer text-center"
                >
                  <span>Pay with Polar ($49/mo)</span>
                  <ShieldCheck size={13} />
                </a>
                <button
                  onClick={() => {
                    onClose();
                    router.push('/checkout?plan=vibecare&billing=annual');
                  }}
                  className="text-[10px] text-[#A1A1AA] hover:text-white text-center py-1 transition-colors"
                >
                  View Checkout &amp; Invoicing &rarr;
                </button>
              </div>
            </div>
          </div>

          <div className="pt-2 text-center text-[0.7rem] text-[#A1A1AA]">
            Annual plans include 20% discount &amp; instant license activation key. Cancel anytime.
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
