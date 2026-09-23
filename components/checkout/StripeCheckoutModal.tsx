'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CreditCard, ShieldCheck, Zap, Check, Lock, User } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { activateUserTier, generateLicenseKey } from '@/lib/stripe-checkout';

interface StripeCheckoutModalProps {
  isOpen: boolean;
  onClose: () => void;
  user: UserProfile | null;
  onUpgradeSuccess: (newTier: 'Pro' | 'Enterprise') => void;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
  initialPlan?: 'Pro' | 'Enterprise';
}

export const StripeCheckoutModal: React.FC<StripeCheckoutModalProps> = ({
  isOpen,
  onClose,
  user,
  onUpgradeSuccess,
  onOpenAuth,
  initialPlan = 'Pro',
}) => {
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');
  const [selectedPlan, setSelectedPlan] = useState<'Pro' | 'Enterprise'>(initialPlan);
  const [cardNumber, setCardNumber] = useState('4242 •••• •••• 4242');
  const [expiry, setExpiry] = useState('12/28');
  const [cvc, setCvc] = useState('•••');
  const [cardHolder, setCardHolder] = useState(user?.name || '');
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const isLoggedIn = Boolean(user && user.isLoggedIn);

  React.useEffect(() => {
    if (initialPlan) {
      setSelectedPlan(initialPlan);
    }
  }, [initialPlan, isOpen]);

  React.useEffect(() => {
    if (user?.name) {
      setCardHolder(user.name);
    }
  }, [user?.name, isOpen]);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const proPrice = billingCycle === 'annual' ? '$15' : '$19';
  const enterprisePrice = billingCycle === 'annual' ? '$39' : '$49';
  const currentPrice = selectedPlan === 'Pro' ? proPrice : enterprisePrice;

  const getPolarCheckoutUrl = () => {
    const base =
      selectedPlan === 'Enterprise'
        ? 'https://buy.polar.sh/polar_cl_M0yZJgYVCucd7U5gDz4oFTND6hdqvYPo65HJQ2334od'
        : 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC';
    try {
      const url = new URL(base);
      if (user?.email) {
        url.searchParams.set('customer_email', user.email.trim());
      }
      if (user?.name) {
        url.searchParams.set('customer_name', user.name.trim());
      }
      return url.toString();
    } catch {
      return base;
    }
  };

  const handlePay = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLoggedIn) {
      onClose();
      if (onOpenAuth) onOpenAuth('signup');
      return;
    }
    setIsProcessing(true);

    setTimeout(() => {
      setIsProcessing(false);
      setIsSuccess(true);
      const planId = selectedPlan === 'Enterprise' ? 'vibecare' : 'zelsis-core';
      const key = generateLicenseKey(planId, user?.email || 'customer@zelsis.dev');
      activateUserTier(selectedPlan, key);

      setTimeout(() => {
        onUpgradeSuccess(selectedPlan);
        setIsSuccess(false);
        onClose();
      }, 1200);
    }, 1000);
  };

  return (
    <AnimatePresence>
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-3 sm:p-4 min-h-[100dvh]"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="w-full max-w-xl max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-8 flex flex-col gap-6 shadow-2xl relative overflow-hidden"
        >

          {/* Close Button */}
          <button
            onClick={onClose}
            aria-label="Close checkout modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
          >
            <X size={20} />
          </button>

          {!isLoggedIn ? (
            <div className="py-8 flex flex-col items-center justify-center text-center gap-5">
              <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center shadow-lg">
                <Lock size={32} />
              </div>

              <div className="flex flex-col gap-2 max-w-sm">
                <h3 className="text-xl font-extrabold text-white">
                  Account Required for Checkout
                </h3>
                <p className="text-xs text-[#CBD5E1] leading-relaxed">
                  Please sign in or create a free account before upgrading your plan. Your subscription and security gate limits will be permanently bound to your account.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row items-center gap-3 w-full max-w-xs mt-2">
                <button
                  type="button"
                  onClick={() => {
                    onClose();
                    if (onOpenAuth) {
                      onOpenAuth('signin');
                    }
                  }}
                  className="w-full min-h-[44px] px-4 py-2.5 rounded-xl bg-white text-black font-extrabold text-xs hover:bg-neutral-200 transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer font-mono"
                >
                  <User size={14} />
                  <span>Sign In</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    onClose();
                    if (onOpenAuth) {
                      onOpenAuth('signup');
                    }
                  }}
                  className="w-full min-h-[44px] px-4 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/15 text-white font-bold text-xs transition-all flex items-center justify-center gap-2 cursor-pointer font-mono"
                >
                  <span>Create Account</span>
                </button>
              </div>

              <div className="flex items-center gap-2 text-[11px] text-[#A1A1AA] pt-4 border-t border-white/10 w-full justify-center">
                <ShieldCheck size={14} className="text-emerald-400" />
                <span>Free account setup takes 10 seconds</span>
              </div>
            </div>
          ) : isSuccess ? (
            <div className="py-12 flex flex-col items-center justify-center text-center gap-4">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className="w-16 h-16 rounded-full bg-white/5 text-white border border-emerald-500/40 flex items-center justify-center"
              >
                <Check size={36} />
              </motion.div>
              <h2 className="text-2xl font-extrabold text-[#EDEDED]">Payment Successful!</h2>
              <p className="text-sm text-[#A1A1AA] max-w-sm">
                Your Zelsis account has been upgraded to <span className="text-white font-bold">{selectedPlan} Tier</span>. Unlimited scans and advanced rules unlocked!
              </p>
            </div>
          ) : (
            <>
              {/* Header */}
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center shrink-0">
                  <CreditCard size={20} />
                </div>
                <div>
                  <h2 className="text-lg font-extrabold text-[#EDEDED]">
                    Upgrade Zelsis SaaS Subscription
                  </h2>
                  <div className="text-xs text-[#A1A1AA]">
                    Secure Stripe Checkout · Cancel or switch anytime
                  </div>
                </div>
              </div>

              {/* Billing Cycle Toggle */}
              <div className="flex items-center justify-between p-2 bg-[#0A0A0A] rounded-xl border border-white/10">
                <span className="text-xs font-bold text-[#A1A1AA] font-mono px-2">Billing Cycle:</span>
                <div className="flex items-center gap-1 bg-[#141414] p-1 rounded-lg border border-white/10">
                  <button
                    type="button"
                    onClick={() => setBillingCycle('monthly')}
                    className={`px-3 py-1 rounded text-xs font-bold transition-all ${
                      billingCycle === 'monthly' ? 'bg-white text-black' : 'text-[#A1A1AA]'
                    }`}
                  >
                    Monthly
                  </button>
                  <button
                    type="button"
                    onClick={() => setBillingCycle('annual')}
                    className={`px-3 py-1 rounded text-xs font-bold flex items-center gap-1.5 transition-all ${
                      billingCycle === 'annual' ? 'bg-white text-black shadow-md' : 'text-[#A1A1AA]'
                    }`}
                  >
                    <span>Annual</span>
                    <span
                      className={`text-[0.6rem] uppercase tracking-wider px-1.5 py-0.5 rounded font-extrabold font-mono transition-colors ${
                        billingCycle === 'annual'
                          ? 'bg-neutral-900 text-emerald-400'
                          : 'bg-white/10 text-emerald-400'
                      }`}
                    >
                      Save 20%
                    </span>
                  </button>
                </div>
              </div>

              {/* Plan Picker */}
              <div className="grid grid-cols-2 gap-3">
                <div
                  onClick={() => setSelectedPlan('Pro')}
                  className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col gap-2 relative ${
                    selectedPlan === 'Pro'
                      ? 'bg-white/5 border-white/20 text-[#EDEDED] shadow-lg'
                      : 'bg-[#0A0A0A] border-white/10 text-[#A1A1AA] hover:border-white/20'
                  }`}
                >
                  {selectedPlan === 'Pro' && (
                    <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-white" />
                  )}
                  <div className="text-xs font-extrabold uppercase text-white font-mono">
                    Pro Plan
                  </div>
                  <div className="text-xl font-extrabold text-[#EDEDED]">
                    {proPrice} <span className="text-xs font-normal text-[#A1A1AA]">/mo</span>
                  </div>
                  <ul className="text-[0.7rem] text-[#A1A1AA] flex flex-col gap-1 mt-1 font-mono">
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Unlimited Scans</li>
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Pre-flight Security Taxonomy</li>
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Claude &amp; Cursor Auto-Fix</li>
                  </ul>
                </div>

                <div
                  onClick={() => setSelectedPlan('Enterprise')}
                  className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col gap-2 relative ${
                    selectedPlan === 'Enterprise'
                      ? 'bg-white/5 border-white/20 text-[#EDEDED] shadow-lg'
                      : 'bg-[#0A0A0A] border-white/10 text-[#A1A1AA] hover:border-white/20'
                  }`}
                >
                  {selectedPlan === 'Enterprise' && (
                    <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-white" />
                  )}
                  <div className="text-xs font-extrabold uppercase text-white font-mono">
                    Enterprise
                  </div>
                  <div className="text-xl font-extrabold text-[#EDEDED]">
                    {enterprisePrice} <span className="text-xs font-normal text-[#A1A1AA]">/mo</span>
                  </div>
                  <ul className="text-[0.7rem] text-[#A1A1AA] flex flex-col gap-1 mt-1 font-mono">
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Multi-Team Security Gates</li>
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Custom Rule Engine API</li>
                    <li className="flex items-center gap-1.5"><span className="text-white/40 select-none">—</span> Dedicated SLA &amp; Support</li>
                  </ul>
                </div>
              </div>

              {/* Polar Live Checkout Direct Action */}
              <div className="p-4 rounded-xl bg-gradient-to-b from-white/[0.08] to-white/[0.02] border border-white/20 flex flex-col gap-2.5 shadow-lg">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white uppercase">
                    Live Polar Checkout ({selectedPlan} Plan)
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                    Merchant of Record
                  </span>
                </div>
                <p className="text-[11px] text-[#A1A1AA] leading-relaxed">
                  Supports Apple Pay, Google Pay, and all major cards. Instant Merchant of Record invoicing and immediate access.
                </p>
                <a
                  href={getPolarCheckoutUrl()}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-primary py-3 px-4 text-xs font-extrabold uppercase tracking-wider w-full rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-md font-mono text-center cursor-pointer"
                >
                  <Lock size={13} />
                  <span>Pay Securely with Polar ({currentPrice}/mo)</span>
                </a>
                <div className="flex items-center justify-center gap-2 text-[10px] text-[#A1A1AA] font-mono">
                  <span>Apple Pay</span>
                  <span className="text-white/20">·</span>
                  <span>Google Pay</span>
                  <span className="text-white/20">·</span>
                  <span>Credit / Debit Card</span>
                </div>
              </div>

              <div className="flex items-center gap-3 my-1">
                <div className="h-px bg-white/10 flex-1" />
                <span className="text-[10px] uppercase font-mono text-[#A1A1AA]">or Test Simulator</span>
                <div className="h-px bg-white/10 flex-1" />
              </div>

              {/* Stripe Payment Form */}
              <form onSubmit={handlePay} className="flex flex-col gap-3 pt-1">
                <div className="flex flex-col gap-1">
                  <label className="text-[0.68rem] text-[#A1A1AA] font-mono font-bold uppercase">Cardholder Name</label>
                  <input
                    aria-label="Cardholder Name"
                    type="text"
                    value={cardHolder}
                    onChange={(e) => setCardHolder(e.target.value)}
                    className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus:border-white/20 font-mono"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-[0.68rem] text-[#A1A1AA] font-mono font-bold uppercase">Card Number</label>
                  <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                    <CreditCard size={15} className="text-[#A1A1AA]" />
                    <input
                      aria-label="Card Number"
                      type="text"
                      value={cardNumber}
                      onChange={(e) => setCardNumber(e.target.value)}
                      className="bg-transparent text-xs text-[#EDEDED] outline-none w-full font-mono"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1">
                    <label className="text-[0.68rem] text-[#A1A1AA] font-mono font-bold uppercase">Expiry (MM/YY)</label>
                    <input
                      aria-label="Expiration Date (MM/YY)"
                      type="text"
                      value={expiry}
                      onChange={(e) => setExpiry(e.target.value)}
                      className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none font-mono"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[0.68rem] text-[#A1A1AA] font-mono font-bold uppercase">CVC / CVV</label>
                    <input
                      aria-label="Security Code CVC"
                      type="text"
                      value={cvc}
                      onChange={(e) => setCvc(e.target.value)}
                      className="px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none font-mono"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isProcessing}
                  className="mt-2 btn btn-primary py-3.5 text-xs uppercase tracking-wider font-extrabold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-xl"
                >
                  <Lock size={13} />
                  <span>{isProcessing ? 'Processing Secure Payment...' : `Pay ${currentPrice} & Upgrade Now`}</span>
                </button>

                <div className="flex flex-col items-center gap-1 text-[0.65rem] text-[#64748B] mt-2 font-mono">
                  <div className="flex items-center gap-1.5 text-zinc-300">
                    <ShieldCheck size={12} className="text-emerald-400" />
                    <span className="font-semibold text-white">Backed by 14-Day Money-Back Guarantee / Cancel Anytime</span>
                  </div>
                  <div className="flex items-center gap-2 text-zinc-400">
                    <span>256-Bit SSL Encrypted Stripe Payment</span>
                    <span>/</span>
                    <a href="/refund" target="_blank" rel="noopener noreferrer" className="text-zinc-400 hover:text-white underline">Refund Policy</a>
                  </div>
                </div>
              </form>
            </>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
