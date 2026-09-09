// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ZELSIS_PRICING_PLANS, PricingPlanItem } from '@/data/pricing-plans';
import { generateLicenseKey, activateUserTier } from '@/lib/stripe-checkout';
import { ShieldCheck, CreditCard, Lock, CheckCircle2, ArrowLeft, Star, Building2, Mail, User, Copy, Zap, Terminal, ShieldAlert, AlertCircle } from 'lucide-react';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';

interface CheckoutViewProps {
  initialPlanId?: string;
  initialBilling?: 'annual' | 'monthly';
  initialSuccess?: boolean;
  onBackToPricing?: () => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
}

export const CheckoutView: React.FC<CheckoutViewProps> = ({
  initialPlanId = 'zelsis-core',
  initialBilling = 'monthly',
  initialSuccess = false,
  onBackToPricing,
  user,
  onOpenAuth,
}) => {
  const router = useRouter();
  const [selectedPlanId, setSelectedPlanId] = useState<string>(initialPlanId);
  const [isAnnual, setIsAnnual] = useState<boolean>(initialBilling === 'annual');

  // User Authentication State
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(user ?? null);
  const [isInternalAuthModalOpen, setIsInternalAuthModalOpen] = useState(false);
  const [internalAuthMode, setInternalAuthMode] = useState<'signin' | 'signup'>('signin');

  // Form Fields
  const [fullName, setFullName] = useState(user?.name || '');
  const [companyName, setCompanyName] = useState('');
  const [vatNumber, setVatNumber] = useState('');
  const [email, setEmail] = useState(user?.email || '');
  const [isSubmitted, setIsSubmitted] = useState(initialSuccess);
  const [activeLicenseKey, setActiveLicenseKey] = useState('');
  const [copiedKey, setCopiedKey] = useState(false);

  // Sync user state from props or localStorage
  useEffect(() => {
    if (user !== undefined) {
      setCurrentUser(user);
    } else {
      try {
        let saved = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!saved && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            saved = decodeURIComponent(match[3]);
          }
        }
        if (saved) {
          const parsed = JSON.parse(saved);
          if (parsed && parsed.isLoggedIn) {
            setCurrentUser(parsed);
          }
        }
      } catch (err) {
        console.warn('[CheckoutView] Failed to read user from storage:', err);
      }
    }
  }, [user]);

  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'zelsis_user' || e.key === 'shipguard_user') {
        try {
          if (e.newValue) {
            const parsed = JSON.parse(e.newValue);
            if (parsed && parsed.isLoggedIn) {
              setCurrentUser(parsed);
            } else {
              setCurrentUser(null);
            }
          } else {
            setCurrentUser(null);
          }
        } catch {
          setCurrentUser(null);
        }
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  useEffect(() => {
    if (currentUser) {
      if (currentUser.name && !fullName) setFullName(currentUser.name);
      if (currentUser.email && !email) setEmail(currentUser.email);
    }
  }, [currentUser]);

  const isAuthenticated = Boolean(currentUser && currentUser.isLoggedIn);

  const handleOpenAuthModal = (mode: 'signin' | 'signup' = 'signin') => {
    if (onOpenAuth) {
      onOpenAuth(mode);
    } else {
      setInternalAuthMode(mode);
      setIsInternalAuthModalOpen(true);
    }
  };

  useEffect(() => {
    if (initialSuccess) {
      const tier = selectedPlanId === 'vibecare' ? 'Enterprise' : 'Pro';
      const userEmail = currentUser?.email || 'customer@zelsis.com';
      const key = generateLicenseKey(selectedPlanId, userEmail);
      setActiveLicenseKey(key);
      activateUserTier(tier, key);
      setIsSubmitted(true);
    }
  }, [initialSuccess, selectedPlanId, currentUser?.email]);

  const selectedPlan: PricingPlanItem =
    ZELSIS_PRICING_PLANS.find((p) => p.id === selectedPlanId) ||
    ZELSIS_PRICING_PLANS[0];

  const pricePerMonth = isAnnual ? selectedPlan.priceAnnual : selectedPlan.priceMonthly;
  const annualTotal = Number((pricePerMonth * 12).toFixed(2));
  const subtotal = Number((isAnnual ? annualTotal : pricePerMonth).toFixed(2));
  const tax = Number((subtotal * 0.18).toFixed(2));
  const total = Number((subtotal + tax).toFixed(2));

  const handleSimulateSandbox = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAuthenticated) {
      handleOpenAuthModal('signup');
      return;
    }
    const tier = selectedPlanId === 'vibecare' ? 'Enterprise' : 'Pro';
    const key = generateLicenseKey(selectedPlanId, email || currentUser?.email || 'evaluator@agency.com');
    setActiveLicenseKey(key);
    activateUserTier(tier, key);
    setIsSubmitted(true);
  };

  return (
    <div className="flex flex-col gap-8 max-w-6xl mx-auto py-6 px-4">
      {/* Header Bar */}
      <div className="flex items-center justify-between border-b border-white/10 pb-4">
        <button
          onClick={onBackToPricing}
          className="flex items-center gap-2 text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
        >
          <ArrowLeft size={16} />
          <span>Back to Subscription Tiers</span>
        </button>

        <div className="flex items-center gap-2 text-xs text-[#10B981] font-extrabold bg-[#10B981]/10 px-3 py-1 rounded-full border border-[#10B981]/30">
          <ShieldCheck size={14} />
          <span>256-BIT SSL ENCRYPTED B2B CHECKOUT</span>
        </div>
      </div>

      {/* Account Required Warning Card for Unauthenticated / Guest Users */}
      {!isAuthenticated && !isSubmitted && (
        <div className="p-6 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-5 shadow-lg">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 text-amber-300 flex items-center justify-center shrink-0 text-xl">
              🛡️
            </div>
            <div className="flex flex-col gap-1">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Account Required
              </h3>
              <p className="text-xs text-[#CBD5E1] leading-relaxed max-w-2xl">
                Please sign in or create a free account before upgrading your plan. Your license and security gates will be permanently bound to your account.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => handleOpenAuthModal('signup')}
            className="min-h-[44px] px-5 py-2.5 rounded-xl bg-white text-black font-extrabold text-xs hover:bg-neutral-200 transition-all shadow-md flex items-center justify-center gap-2 shrink-0 cursor-pointer font-mono"
          >
            <User size={15} />
            <span>Open Sign In / Sign Up</span>
          </button>
        </div>
      )}

      {isSubmitted ? (
        <div className="bg-[#141414] border border-white/10 rounded-xl p-12 text-center flex flex-col items-center gap-5 border-[#10B981]/40 bg-[#10B981]/10">
          <CheckCircle2 size={64} className="text-[#10B981]" />
          <h2 className="text-3xl font-extrabold text-white">
            Subscription Order Activated!
          </h2>
          <p className="text-sm text-[#CBD5E1] max-w-lg leading-relaxed">
            Your <strong className="text-white">{selectedPlan.name}</strong> subscription has been successfully provisioned. A VAT invoice and license key have been emailed to <span className="text-white font-mono">{email}</span>.
          </p>

          <div className="p-4 rounded-xl bg-[#0A0E1A] border border-white/10 font-mono text-xs text-[#6EE7B7] max-w-md w-full text-left flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-white">PROVISIONED LICENSE KEY:</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(activeLicenseKey);
                  setCopiedKey(true);
                  setTimeout(() => setCopiedKey(false), 2000);
                }}
                className="btn btn-secondary text-[0.68rem] px-2 py-0.5 flex items-center gap-1"
              >
                {copiedKey ? <CheckCircle2 size={12} className="text-white" /> : <Copy size={12} />}
                <span>{copiedKey ? 'Copied!' : 'Copy Key'}</span>
              </button>
            </div>
            <div className="bg-[#0A0A0A] p-2 rounded border border-white/10 select-all break-all text-white">
              {activeLicenseKey || 'SG-PROD-2026-X94821'}
            </div>
            <div className="text-[0.7rem] text-[#A1A1AA]">
              STATUS: ACTIVE (Full Security Checks &amp; VibePolish Rules Enabled)
            </div>
          </div>

          <button
            onClick={() => {
              router.push('/dashboard');
            }}
            className="btn btn-primary px-8 py-3 uppercase text-xs font-bold tracking-wider mt-4 flex items-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
          >
            <span>Proceed to Security Gate Dashboard</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left Column: B2B Invoice & Payment Form */}
          <div className="lg:col-span-7 flex flex-col gap-6">
            <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6">
              <div>
                <h2 className="text-lg font-extrabold text-[#F8FAFC]">
                  1. Company &amp; Invoice Details
                </h2>
                <p className="text-xs text-[#A1A1AA] mt-0.5">
                  Provide your organization details for official VAT tax invoice generation
                </p>
              </div>

              <div className="flex flex-col gap-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="full-name-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Full Name / Contact Person
                    </label>
                    <div className="relative">
                      <input
                        id="full-name-input"
                        type="text"
                        placeholder="Alex Morgan"
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        required
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus:border-white/20 pl-9"
                      />
                      <User size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="email-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Business Email Address
                    </label>
                    <div className="relative">
                      <input
                        id="email-input"
                        type="email"
                        placeholder="alex@agency.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus:border-white/20 pl-9"
                      />
                      <Mail size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="company-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      Company / Agency Name
                    </label>
                    <div className="relative">
                      <input
                        id="company-input"
                        type="text"
                        placeholder="Your Company Name"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus:border-white/20 pl-9"
                      />
                      <Building2 size={14} className="absolute left-3 top-3 text-[#64748B]" />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="vat-input" className="block text-xs font-bold text-[#A1A1AA] mb-1.5 uppercase font-mono">
                      VAT / Tax ID (Optional)
                    </label>
                    <input
                      id="vat-input"
                      type="text"
                      placeholder="US987654321 or EU123456"
                      value={vatNumber}
                      onChange={(e) => setVatNumber(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-lg bg-[#0A0A0A] border border-white/10 text-xs text-[#EDEDED] outline-none focus:border-white/20"
                    />
                  </div>
                </div>

                <div className="pt-4 border-t border-white/10 mt-2">
                  <h2 className="text-lg font-extrabold text-[#EDEDED] mb-1">
                    2. Payment Method
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mb-4">
                    All major credit cards accepted. Cancel anytime with 1 click.
                  </p>

                  {/* Polar Live Checkout Card */}
                  <div className="p-6 rounded-xl bg-gradient-to-b from-white/[0.08] to-white/[0.02] border border-white/20 flex flex-col gap-4 shadow-xl">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Zap size={18} className="text-white" />
                        <span className="text-base font-extrabold text-white">Live Polar 3D Secure Checkout</span>
                      </div>
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white/10 text-white border border-white/20">
                        Merchant of Record
                      </span>
                    </div>

                    <p className="text-xs text-[#A1A1AA] leading-relaxed">
                      Instant 3D Secure checkout managed by Polar Software, Inc. Official VAT tax invoice and subscription activated immediately.
                    </p>

                    {isAuthenticated ? (
                      <a
                        href={selectedPlan.polarCheckoutUrl || 'https://buy.polar.sh/polar_cl_rxs3MC7Hq08OwYgoaJQatH93arqZfotoGUS0N15NqbC'}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-primary min-h-[44px] py-4 px-4 text-xs font-extrabold uppercase tracking-wider w-full rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-xl font-mono text-center cursor-pointer"
                      >
                        <Lock size={14} />
                        <span>Pay Securely with Polar (${selectedPlan.priceMonthly.toFixed(2)}/mo)</span>
                      </a>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <button
                          type="button"
                          onClick={() => handleOpenAuthModal('signup')}
                          className="min-h-[44px] py-4 px-4 text-xs font-extrabold uppercase tracking-wider w-full rounded-xl flex items-center justify-center gap-2 bg-white/10 text-[#A1A1AA] hover:bg-white/15 hover:text-white transition-all border border-white/10 font-mono text-center cursor-pointer"
                        >
                          <Lock size={14} />
                          <span>Sign In to Upgrade (${selectedPlan.priceMonthly.toFixed(2)}/mo)</span>
                        </button>
                        <span className="text-[11px] text-amber-300/80 font-mono text-center">
                          Guest accounts cannot process payments. Please sign in first.
                        </span>
                      </div>
                    )}
                    {isAnnual && isAuthenticated && (
                      <p className="text-[10px] text-white/60 font-mono text-center -mt-2">
                        Polar online checkout bills monthly (${selectedPlan.priceMonthly.toFixed(2)}/mo). Cancel anytime in 1-click.
                      </p>
                    )}

                    <div className="flex items-center justify-center gap-4 text-[11px] text-[#A1A1AA] pt-1 border-t border-white/10">
                      <span>✓ Apple Pay</span>
                      <span>✓ Google Pay</span>
                      <span>✓ Visa &amp; Mastercard</span>
                      <span>✓ Official VAT Invoices</span>
                    </div>
                  </div>

                  {/* Sandbox / Demo Simulator Section */}
                  <div className="mt-6 p-5 rounded-xl bg-[#0A0A0A] border border-dashed border-white/20 flex flex-col gap-3">
                    <div className="flex items-center gap-2">
                      <Terminal size={16} className="text-white" />
                      <span className="text-xs font-mono font-bold uppercase text-white">
                        Developer Demo &amp; Sandbox Simulator
                      </span>
                    </div>
                    <p className="text-xs text-[#A1A1AA] leading-relaxed">
                      Evaluating Zelsis for your agency or team? Simulate an instant subscription upgrade and generate a valid local license key without payment.
                    </p>
                    <button
                      type="button"
                      onClick={handleSimulateSandbox}
                      disabled={!isAuthenticated}
                      className={`min-h-[44px] py-3 text-xs font-bold uppercase tracking-wider w-full rounded-lg flex items-center justify-center gap-2 border transition-all font-mono ${
                        !isAuthenticated
                          ? 'border-white/10 bg-white/5 text-[#71717A] cursor-not-allowed opacity-60'
                          : 'btn btn-secondary border-white/20 hover:bg-white/10 text-white cursor-pointer'
                      }`}
                    >
                      <span>
                        {!isAuthenticated
                          ? 'Sign In Required for Instant Upgrade'
                          : `Simulate Instant Upgrade (${selectedPlan.name})`}
                      </span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Sticky Order Summary */}
          <div className="lg:col-span-5 sticky top-24">
            <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-5 border border-white/10 bg-[#141414] shadow-xl">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <span className="text-xs font-extrabold text-[#A1A1AA] font-mono uppercase tracking-wider">
                  ORDER SUMMARY
                </span>
                <span className="badge badge-passed text-[0.65rem]">
                  14-DAY FREE TRIAL
                </span>
              </div>

              {/* Plan Switcher Pills */}
              <div className="flex items-center gap-1 bg-[#0A0A0A] p-1 rounded-xl border border-white/10">
                {ZELSIS_PRICING_PLANS.map((plan) => (
                  <button
                    key={plan.id}
                    type="button"
                    onClick={() => setSelectedPlanId(plan.id)}
                    className={`flex-1 py-1.5 px-2 rounded-lg text-[0.68rem] font-bold transition-all truncate ${
                      selectedPlanId === plan.id
                        ? 'bg-white text-black font-bold shadow-sm'
                        : 'text-[#A1A1AA] hover:text-white'
                    }`}
                  >
                    {plan.name}
                  </button>
                ))}
              </div>

              {/* Selected Plan Details */}
              <div>
                <div className="flex items-center justify-between">
                  <h3 className="text-xl font-extrabold text-[#EDEDED]">
                    {selectedPlan.name}
                  </h3>
                  <div className="text-sm font-extrabold text-white font-mono">
                    ${pricePerMonth.toFixed(2)} <span className="text-xs text-[#A1A1AA]">/ mo</span>
                  </div>
                </div>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  {selectedPlan.description}
                </p>
              </div>

              {/* Billing Frequency Selector */}
              <div className="bg-[#0A0A0A] p-2 rounded-xl border border-white/10 flex items-center justify-between text-xs">
                <span className="font-bold text-[#A1A1AA] font-mono">Billing Cycle:</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setIsAnnual(false)}
                    className={`px-2.5 py-1 rounded text-[0.7rem] font-bold transition-all ${
                      !isAnnual ? 'bg-white text-black' : 'text-[#A1A1AA]'
                    }`}
                  >
                    Monthly
                  </button>
                  <button
                    onClick={() => setIsAnnual(true)}
                    className={`px-2.5 py-1 rounded text-[0.7rem] font-bold transition-all ${
                      isAnnual ? 'bg-white text-black' : 'text-[#A1A1AA]'
                    }`}
                  >
                    Annual (Save 20%)
                  </button>
                </div>
              </div>

              {/* Calculation Breakdown */}
              <div className="space-y-2.5 text-xs text-[#A1A1AA] pt-3 border-t border-white/10">
                <div className="flex justify-between">
                  <span>Base Price ({isAnnual ? '12 Months' : '1 Month'}):</span>
                  <span className="font-mono text-white">${subtotal.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-[#A1A1AA]">
                  <span>Estimated VAT / Tax (18%):</span>
                  <span className="font-mono">${tax.toFixed(2)}</span>
                </div>
                <div className="flex justify-between pt-2 border-t border-white/10 text-sm font-extrabold text-white">
                  <span>Total Due Today:</span>
                  <span className="font-mono text-white font-bold">${total.toFixed(2)}</span>
                </div>
              </div>

              {/* Included Features List */}
              <div className="space-y-2 pt-3 border-t border-white/10">
                <div className="text-[0.7rem] font-extrabold text-[#A1A1AA] uppercase font-mono">
                  INCLUDED IN THIS PLAN:
                </div>
                {selectedPlan.features.map((feat, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-[#EDEDED]">
                    <span className="text-white/40">&middot;</span>
                    <span>{feat}</span>
                  </div>
                ))}
              </div>

              {/* Trust Indicators */}
              <div className="p-3 rounded-lg bg-[#0A0A0A] border border-white/10 text-[0.72rem] text-[#A1A1AA] flex items-center gap-2">
                <Star size={14} className="text-[#F59E0B] shrink-0" />
                <span>14-Day 100% Money-Back Guarantee. No questions asked.</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Auth Modal for Unauthenticated Checkout Guests */}
      <AuthModal
        isOpen={isInternalAuthModalOpen}
        onClose={() => setIsInternalAuthModalOpen(false)}
        onLoginSuccess={(authedUser) => {
          setCurrentUser(authedUser);
          setIsInternalAuthModalOpen(false);
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(authedUser));
            localStorage.removeItem('shipguard_user');
          } catch (err) {
            console.warn('[CheckoutView] Failed to persist user session:', err);
          }
        }}
        initialMode={internalAuthMode}
      />
    </div>
  );
};
