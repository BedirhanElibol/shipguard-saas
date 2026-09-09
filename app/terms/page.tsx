import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck, ArrowLeft } from 'lucide-react';

export const metadata: Metadata = {
  title: 'Terms of Service',
  description: 'Zelsis Terms of Service, code verification conditions, and subscription billing agreements.',
};

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-[#0D0D0D] text-[#F8FAFC] p-6 sm:p-12 font-sans">
      <div className="max-w-3xl mx-auto flex flex-col gap-8">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-xs font-mono text-[#888888] hover:text-[#FFFFFF] transition-colors"
        >
          <ArrowLeft size={14} />
          <span>Back to Home</span>
        </Link>

        <div>
          <div className="flex items-center gap-2.5 mb-2">
            <ShieldCheck size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Terms of Service &amp; Conditions
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 2, 2026 // Version 1.0.0
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Terms Agreement</h2>
            <p>
              By accessing or using the Zelsis platform, you agree to be bound by these Terms of Service. If you do not agree to these terms, you may not access or use our services.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. Scope of Service</h2>
            <p>
              Zelsis provides automated security clearance checks, design system hygiene audits, and code verification tooling. Audit findings and prompts are provided for developer assistance and do not constitute formal legal or regulatory certification guarantees.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Acceptable Use</h2>
            <p>
              You agree not to use Zelsis to scan unauthorized third-party repositories without explicit permission or attempt to bypass system rate limits and authentication boundaries.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Subscription &amp; Billing</h2>
            <p>
              Subscriptions renew automatically according to your selected billing cycle (Monthly or Annual). You may cancel your subscription at any time via your dashboard profile billing settings.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
