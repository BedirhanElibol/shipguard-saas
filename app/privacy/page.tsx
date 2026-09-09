import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck, ArrowLeft } from 'lucide-react';

export const metadata: Metadata = {
  title: 'Privacy Policy',
  description: 'Zelsis Privacy Policy, telemetry data handling, and zero codebase retention policy.',
};

export default function PrivacyPolicyPage() {
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
              Privacy Policy &amp; Data Protection
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 2, 2026 // Version 1.0.0
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Overview</h2>
            <p>
              Zelsis ("we", "our", or "us") is committed to protecting your privacy. This Privacy Policy explains how our AI Security Clearance &amp; Pre-flight Audit Matrix platform handles code inspection, telemetry, and user authentication data.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. Codebase Privacy &amp; Zero Retention</h2>
            <p>
              Code snippets submitted for AST analysis in Zelsis are processed ephemerally in memory to evaluate security rules and design system anti-patterns. We do not store, index, or train public AI models on your proprietary source code.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Information We Collect</h2>
            <ul className="list-disc list-inside space-y-1 text-[#AAAAAA]">
              <li>Account credentials (Email, OAuth profile tokens via Supabase Auth)</li>
              <li>Usage telemetry (Scan timestamps, pass/fail status metrics)</li>
              <li>Billing metadata processed via PCI-DSS compliant Stripe checkout</li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Contact Us</h2>
            <p>
              For privacy requests or KVKK/GDPR data removal inquiries, please contact our privacy desk at{' '}
              <a href="mailto:privacy@zelsis.com" className="text-[#FFFFFF] underline underline-offset-4">
                privacy@zelsis.com
              </a>.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
