import React from 'react';
import type { Metadata } from 'next';
import Link from 'next/link';
import { ShieldCheck, ArrowLeft, Globe, Lock, FileText } from 'lucide-react';

export const metadata: Metadata = {
  title: 'Privacy Policy & Data Protection',
  description: 'Zelsis Privacy Policy, GDPR & KVKK compliance, telemetry data handling, and zero codebase retention policy.',
};

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-[#0D0D0D] text-[#F8FAFC] p-6 sm:p-12 font-sans">
      <div className="max-w-3xl mx-auto flex flex-col gap-8">
        <div className="flex items-center justify-between">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-xs font-mono text-[#888888] hover:text-[#FFFFFF] transition-colors"
          >
            <ArrowLeft size={14} />
            <span>Back to Home</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              href="/kvkk"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              KVKK Aydınlatma Metni (TR)
            </Link>
            <span className="text-[#333]">•</span>
            <Link
              href="/cerez-politikasi"
              className="text-xs font-mono text-emerald-400 hover:underline"
            >
              Cookie Policy
            </Link>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2.5 mb-2">
            <ShieldCheck size={24} className="text-[#10B981]" />
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#FFFFFF] tracking-tight">
              Privacy Policy &amp; Data Protection
            </h1>
          </div>
          <p className="text-xs font-mono text-[#888888]">
            Last Updated: September 10, 2026 // Compliant with GDPR (EU 2016/679) &amp; KVKK No. 6698
          </p>
        </div>

        <div className="flex flex-col gap-6 text-xs sm:text-sm text-[#CCCCCC] leading-relaxed border-t border-[#262626] pt-6">
          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">1. Data Controller Identity &amp; Scope</h2>
            <p>
              Zelsis (&quot;we&quot;, &quot;our&quot;, or &quot;us&quot;) operates the Zelsis Pre-Flight Release Gate SaaS platform. This Privacy Policy details how we process personal data in accordance with the General Data Protection Regulation (GDPR), the Turkish Law on the Protection of Personal Data (KVKK No. 6698), and applicable data protection legislation.
            </p>
            <div className="bg-[#141414] border border-[#262626] rounded-xl p-3 text-xs font-mono text-[#AAAAAA] mt-1 space-y-0.5">
              <div>Data Protection Officer: privacy@zelsis.com</div>
              <div>General Inquiries: contact@zelsis.com</div>
              <div>Registered Jurisdiction: Istanbul, Turkey</div>
            </div>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">2. Codebase Privacy &amp; Zero Retention Architecture</h2>
            <p>
              Source code submitted for static analysis, secret scanning, and design cliché audits is evaluated ephemerally in serverless memory. <strong>We do not store, index, sell, or train public AI/LLM models on your proprietary source code.</strong> Once the AST rule evaluation finishes, in-memory buffers are flushed immediately.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">3. Categories of Personal Data Collected</h2>
            <ul className="list-disc list-inside space-y-1.5 text-[#AAAAAA]">
              <li><strong>Identity &amp; Account Data:</strong> Name, email address, GitHub username, avatar URL (when authenticated via GitHub/OAuth).</li>
              <li><strong>Telemetry &amp; Audit Logs:</strong> Timestamps of security scans, pass/warning/failed clearance scores, rule violation counts.</li>
              <li><strong>Technical Metadata:</strong> IP address, browser user-agent, session cookies (<code className="text-emerald-400">zelsis_user</code>).</li>
              <li><strong>Billing Records:</strong> Subscription plan tier, license keys, and transaction references tokenized by certified payment gateways (Polar / Stripe). We never store raw credit card numbers.</li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">4. Legal Grounds for Processing (GDPR Art. 6 / KVKK Art. 5)</h2>
            <ul className="list-disc list-inside space-y-1 text-[#AAAAAA]">
              <li><strong>Contractual Performance (Art. 6(1)(b)):</strong> Providing the SaaS service, executing scans, and managing user subscriptions.</li>
              <li><strong>Legitimate Interests (Art. 6(1)(f)):</strong> Platform security, brute-force protection, and preventing service abuse.</li>
              <li><strong>Legal Obligation (Art. 6(1)(c)):</strong> Compliance with statutory tax, invoicing, and digital commercial obligations.</li>
            </ul>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">5. Cross-Border Data Transfers &amp; Subprocessors</h2>
            <p>
              Zelsis infrastructure is hosted on ISO 27001 / SOC 2 certified cloud providers: Supabase (Postgres managed on AWS EU/US) and Vercel Inc. (Edge network, USA). All cross-border transmissions are executed under Standard Contractual Clauses (SCCs) and explicit consent mechanisms.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">6. Data Retention &amp; Right to Erasure (GDPR Art. 17 / KVKK Art. 7)</h2>
            <p>
              Account data is retained for the duration of your active subscription. You can permanently delete your account and all associated telemetry at any time directly in your Project Settings dashboard or by sending an erasure request to{' '}
              <a href="mailto:privacy@zelsis.com" className="text-[#FFFFFF] underline underline-offset-4 font-mono">
                privacy@zelsis.com
              </a>. Server-side deletion cascades to all database records and authentication tables within 24 hours.
            </p>
          </section>

          <section className="flex flex-col gap-2">
            <h2 className="text-base font-bold text-[#FFFFFF]">7. Contact &amp; Regulatory Inquiries</h2>
            <p>
              To exercise your rights (access, rectification, portability, erasure), please contact:
            </p>
            <p className="font-mono text-xs text-emerald-400">
              privacy@zelsis.com // Attn: Data Protection Officer
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
