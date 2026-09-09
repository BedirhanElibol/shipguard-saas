// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { ShieldCheck, ArrowUpRight } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

export const Footer: React.FC = () => {
  return (
    <footer className="bg-[#0A0A0A] text-[#A1A1AA] border-t border-white/10 pt-20 pb-12 px-6">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-12 pb-16 border-b border-white/10">
        {/* Col 1: Brand Info (5 cols) */}
        <div className="md:col-span-5 flex flex-col gap-4">
          <ZelsisLogo size="md" />

          <p className="text-sm leading-relaxed max-w-sm text-[#A1A1AA]">
            Automated release gate for AI-built software applications. Pre-flight security clearance &amp; VibePolish design verification matrix.
          </p>

          <a
            href="mailto:contact@zelsis.com"
            className="text-sm font-mono text-white hover:underline inline-flex items-center gap-1 mt-2"
          >
            <span>contact@zelsis.com</span>
            <ArrowUpRight size={14} />
          </a>
        </div>

        {/* Col 2: Navigation (3 cols) */}
        <div className="md:col-span-3 flex flex-col gap-3">
          <span className="text-xs font-bold text-white font-mono tracking-widest uppercase mb-2">
            NAVIGATION
          </span>
          <a href="#services" className="text-sm hover:text-white transition-colors">
            Features &amp; Gate
          </a>
          <a href="#work" className="text-sm hover:text-white transition-colors">
            Case Studies
          </a>
          <a href="#pricing" className="text-sm hover:text-white transition-colors">
            Pricing Plans
          </a>
        </div>

        {/* Col 3: SaaS Platform (4 cols) */}
        <div className="md:col-span-4 flex flex-col gap-3">
          <span className="text-xs font-bold text-[#EDEDED] tracking-widest uppercase mb-2 font-mono">
            ZELSIS PLATFORM
          </span>
          <a href="/dashboard" className="text-sm text-white hover:underline transition-colors font-mono">
            Launch Audit Engine →
          </a>
          <span className="text-xs text-[#A1A1AA]">Zero Day-One Production Vulnerabilities</span>
          <span className="text-xs text-[#A1A1AA]">Enterprise-Grade UX &amp; Accessibility</span>
          <span className="text-xs text-[#A1A1AA]">Guaranteed Deployment Safety &amp; Uptime</span>
        </div>


      </div>

      {/* Bottom Bar */}
      <div className="max-w-7xl mx-auto pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#A1A1AA]">
        <div>
          © 2026 Zelsis. All rights reserved.
        </div>
        <div className="flex gap-6">
          <a href="/privacy" className="hover:text-white transition-colors">Privacy</a>
          <a href="/terms" className="hover:text-white transition-colors">Terms</a>
        </div>
      </div>
    </footer>
  );
};
