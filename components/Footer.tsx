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
            Universal pre-flight release gate for modern web and cloud applications. Automated OWASP security clearance, WCAG 2.1 AA accessibility, and cloud infrastructure verification.
          </p>

          <span
            className="text-sm font-mono text-white inline-flex items-center gap-1 mt-2"
          >
            <span>contact@zelsis.com</span>
            <ArrowUpRight size={14} />
          </span>
        </div>

        {/* Col 2: Navigation (3 cols) */}
        <div className="md:col-span-3 flex flex-col gap-3">
          <span className="text-xs font-bold text-white font-mono tracking-widest uppercase mb-2">
            NAVIGATION
          </span>
          <a href="#features" className="text-sm hover:text-white transition-colors">
            Release Capabilities
          </a>
          <a href="#workflow" className="text-sm hover:text-white transition-colors">
            How It Works
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
        <div className="flex flex-wrap gap-4 sm:gap-6">
          <a href="/privacy" className="hover:text-white transition-colors">Privacy</a>
          <a href="/terms" className="hover:text-white transition-colors">Terms</a>
          <a href="/cookies" className="hover:text-white transition-colors">Cookie Policy</a>
        </div>
      </div>
    </footer>
  );
};
