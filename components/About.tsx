'use client';

import React from 'react';
import { motion } from 'framer-motion';

export const About: React.FC = () => {
  return (
    <section id="about" className="py-28 px-6 sm:px-12 bg-[#0A0A0A] border-b border-white/10 relative overflow-hidden">
      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-3">
          <span className="text-xs font-extrabold text-[#A1A1AA] font-mono uppercase tracking-widest">
            ABOUT
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight uppercase">
            Our Approach
          </h2>
        </div>

        {/* Manifesto Paragraph */}
        <div className="max-w-5xl text-2xl sm:text-4xl lg:text-5xl font-extrabold text-white leading-snug tracking-tight">
          Modern software development moves at breakneck speed. Whether written by senior engineers, accelerated by AI, or assembled from open-source packages, shipping without rigorous pre-flight validation introduces critical risk. ShipGuard guarantees that your web applications, cloud containers, and database layers are secure, accessible, and production-hardened before code merges.
        </div>

        {/* Core Standards Grid */}
        <div className="w-full pt-8 border-t border-white/10 grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
            <span className="text-xs font-mono font-bold text-[#A1A1AA] uppercase block">Security Clearance</span>
            <span className="text-sm font-bold text-white mt-1 block">Zero Day-One OWASP Flaws</span>
          </div>
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
            <span className="text-xs font-mono font-bold text-[#A1A1AA] uppercase block">UI/UX &amp; Accessibility</span>
            <span className="text-sm font-bold text-white mt-1 block">WCAG 2.1 AA &amp; Web Vitals</span>
          </div>
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
            <span className="text-xs font-mono font-bold text-[#A1A1AA] uppercase block">Cloud Infrastructure</span>
            <span className="text-sm font-bold text-white mt-1 block">Hardened Containers &amp; K8s</span>
          </div>
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
            <span className="text-xs font-mono font-bold text-[#A1A1AA] uppercase block">Instant Remediation</span>
            <span className="text-sm font-bold text-white mt-1 block">1-Click Patches &amp; Jira Sync</span>
          </div>
        </div>
      </div>
    </section>
  );
};
