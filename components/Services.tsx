'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2 } from 'lucide-react';
import Image from 'next/image';

export const Services: React.FC = () => {
  const [activeIdx, setActiveIdx] = useState(0);

  const services = [
    {
      id: 'sec-audit',
      title: 'AI Software Architecture & Security Audit',
      category: 'CYBERSECURITY & AUDIT',
      description:
        'We design and audit production-grade AI codebases. We verify secret key isolation, Supabase Row Level Security (RLS) policies, CORS restrictions, rate-limiting, and password hashing before launch.',
      image: '/images/security_rules.png',
      badge: 'OWASP TOP 10',
      highlights: [
        'Zero hardcoded API secrets in client bundles',
        'Strict PostgreSQL RLS policy validation',
        'HMAC webhook signature verification'
      ]
    },
    {
      id: 'vibepolish',
      title: 'Brand Strategy & Design System Polish',
      category: 'DESIGN SYSTEM & UX CRAFT',
      description:
        'We craft visual identities and desaturated monochrome design tokens. We strip out common AI UI clichés like neon glow clutter, icon flooding, stark unstyled whites, and em-dash addiction.',
      image: '/images/audit_findings.png',
      badge: 'UI & UX POLISH',
      highlights: [
        'Desaturated monochrome color tokens',
        'Negative prompt linter for Cursor / v0 / Lovable',
        'Accessibility & contrast scorecard'
      ]
    },
    {
      id: 'vibecare',
      title: 'Lifecycle Monitoring & Infrastructure Resilience',
      category: 'LIFECYCLE & SUSTAINABILITY',
      description:
        'We safeguard your application against runaway LLM token loops and unexpected billing spikes with hard caps ($50/80/100%), automated S3 disaster recovery snapshots, and dependency CVE drift alerts.',
      image: '/images/bundle_profiler.png',
      badge: 'SUSTAINABILITY',
      highlights: [
        'Automated daily encrypted S3 snapshots',
        'LLM daily budget webhook alerts',
        'White-label client PDF audit rescue reports'
      ]
    }
  ];

  return (
    <section id="services" className="py-28 px-6 sm:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-3">
          <span className="text-xs font-extrabold text-[#A1A1AA] uppercase tracking-widest">
            PRODUCT CAPABILITIES
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#F5F3EF] tracking-tight uppercase">
            RELEASE GATE FOR AI SOFTWARE
          </h2>
        </div>

        {/* 12-Column Grid Layout (5/7 Split) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
          {/* Left Column (5 Cols) - Interactive Service List */}
          <div className="lg:col-span-5 flex flex-col gap-4">
            {services.length === 0 ? (
              <div className="bg-[#141414] border border-white/10 rounded-xl p-6 text-center text-xs text-[#A1A1AA]">
                No services available at this time.
              </div>
            ) : (
              services.map((item, idx) => {
                const isActive = activeIdx === idx;

                return (
                  <div
                    key={item.id}
                    onMouseEnter={() => setActiveIdx(idx)}
                    onClick={() => setActiveIdx(idx)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setActiveIdx(idx);
                      }
                    }}
                    className={`bg-[#141414] border rounded-xl p-6 sm:p-8 cursor-pointer transition-all ${
                      isActive
                        ? 'border-white/30 shadow-xl'
                        : 'border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[0.68rem] font-mono text-[#A1A1AA] font-bold">
                        {item.category}
                      </span>
                      <span className="badge badge-passed text-[0.65rem] font-mono">
                        {item.badge}
                      </span>
                    </div>

                    <h3 className="text-lg font-extrabold text-white mb-2">
                      {item.title}
                    </h3>

                    <p className="text-xs text-[#A1A1AA] leading-relaxed mb-4">
                      {item.description}
                    </p>

                    {/* Highlights List */}
                    <div className="space-y-1.5 pt-3 border-t border-white/10">
                      {item.highlights.map((h, i) => (
                        <div key={i} className="flex items-center gap-2 text-[0.72rem] text-[#EDEDED]">
                          <span className="text-white/40 shrink-0">·</span>
                          <span>{h}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Right Column (7 Cols) - Sticky Media Crossfade Preview */}
          <div className="lg:col-span-7 sticky top-28 w-full">
            <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-6 overflow-hidden min-h-[440px] flex flex-col justify-between">
              {services[activeIdx] && (
                <AnimatePresence mode="wait">
                  <motion.div
                    key={services[activeIdx].id}
                    initial={{ opacity: 0, scale: 0.98 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 1.02 }}
                    transition={{ duration: 0.2 }}
                    className="flex flex-col gap-4 w-full h-full"
                  >
                    <div className="relative w-full aspect-[16/10] rounded-xl overflow-hidden border border-white/10 bg-[#0A0A0A] p-2 sm:p-4 flex items-center justify-center shadow-inner">
                      <div className="relative w-full h-full">
                        <Image
                          src={services[activeIdx].image}
                          alt={services[activeIdx].title}
                          fill
                          sizes="(max-width: 1200px) 100vw, 800px"
                          className="object-contain"
                        />
                      </div>
                    </div>

                    <div className="p-1">
                      <div className="text-xs font-mono text-[#A1A1AA] font-bold">
                        {services[activeIdx].badge}
                      </div>
                      <div className="text-sm font-extrabold text-white mt-1">
                        {services[activeIdx].title}
                      </div>
                    </div>
                  </motion.div>
                </AnimatePresence>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
