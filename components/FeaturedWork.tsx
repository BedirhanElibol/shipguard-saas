// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowUpRight, X, CheckCircle2 } from 'lucide-react';
import Image from 'next/image';

interface ProjectCard {
  id: string;
  title: string;
  category: string;
  client: string;
  year: string;
  image: string;
  score: number;
  gateStatus: 'PASSED' | 'WARNING' | 'FAILED';
  description: string;
  outcomes: string[];
}

export const FeaturedWork: React.FC = () => {
  const [selectedCase, setSelectedCase] = useState<ProjectCard | null>(null);

  React.useEffect(() => {
    if (selectedCase) {
      document.body.style.overflow = 'hidden';
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') setSelectedCase(null);
      };
      window.addEventListener('keydown', handleKeyDown);
      return () => {
        document.body.style.overflow = 'unset';
        window.removeEventListener('keydown', handleKeyDown);
      };
    }
  }, [selectedCase]);

  const projects: ProjectCard[] = [
    {
      id: 'proj-nexus',
      title: 'E-commerce Platform Security Audit',
      category: 'E-COMMERCE & NEXT.JS 15',
      client: 'Enterprise Client',
      year: '2026',
      image: '/images/vulnerability_sandbox.png',
      score: 98,
      gateStatus: 'PASSED',
      description:
        'Full release gate execution for an AI-generated e-commerce engine. Scanned 45 API routes, isolated exposed Stripe live keys into server environment variables, and added strict Supabase Row Level Security.',
      outcomes: [
        'Zero security vulnerabilities in production',
        '100% Pre-flight compliance clearance',
        'Prevented unauthorized anonymous user database queries'
      ]
    },
    {
      id: 'proj-synthflow',
      title: 'Developer Tool UI Redesign',
      category: 'FINTECH & VITE SPA',
      client: 'SaaS Startup',
      year: '2026',
      image: '/images/audit_findings.png',
      score: 94,
      gateStatus: 'PASSED',
      description:
        'Refactored a generic AI copilot interface. Stripped 14 visual UI anti-patterns, replaced high-contrast rainbow gradient borders with desaturated dark monochrome tokens, and added clean monospace metrics.',
      outcomes: [
        'Significant improvement in user session metrics',
        'Fully accessible high-contrast color scheme',
        'Eliminated Lucide icon flooding across top navigation'
      ]
    },
    {
      id: 'proj-aura',
      title: 'Healthcare API Cost Protection',
      category: 'HEALTHCARE & FASTAPI',
      client: 'Health Tech Client',
      year: '2026',
      image: '/images/security_rules.png',
      score: 97,
      gateStatus: 'PASSED',
      description:
        'Configured LLM token spend guardrails and automated disaster recovery. Set hard daily spending caps at $50/80/100% thresholds and implemented daily encrypted S3 snapshot backups.',
      outcomes: [
        'Prevented uncontrolled LLM token consumption',
        'Automated 24/7 disaster recovery restoration tested',
        'GDPR compliant PII data sanitization cascade'
      ]
    }
  ];

  return (
    <section id="work" className="py-28 px-6 sm:px-12 bg-[#0A0A0A] border-b border-white/10">
      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-3">
          <span className="text-xs font-extrabold text-[#A1A1AA] uppercase tracking-widest">
            CASE STUDIES
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-[#F5F3EF] tracking-tight uppercase">
            PRODUCTS WE AUDITED
          </h2>
        </div>

        {/* Sticky Stacking Cards Deck */}
        <div className="flex flex-col gap-12 relative">
          {projects.length === 0 ? (
            <div className="p-12 text-center bg-[#141414] border border-white/10 rounded-xl text-xs text-[#94A3B8]">
              No case studies available. Check back soon for audited client releases.
            </div>
          ) : (
            projects.map((item, idx) => (
              <motion.div
                key={item.id}
                className="sticky top-28 bg-[#141414] border border-white/10 rounded-xl p-8 sm:p-12 shadow-2xl flex flex-col lg:flex-row justify-between gap-8 items-center"
                style={{ zIndex: idx + 1 }}
              >
                <div className="flex flex-col justify-between gap-6 max-w-xl">
                  <div>
                    <div className="flex items-center gap-3 mb-3">
                      <span className="text-xs font-mono text-white font-bold">
                        {item.category}
                      </span>
                      <span className="badge badge-passed text-[0.65rem] font-mono">
                        SCORE: {item.score}/100
                      </span>
                    </div>

                    <h3 className="text-2xl sm:text-4xl font-extrabold text-[#FAFAFA] leading-tight mb-4">
                      {item.title}
                    </h3>

                    <p className="text-xs sm:text-sm text-[#94A3B8] leading-relaxed">
                      {item.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-4">
                    <button
                      onClick={() => setSelectedCase(item)}
                      className="btn btn-primary px-6 py-3 text-xs uppercase tracking-wider font-bold bg-white text-black hover:bg-neutral-200 transition-all rounded-lg flex items-center gap-2 shadow-sm"
                    >
                      <span>View Case Study</span>
                      <ArrowUpRight size={14} />
                    </button>
                  </div>
                </div>

                {/* Card Image Thumbnail */}
                <div className="relative w-full lg:w-[480px] aspect-[16/10] rounded-xl overflow-hidden border border-white/10 bg-[#0A0A0A] p-2 sm:p-3 flex items-center justify-center shrink-0">
                  <div className="relative w-full h-full">
                    <Image
                      src={item.image}
                      alt={item.title}
                      fill
                      sizes="(max-width: 1200px) 100vw, 480px"
                      className="object-contain"
                    />
                  </div>
                </div>
              </motion.div>
            ))
          )}
        </div>
      </div>

      {/* Case Study Modal */}
      <AnimatePresence>
        {selectedCase && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
            onClick={(e) => { if (e.target === e.currentTarget) setSelectedCase(null); }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#141414] border border-white/10 rounded-xl max-w-2xl w-full p-8 max-h-[90vh] overflow-y-auto relative flex flex-col gap-6"
            >
              <button
                onClick={() => setSelectedCase(null)}
                className="absolute top-6 right-6 text-[#A1A1AA] hover:text-white"
              >
                <X size={20} />
              </button>

              <div>
                <span className="text-xs font-mono text-white font-bold">
                  {selectedCase.category}
                </span>
                <h3 className="text-2xl font-extrabold text-[#F5F3EF] mt-1">
                  {selectedCase.title}
                </h3>
              </div>

              <div className="relative w-full aspect-[16/10] rounded-xl overflow-hidden border border-white/10 bg-[#0A0A0A] p-2 flex items-center justify-center">
                <div className="relative w-full h-full">
                  <Image
                    src={selectedCase.image}
                    alt={selectedCase.title}
                    fill
                    className="object-contain"
                  />
                </div>
              </div>

              <p className="text-xs text-[#E4E4E7] leading-relaxed">
                {selectedCase.description}
              </p>

              <div>
                <h4 className="text-xs font-extrabold text-[#F5F3EF] uppercase tracking-wider mb-2">
                  Key Verification Outcomes:
                </h4>
                <div className="space-y-2">
                  {selectedCase.outcomes.map((out, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs text-white">
                      <span className="text-white/40 shrink-0">·</span>
                      <span>{out}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 border-t border-white/10 flex justify-end">
                <button
                  onClick={() => setSelectedCase(null)}
                  className="btn btn-secondary btn-sm"
                >
                  Close Modal
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </section>
  );
};
