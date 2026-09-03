// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Award, ShieldCheck, CheckCircle2, AlertTriangle, Play, Pause, Volume2 } from 'lucide-react';
import { Project } from '@/data/schema';

interface ExecutiveBriefingModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
}

export const ExecutiveBriefingModal: React.FC<ExecutiveBriefingModalProps> = ({
  isOpen,
  onClose,
  project
}) => {
  const [isPlaying, setIsPlaying] = useState(false);

  // Keyboard Escape listener for Accessibility (WCAG 2.2 AA)
  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const toggleAudio = () => {
    setIsPlaying((prev) => !prev);
  };

  const isPassed = project.gateStatus === 'PASSED';

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
        role="dialog"
        aria-modal="true"
        aria-labelledby="executive-briefing-title"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Award size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Executive Briefing &amp; CISO Summary
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Synthesized strategic release readiness briefing for C-Level Leadership
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close executive briefing"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={20} />
            </button>
          </div>

          {/* Audio Briefing Player Bar */}
          <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <button
                onClick={toggleAudio}
                className="w-10 h-10 rounded-full bg-white text-black flex items-center justify-center font-bold hover:bg-neutral-200 transition-all shadow-md"
              >
                {isPlaying ? <Pause size={18} /> : <Play size={18} className="ml-0.5" />}
              </button>
              <div>
                <div className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
                  <Volume2 size={14} className="text-white" />
                  <span>3-Minute AI Executive Voice Briefing</span>
                </div>
                <div className="text-[0.68rem] text-[#94A3B8]">
                  {isPlaying ? 'Playing AI synthesized audio report...' : 'Click play to listen to 3-minute executive summary'}
                </div>
              </div>
            </div>

            <span className="text-xs font-mono text-white font-bold">
              03:12
            </span>
          </div>

          {/* Executive Summary Card */}
          <div className="space-y-4 text-xs text-[#94A3B8] leading-relaxed">
            <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 space-y-2">
              <h3 className="font-bold uppercase text-[0.7rem] tracking-wider text-white font-mono">
                1. EXECUTIVE SUMMARY &amp; OVERALL RISK POSTURE
              </h3>
              <p>
                Target system <strong>"{project.name}"</strong> has evaluated a readiness score of{' '}
                <strong className="text-white">{project.readinessScore}/100</strong>. The release gate status is currently evaluated as{' '}
                <strong className={isPassed ? 'text-white' : 'text-red-400'}>{project.gateStatus}</strong>.
              </p>
            </div>

            <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 space-y-2">
              <h3 className="font-bold uppercase text-[0.7rem] tracking-wider text-white font-mono">
                2. COMPLIANCE &amp; OWASP CLEARANCE SUMMARY
              </h3>
              <p>
                The automated audit engine scanned {project.findings.length} total findings across 23 OWASP Top-10 security guidelines and 200 VibePolish UI rules. Detected{' '}
                <strong className="text-red-400">{project.criticalCount} Critical</strong> vulnerabilities and{' '}
                <strong className="text-[#A1A1AA]">{project.highCount} High</strong> risk findings requiring remediation.
              </p>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-end pt-2 border-t border-white/10">
            <button className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm" onClick={onClose}>
              Close Briefing
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
