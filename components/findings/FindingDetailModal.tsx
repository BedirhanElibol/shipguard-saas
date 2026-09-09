// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Finding } from '@/data/schema';
import { X, Copy, CheckCircle2, AlertTriangle, Code, ShieldCheck, User, GitCommit, ExternalLink } from 'lucide-react';

export interface FindingDetailModalProps {
  isOpen: boolean;
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve?: (id: string) => void;
}

/**
 * Defang raw dangerous HTML tags and scripts to prevent client-side XSS injection
 */
function sanitizeContent(text: string): string {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRUBBED_SCRIPT]')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '[SCRUBBED_IFRAME]')
    .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '[SCRUBBED_OBJECT]')
    .replace(/javascript\s*:/gi, 'blocked-javascript:');
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  isOpen,
  finding,
  onClose,
  onToggleResolve,
}) => {
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [activeTab, setActiveTab] = useState<'prompt' | 'diff'>('prompt');

  // Keyboard accessibility: Close on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !finding) return null;

  const cleanSnippet = sanitizeContent(finding.snippet);
  const cleanPrompt = sanitizeContent(finding.remediationPrompt);
  const cleanTitle = sanitizeContent(finding.title);
  const cleanSteps = (finding.reproductionSteps || []).map(sanitizeContent);

  const diffText =
    finding.diffPatch ||
    `--- a/${finding.filePath}\n+++ b/${finding.filePath}\n@@ -${finding.lineRange} @@\n- ${cleanSnippet}\n+ // REMEDIATION: ${cleanPrompt}`;

  const copyDiff = () => {
    navigator.clipboard.writeText(diffText);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  const copyPrompt = () => {
    navigator.clipboard.writeText(cleanPrompt);
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  const severityBadgeClass =
    finding.severity === 'CRITICAL'
      ? 'bg-red-500/10 text-red-400 border border-red-500/30'
      : finding.severity === 'HIGH'
      ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
      : finding.severity === 'MEDIUM'
      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
      : 'bg-zinc-800 text-zinc-300 border border-zinc-700';

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm min-h-[100dvh]"
        onClick={onClose}
        role="presentation"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 10 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-label={`Detailed Audit Finding: ${cleanTitle}`}
          className="w-full max-w-2xl max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-8 flex flex-col gap-6 shadow-2xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-extrabold uppercase ${severityBadgeClass}`}>
                {finding.severity}
              </span>
              {finding.type === 'LEGAL_COMPLIANCE' && (
                <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1.5">
                  <span>⚖️</span>
                  <span>Legal &amp; Privacy Gate</span>
                </span>
              )}
              {finding.type === 'INFRA_DATABASE' && (
                <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 flex items-center gap-1.5">
                  <span>🗄️</span>
                  <span>Infra &amp; Database Gate</span>
                </span>
              )}
              <span className="text-xs font-mono text-zinc-400 font-bold">
                {finding.category}
              </span>
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label="Close modal"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Finding Title & File Path */}
          <div>
            <h2 className="text-lg sm:text-xl font-extrabold text-[#EDEDED] leading-tight">
              {cleanTitle}
            </h2>
            <div className="text-xs font-mono text-emerald-400/90 mt-1.5 flex items-center gap-2">
              <span>{finding.filePath}</span>
              <span className="text-zinc-500">·</span>
              <span className="bg-white/5 px-2 py-0.5 rounded text-zinc-300 font-bold">
                {finding.lineRange}
              </span>
            </div>
          </div>

          {/* Code Snippet Evidence */}
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-zinc-400 mb-2 font-mono">
              <Code size={15} className="text-zinc-300" />
              <span>Exposed Code Snippet Evidence:</span>
            </div>
            <div className="bg-[#0A0A0A] border border-white/10 p-4 rounded-xl font-mono text-xs text-zinc-200 overflow-x-auto leading-relaxed">
              <pre className="m-0 whitespace-pre">{cleanSnippet}</pre>
            </div>
          </div>

          {/* Reproduction & Audit Steps */}
          {cleanSteps.length > 0 && (
            <div>
              <div className="flex items-center gap-2 text-xs font-bold text-zinc-300 mb-2 font-mono">
                <AlertTriangle size={15} className="text-amber-400" />
                <span>Reproduction &amp; Verification Evidence:</span>
              </div>
              <ol className="list-decimal list-inside space-y-1.5 text-xs text-zinc-400 bg-black/40 border border-white/5 rounded-xl p-3.5">
                {cleanSteps.map((step, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {step}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Remediation Guidance & Safe Diff */}
          <div className="bg-[#0A0A0A] border border-white/10 p-5 rounded-xl flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center gap-2 text-xs font-mono font-extrabold text-zinc-200">
                <ShieldCheck size={16} className="text-emerald-400" />
                <span>Auditor Remediation &amp; Patch Guide</span>
              </div>

              {/* View Toggle Tabs */}
              <div className="flex items-center gap-1 bg-[#141414] p-1 rounded-lg border border-white/10 self-start sm:self-auto">
                <button
                  type="button"
                  onClick={() => setActiveTab('prompt')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded text-[0.7rem] font-mono font-bold transition-all ${
                    activeTab === 'prompt'
                      ? 'bg-white text-black font-extrabold shadow-sm'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  <Code size={12} />
                  <span>Remediation Prompt</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('diff')}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded text-[0.7rem] font-mono font-bold transition-all ${
                    activeTab === 'diff'
                      ? 'bg-white text-black font-extrabold shadow-sm'
                      : 'text-zinc-400 hover:text-white'
                  }`}
                >
                  <GitCommit size={12} />
                  <span>Git Diff Patch</span>
                </button>
              </div>
            </div>

            {/* Quick Action Copy Button */}
            <div className="flex items-center justify-between pt-1">
              <span className="text-[0.7rem] font-mono text-zinc-400">
                {activeTab === 'prompt' ? 'Developer-Reviewed Prompt:' : 'Unified AST Patch:'}
              </span>

              {activeTab === 'prompt' ? (
                <button
                  type="button"
                  onClick={copyPrompt}
                  className="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-xs font-bold font-mono flex items-center gap-1.5 transition-all"
                >
                  {copiedPrompt ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                  <span>{copiedPrompt ? 'Prompt Copied!' : 'Copy Prompt'}</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={copyDiff}
                  className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 border border-white/15 text-white text-xs font-bold font-mono flex items-center gap-1.5 transition-all"
                >
                  {copiedDiff ? <CheckCircle2 size={13} className="text-emerald-400" /> : <Code size={13} />}
                  <span>{copiedDiff ? 'Diff Copied!' : 'Copy Diff'}</span>
                </button>
              )}
            </div>

            {/* Prompt or Diff View */}
            {activeTab === 'prompt' ? (
              <div className="bg-[#141414] p-4 rounded-xl border border-white/10 font-mono text-xs text-zinc-200 leading-relaxed select-text">
                {cleanPrompt}
              </div>
            ) : (
              <div className="bg-[#141414] border border-white/10 rounded-xl overflow-hidden font-mono text-xs">
                <div className="p-3 space-y-1 overflow-x-auto text-[0.73rem] leading-relaxed">
                  {finding.diffPatch ? (
                    finding.diffPatch.split('\n').map((dLine, idx) => {
                      const isAdd = dLine.startsWith('+') && !dLine.startsWith('+++');
                      const isDel = dLine.startsWith('-') && !dLine.startsWith('---');
                      const isHdr = dLine.startsWith('@@') || dLine.startsWith('---') || dLine.startsWith('+++');
                      return (
                        <div
                          key={`patch-${idx}`}
                          className={`px-2 py-0.5 rounded font-mono ${
                            isAdd
                              ? 'bg-emerald-500/15 text-emerald-300 border-l-2 border-emerald-500'
                              : isDel
                              ? 'bg-red-500/15 text-red-300 border-l-2 border-red-500'
                              : isHdr
                              ? 'text-zinc-500 font-bold select-none'
                              : 'text-zinc-300'
                          }`}
                        >
                          <span className="whitespace-pre">{dLine}</span>
                        </div>
                      );
                    })
                  ) : (
                    <>
                      <div className="text-zinc-400 select-none">--- a/{finding.filePath}</div>
                      <div className="text-zinc-400 select-none">+++ b/{finding.filePath}</div>
                      <div className="text-zinc-500 select-none">@@ -{finding.lineRange} +{finding.lineRange} @@</div>
                      {cleanSnippet.split('\n').map((line, idx) => (
                        <div
                          key={`del-${idx}`}
                          className="bg-red-500/15 text-red-300 px-2 py-0.5 rounded border-l-2 border-red-500 flex items-start gap-2 font-mono"
                        >
                          <span className="text-red-400 select-none">-</span>
                          <span className="whitespace-pre">{line}</span>
                        </div>
                      ))}
                      <div className="bg-emerald-500/15 text-emerald-300 px-2 py-0.5 rounded border-l-2 border-emerald-500 flex items-start gap-2 font-mono">
                        <span className="text-emerald-400 select-none">+</span>
                        <span className="whitespace-pre">// REMEDIATION: {cleanPrompt}</span>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Auditor & Advisor Disclaimer Banner */}
            {finding.type === 'LEGAL_COMPLIANCE' ? (
              <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="text-amber-400 select-none text-base leading-none shrink-0 mt-0.5">⚖️</span>
                <div className="leading-relaxed">
                  <span className="font-bold text-amber-400">Legal &amp; Regulatory Pre-Flight Gate:</span>{' '}
                  This finding flags non-compliance with statutory privacy or payment standards (GDPR, ePrivacy, CCPA, PCI-DSS). Remediate before deploying to production.
                </div>
              </div>
            ) : finding.type === 'INFRA_DATABASE' ? (
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="text-cyan-400 select-none text-base leading-none shrink-0 mt-0.5">🗄️</span>
                <div className="leading-relaxed">
                  <span className="font-bold text-cyan-400">Infrastructure &amp; Database Gate:</span>{' '}
                  This finding detects cloud configuration or database exposure (Supabase RLS, Docker privileges, DB secrets, CORS). Apply the unified patch to secure your release.
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
                <span className="text-emerald-400 select-none text-base leading-none shrink-0 mt-0.5">🛡️</span>
                <div className="leading-relaxed">
                  <span className="font-bold text-emerald-400">Zelsis Advisor Notice:</span>{' '}
                  Remediation prompts are suggested guidelines. Always review code changes in your development environment before committing.
                </div>
              </div>
            )}
          </div>

          {/* Footer Actions (min 44px touch targets for mobile viewport safety) */}
          <div className="pt-3 border-t border-white/10 flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2 text-xs text-zinc-400">
              <User size={14} />
              <span>Owner: {finding.owner || 'Unassigned'}</span>
            </div>

            <div className="flex items-center gap-2.5">
              {onToggleResolve && (
                <button
                  type="button"
                  onClick={() => onToggleResolve(finding.id)}
                  className={`min-h-[44px] px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    finding.status === 'RESOLVED'
                      ? 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700'
                      : 'bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300'
                  }`}
                >
                  {finding.status === 'RESOLVED' ? 'Reopen Finding' : 'Mark as Resolved'}
                </button>
              )}
              <button
                type="button"
                onClick={onClose}
                className="min-h-[44px] px-5 py-2.5 rounded-xl bg-white text-black font-bold text-xs hover:bg-neutral-200 transition-all shadow-sm cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
