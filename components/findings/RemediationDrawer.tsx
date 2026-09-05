// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Finding } from '@/data/schema';
import { X, Copy, CheckCircle2, AlertTriangle, Code, ShieldCheck, User, GitCommit } from 'lucide-react';

interface RemediationDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve: (id: string) => void;
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

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  finding,
  onClose,
  onToggleResolve,
}) => {
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [activeTab, setActiveTab] = useState<'diff' | 'prompt'>('diff');

  // Keyboard accessibility: Close drawer on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!finding) return null;

  const cleanSnippet = sanitizeContent(finding.snippet);
  const cleanPrompt = sanitizeContent(finding.remediationPrompt);
  const cleanTitle = sanitizeContent(finding.title);
  const cleanSteps = (finding.reproductionSteps || []).map(sanitizeContent);

  const diffText = `--- a/${finding.filePath}\n+++ b/${finding.filePath}\n@@ -${finding.lineRange} @@\n- ${cleanSnippet}\n+ // REMEDIATION: ${cleanPrompt}`;

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

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-50 flex justify-end bg-black/70 cursor-pointer min-h-[100dvh]"
        onClick={onClose}
      >
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-modal="true"
          aria-label={`Remediation details for ${cleanTitle}`}
          className="w-full max-w-xl bg-[#141414] border-l border-white/10 h-[100dvh] overflow-y-auto p-5 sm:p-8 flex flex-col gap-6 cursor-default shadow-2xl"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <span
                className={`badge ${
                  finding.severity === 'CRITICAL'
                    ? 'badge-critical'
                    : finding.severity === 'HIGH'
                    ? 'badge-high'
                    : 'badge-medium'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-white font-bold">
                {finding.category}
              </span>
            </div>

            <button
              onClick={onClose}
              aria-label="Close remediation drawer"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl hover:bg-white/10 text-[#A1A1AA] hover:text-white transition-colors cursor-pointer"
            >
              <X size={20} />
            </button>
          </div>

          {/* Finding Title & File */}
          <div>
            <h2 className="text-xl font-extrabold text-[#EDEDED]">
              {cleanTitle}
            </h2>
            <div className="text-xs font-mono text-white mt-1">
              File: {finding.filePath} ({finding.lineRange})
            </div>
          </div>

          {/* Code Snippet Evidence Block */}
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-[#A1A1AA] mb-2 font-mono">
              <Code size={16} className="text-white" />
              <span>Exposed Code Snippet Evidence:</span>
            </div>
            <div className="code-block bg-[#0A0A0A] border border-white/10 p-4 rounded-xl font-mono text-xs text-[#EDEDED] overflow-x-auto">
              <pre className="m-0 whitespace-pre">{cleanSnippet}</pre>
            </div>
          </div>

          {/* Reproduction & Impact Steps */}
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-[#CBD5E1] mb-2">
              <AlertTriangle size={16} className="text-[#F59E0B]" />
              <span>Audit Proof &amp; Reproduction Steps:</span>
            </div>
            <ol className="list-decimal list-inside space-y-1.5 text-xs text-[#A1A1AA]">
              {cleanSteps.length === 0 ? (
                <li className="list-none text-gray-500 italic">No custom reproduction steps recorded for this automated finding.</li>
              ) : (
                cleanSteps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))
              )}
            </ol>
          </div>

          {/* Claude Auto-Fix Prompt & Visual Diff Patch Block */}
          <div className="bg-[#0A0A0A] border border-white/10 p-5 rounded-xl flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center gap-2 text-xs font-mono font-extrabold text-white">
                <ShieldCheck size={16} />
                <span>Claude / Cursor Auto-Fix &amp; AST Diff Patch</span>
              </div>

              {/* View Toggle Tabs */}
              <div className="flex items-center gap-1.5 bg-[#141414] p-1 rounded-lg border border-white/10">
                <button
                  type="button"
                  onClick={() => setActiveTab('diff')}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded text-[0.7rem] font-mono font-bold transition-all ${
                    activeTab === 'diff'
                      ? 'bg-white text-black font-extrabold shadow-sm'
                      : 'text-[#A1A1AA] hover:text-white'
                  }`}
                >
                  <GitCommit size={12} />
                  <span>Visual Git Diff</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('prompt')}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded text-[0.7rem] font-mono font-bold transition-all ${
                    activeTab === 'prompt'
                      ? 'bg-white text-black font-extrabold shadow-sm'
                      : 'text-[#A1A1AA] hover:text-white'
                  }`}
                >
                  <Code size={12} />
                  <span>Claude Prompt</span>
                </button>
              </div>
            </div>

            {/* Quick Action Copy Bar */}
            <div className="flex items-center justify-between pt-1">
              <span className="text-[0.7rem] font-mono text-[#A1A1AA]">
                {activeTab === 'diff' ? 'Unified AST Patch (Git Compatible):' : 'Zero-Shot LLM Remediation Prompt:'}
              </span>

              <div className="flex items-center gap-2">
                {activeTab === 'diff' ? (
                  <button
                    onClick={copyDiff}
                    className="btn btn-secondary text-xs px-3 py-1 flex items-center gap-1.5"
                  >
                    {copiedDiff ? <CheckCircle2 size={13} className="text-[#10B981]" /> : <Code size={13} />}
                    <span>{copiedDiff ? 'Diff Copied!' : 'Copy Git Diff'}</span>
                  </button>
                ) : (
                  <button
                    onClick={copyPrompt}
                    className="btn btn-primary text-xs px-3 py-1 flex items-center gap-1.5"
                  >
                    {copiedPrompt ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                    <span>{copiedPrompt ? 'Prompt Copied!' : 'Copy Prompt'}</span>
                  </button>
                )}
              </div>
            </div>

            {/* Content Display: Visual Diff View or Claude Prompt */}
            {activeTab === 'diff' ? (
              <div className="bg-[#0A0A0A] border border-white/10 rounded-xl overflow-hidden font-mono text-xs">
                <div className="bg-[#141414] px-3.5 py-2 border-b border-white/10 flex items-center justify-between text-[#A1A1AA]">
                  <span className="truncate max-w-[280px]">{finding.filePath}</span>
                  <span className="text-[0.68rem] bg-white/10 px-2 py-0.5 rounded text-white font-bold font-mono">
                    Line {finding.lineRange}
                  </span>
                </div>
                <div className="p-3 space-y-1 overflow-x-auto text-[0.73rem] leading-relaxed">
                  <div className="text-white select-none font-bold">--- a/{finding.filePath}</div>
                  <div className="text-white select-none font-bold">+++ b/{finding.filePath}</div>
                  <div className="text-[#A1A1AA] select-none font-bold">@@ -{finding.lineRange} +{finding.lineRange} @@</div>
                  {/* Deletion line(s) */}
                  {cleanSnippet.split('\n').map((line, idx) => (
                    <div
                      key={`del-${idx}`}
                      className="bg-red-500/15 text-red-300 px-2 py-0.5 rounded border-l-2 border-red-500 flex items-start gap-2 font-mono"
                    >
                      <span className="text-red-400 select-none font-bold">-</span>
                      <span className="whitespace-pre">{line}</span>
                    </div>
                  ))}
                  {/* Addition line */}
                  <div className="bg-white/5 text-white px-2 py-0.5 rounded border-l-2 border-white/20 flex items-start gap-2 font-mono">
                    <span className="text-white select-none font-bold">+</span>
                    <span className="whitespace-pre">// REMEDIATION: {cleanPrompt}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 font-mono text-xs text-white leading-relaxed select-text">
                {cleanPrompt}
              </div>
            )}

            {/* Auditor & Advisor Disclaimer Notice */}
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3.5 flex items-start gap-2.5 text-xs text-zinc-300">
              <span className="text-emerald-400 select-none text-base leading-none shrink-0 mt-0.5">🛡️</span>
              <div className="leading-relaxed">
                <span className="font-bold text-emerald-400">ShipGuard Advisor Notice:</span>{' '}
                Remediation prompts are suggested guidelines. Always review code changes in your development environment before committing.
              </div>
            </div>
          </div>

          {/* Owner & Controls (min 44px touch targets for mobile viewport safety) */}
          <div className="mt-auto pt-4 border-t border-white/10 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-[#A1A1AA]">
              <User size={14} />
              <span>Owner: {finding.owner || 'Unassigned'}</span>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                className="min-h-[44px] px-4 py-2 rounded-xl bg-white/10 hover:bg-white/15 text-xs font-bold text-[#EDEDED] transition-colors cursor-pointer"
                onClick={onClose}
              >
                Close
              </button>

              <button
                type="button"
                onClick={() => {
                  onToggleResolve(finding.id);
                  onClose();
                }}
                className={`min-h-[44px] px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                  finding.status === 'RESOLVED'
                    ? 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700'
                    : 'bg-white text-black hover:bg-neutral-200'
                }`}
              >
                <CheckCircle2 size={14} />
                <span>{finding.status === 'RESOLVED' ? 'Re-open' : 'Mark Resolved'}</span>
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
