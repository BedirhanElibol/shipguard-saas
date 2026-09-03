// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useRef } from 'react';
import { Project, Finding } from '@/data/schema';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import { Play, AlertTriangle, CheckCircle2, Sliders, Download, Award, MoreVertical, GitCompare, Bell, Server, ShieldAlert, ShieldCheck, BookOpen } from 'lucide-react';

interface GateStatusBannerProps {
  project: Project;
  criticals: Finding[];
  highs: Finding[];
  uiCliches: Finding[];
  onTriggerScan: () => void;
  setIsRuleConfigOpen: (v: boolean) => void;
  setIsExecutiveBriefingOpen: (v: boolean) => void;
  isMoreToolsOpen: boolean;
  setIsMoreToolsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  setIsCompareOpen: (v: boolean) => void;
  setIsNotifOpen: (v: boolean) => void;
  setIsManifestOpen: (v: boolean) => void;
  setIsPenTestOpen: (v: boolean) => void;
  setIsBadgeOpen: (v: boolean) => void;
  setIsKbOpen: (v: boolean) => void;
}

export const GateStatusBanner: React.FC<GateStatusBannerProps> = ({
  project,
  criticals,
  highs,
  uiCliches,
  onTriggerScan,
  setIsRuleConfigOpen,
  setIsExecutiveBriefingOpen,
  isMoreToolsOpen,
  setIsMoreToolsOpen,
  setIsCompareOpen,
  setIsNotifOpen,
  setIsManifestOpen,
  setIsPenTestOpen,
  setIsBadgeOpen,
  setIsKbOpen,
}) => {
  const moreToolsRef = useRef<HTMLDivElement>(null);

  return (
    <div
      className={`bg-[#141414] border rounded-xl p-6 sm:p-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 ${
        project.gateStatus === 'FAILED' ? 'border-red-500/30' : 'border-white/10'
      }`}
    >
      <div className="flex items-center gap-5">
        <div
          className={`w-14 h-14 rounded-xl flex items-center justify-center border font-bold ${
            project.gateStatus === 'FAILED'
              ? 'bg-red-500/10 border-red-500/30 text-red-500'
              : 'bg-white/5 border-white/10 text-white'
          }`}
        >
          {project.gateStatus === 'FAILED' ? <AlertTriangle size={28} /> : <CheckCircle2 size={28} />}
        </div>

        <div>
          <div className="text-xs font-bold text-[#A1A1AA] font-mono tracking-widest uppercase">
            RELEASE GATE EVALUATION
          </div>
          <h1 className="text-2xl font-extrabold text-[#EDEDED] mt-1">
            {project.name} ·{' '}
            <span className={project.gateStatus === 'FAILED' ? 'text-red-400' : 'text-emerald-400'}>
              {project.gateStatus}
            </span>
          </h1>
          <p className="text-xs text-[#A1A1AA] mt-1">
            Readiness Score: <strong className="text-white font-mono">{project.readinessScore}/100</strong> ·{' '}
            {criticals.length} Criticals, {highs.length} Highs, {uiCliches.length} UI Clichés
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={onTriggerScan}
          className="btn btn-primary px-5 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg flex items-center gap-2 bg-white text-black hover:bg-neutral-200"
        >
          <Play size={13} fill="#0A0A0A" />
          <span>Re-Run Audit</span>
        </button>

        <button
          onClick={() => setIsRuleConfigOpen(true)}
          className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-1.5"
          title="Configure Rule Matrix"
        >
          <Sliders size={13} />
          <span className="hidden sm:inline">Rules</span>
        </button>

        <button
          onClick={() => generateAuditPdfReport(project)}
          className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-1.5"
          title="Export PDF Report"
        >
          <Download size={13} />
          <span className="hidden sm:inline">PDF</span>
        </button>

        <button
          onClick={() => setIsExecutiveBriefingOpen(true)}
          className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-1.5"
          title="Executive Briefing"
        >
          <Award size={13} />
          <span className="hidden sm:inline">Briefing</span>
        </button>

        <div className="relative" ref={moreToolsRef}>
          <button
            onClick={() => setIsMoreToolsOpen((prev) => !prev)}
            className="btn btn-secondary p-2.5 rounded-lg flex items-center justify-center text-[#A1A1AA] hover:text-white"
            title="More Audit Tools"
          >
            <MoreVertical size={15} />
          </button>

          {isMoreToolsOpen && (
            <div className="absolute right-0 top-full mt-2 w-56 bg-[#141414] border border-white/10 rounded-xl shadow-2xl p-1.5 z-40 flex flex-col gap-1 text-xs font-mono">
              <button
                onClick={() => {
                  setIsCompareOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
              >
                <GitCompare size={14} />
                <span>Compare Snapshots</span>
              </button>

              <button
                onClick={() => {
                  setIsNotifOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
              >
                <Bell size={14} />
                <span>Webhook Alerts</span>
              </button>

              <button
                onClick={() => {
                  setIsManifestOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
              >
                <Server size={14} />
                <span>Deploy Manifests</span>
              </button>

              <button
                onClick={() => {
                  setIsPenTestOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
              >
                <ShieldAlert size={14} />
                <span>PenTest Payloads</span>
              </button>

              <button
                onClick={() => {
                  setIsBadgeOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
              >
                <ShieldCheck size={14} />
                <span>Release Gate Shield</span>
              </button>

              <button
                onClick={() => {
                  setIsKbOpen(true);
                  setIsMoreToolsOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2 border-t border-white/10 pt-2"
              >
                <BookOpen size={14} />
                <span>Rule Knowledge Base</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
