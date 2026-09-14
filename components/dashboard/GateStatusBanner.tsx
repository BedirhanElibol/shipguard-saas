'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Project, Finding } from '@/data/schema';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import {
  Play,
  AlertTriangle,
  CheckCircle2,
  Sliders,
  Download,
  Award,
  GitCompare,
  Bell,
  Server,
  ShieldAlert,
  ShieldCheck,
  BookOpen,
  Code,
  Table,
  FileText,
  ChevronDown
} from 'lucide-react';
import { exportFindingsToCsv, exportScorecardToJson } from '@/lib/export-utils';

interface GateStatusBannerProps {
  project: Project;
  criticals: Finding[];
  highs: Finding[];
  uiCliches: Finding[];
  onTriggerScan: () => void;
  setIsRuleConfigOpen: (v: boolean) => void;
  setIsExecutiveBriefingOpen: (v: boolean) => void;
  isMoreToolsOpen?: boolean;
  setIsMoreToolsOpen?: React.Dispatch<React.SetStateAction<boolean>>;
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
  setIsCompareOpen,
  setIsNotifOpen,
  setIsManifestOpen,
  setIsPenTestOpen,
  setIsBadgeOpen,
  setIsKbOpen,
}) => {
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);
  const [isToolsMenuOpen, setIsToolsMenuOpen] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);
  const toolsMenuRef = useRef<HTMLDivElement>(null);

  // Click outside and Escape key listener for both dropdowns
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (exportMenuRef.current && !exportMenuRef.current.contains(target)) {
        setIsExportMenuOpen(false);
      }
      if (toolsMenuRef.current && !toolsMenuRef.current.contains(target)) {
        setIsToolsMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsExportMenuOpen(false);
        setIsToolsMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  return (
    <div
      className={`bg-[#141414] border rounded-xl p-4 sm:p-6 lg:p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5 sm:gap-6 ${
        project.gateStatus === 'FAILED' ? 'border-red-500/30' : 'border-white/10'
      }`}
    >
      {/* Left: Clearance Status & Metric Scorecard */}
      <div className="flex items-start sm:items-center gap-3.5 sm:gap-5 min-w-0">
        <div
          className={`w-12 h-12 sm:w-14 sm:h-14 rounded-xl flex items-center justify-center border font-bold shrink-0 ${
            project.gateStatus === 'FAILED'
              ? 'bg-red-500/10 border-red-500/30 text-red-500'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
          }`}
        >
          {project.gateStatus === 'FAILED' ? (
            <AlertTriangle size={24} className="sm:w-7 sm:h-7" />
          ) : (
            <CheckCircle2 size={24} className="sm:w-7 sm:h-7" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] sm:text-xs font-bold text-[#A1A1AA] font-mono tracking-widest uppercase">
              RELEASE GATE EVALUATION
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold ${
                project.gateStatus === 'FAILED'
                  ? 'bg-red-500/10 border border-red-500/30 text-red-400'
                  : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
              }`}
            >
              {project.gateStatus}
            </span>
          </div>

          <h1 className="text-lg sm:text-2xl font-extrabold text-[#EDEDED] mt-1 truncate">
            {project.name}
          </h1>

          <p className="text-[11px] sm:text-xs text-[#A1A1AA] mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              Readiness Score: <strong className="text-white font-mono">{project.readinessScore}/100</strong>
            </span>
            <span className="text-white/20">•</span>
            <span className={criticals.length > 0 ? 'text-red-400 font-bold' : 'text-[#A1A1AA]'}>
              {criticals.length} Critical
            </span>
            <span className="text-white/20">•</span>
            <span className={highs.length > 0 ? 'text-amber-400 font-bold' : 'text-[#A1A1AA]'}>
              {highs.length} High
            </span>
            <span className="text-white/20">•</span>
            <span className="text-[#A1A1AA]">
              {uiCliches.length} UI Clichés
            </span>
          </p>
        </div>
      </div>

      {/* Right: Consolidated, Clean Action Controls (3 Focused CTAs) */}
      <div className="flex flex-wrap items-center gap-2.5 sm:gap-3 w-full lg:w-auto">
        {/* Primary Action: Re-Run Audit */}
        <button
          onClick={onTriggerScan}
          className="btn btn-primary px-4 sm:px-5 py-2.5 text-xs font-bold uppercase tracking-wider rounded-lg flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 flex-1 sm:flex-initial shadow-md transition-all active:scale-95 cursor-pointer"
        >
          <Play size={13} fill="#0A0A0A" />
          <span>Re-Run Audit</span>
        </button>

        {/* Action 2: Export Report Dropdown (PDF, CSV, JSON) */}
        <div className="relative" ref={exportMenuRef}>
          <button
            onClick={() => {
              setIsExportMenuOpen((prev) => !prev);
              setIsToolsMenuOpen(false);
            }}
            className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-2 border-white/10 text-[#EDEDED] hover:bg-white/10 transition-colors cursor-pointer"
            aria-label="Export Release Reports"
          >
            <Download size={13} className="text-white" />
            <span>Export Report</span>
            <ChevronDown size={12} className={`text-[#A1A1AA] transition-transform duration-200 ${isExportMenuOpen ? 'rotate-180' : ''}`} />
          </button>

          {isExportMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-60 bg-[#141414] border border-white/10 rounded-xl shadow-2xl p-1.5 z-40 flex flex-col gap-1 text-xs font-mono animate-in fade-in duration-150">
              <button
                onClick={() => {
                  generateAuditPdfReport(project);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <FileText size={14} className="text-blue-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Executive PDF Report</span>
                  <span className="text-[10px] text-[#A1A1AA]">Formal stakeholder sign-off</span>
                </div>
              </button>

              <button
                onClick={() => {
                  exportFindingsToCsv(project.findings, project.name);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Table size={14} className="text-emerald-400" />
                <div className="flex flex-col">
                  <span className="font-bold">RFC 4180 CSV Export</span>
                  <span className="text-[10px] text-[#A1A1AA]">Import to Jira, Linear &amp; GitHub</span>
                </div>
              </button>

              <button
                onClick={() => {
                  exportScorecardToJson(project);
                  setIsExportMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer border-t border-white/5 pt-1.5"
              >
                <Code size={14} className="text-purple-400" />
                <div className="flex flex-col">
                  <span className="font-bold">JSON Scorecard Payload</span>
                  <span className="text-[10px] text-[#A1A1AA]">CI/CD automation artifact</span>
                </div>
              </button>
            </div>
          )}
        </div>

        {/* Action 3: Audit Tools & Governance Dropdown */}
        <div className="relative" ref={toolsMenuRef}>
          <button
            onClick={() => {
              setIsToolsMenuOpen((prev) => !prev);
              setIsExportMenuOpen(false);
            }}
            className="btn btn-secondary px-3.5 py-2.5 text-xs font-mono rounded-lg flex items-center gap-2 border-white/10 text-[#EDEDED] hover:bg-white/10 transition-colors cursor-pointer"
            aria-label="Audit Tools and Governance Settings"
          >
            <Sliders size={13} className="text-white" />
            <span>Audit Tools</span>
            <ChevronDown size={12} className={`text-[#A1A1AA] transition-transform duration-200 ${isToolsMenuOpen ? 'rotate-180' : ''}`} />
          </button>

          {isToolsMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-[#141414] border border-white/10 rounded-xl shadow-2xl p-1.5 z-40 flex flex-col gap-1 text-xs font-mono animate-in fade-in duration-150">
              <button
                onClick={() => {
                  setIsRuleConfigOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Sliders size={14} className="text-white" />
                <div className="flex flex-col">
                  <span className="font-bold">Rule Matrix Configurator</span>
                  <span className="text-[10px] text-[#A1A1AA]">Toggle security &amp; UI rule weights</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsExecutiveBriefingOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Award size={14} className="text-amber-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Executive Briefing</span>
                  <span className="text-[10px] text-[#A1A1AA]">High-level board-ready audit</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsCompareOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <GitCompare size={14} className="text-cyan-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Compare Snapshots</span>
                  <span className="text-[10px] text-[#A1A1AA]">Differential regression analysis</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsNotifOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Bell size={14} className="text-rose-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Webhook Alerts</span>
                  <span className="text-[10px] text-[#A1A1AA]">Slack &amp; Discord dispatch setup</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsManifestOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <Server size={14} className="text-blue-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Deployment Manifest</span>
                  <span className="text-[10px] text-[#A1A1AA]">Cryptographic release attestation</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsPenTestOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <ShieldAlert size={14} className="text-red-400" />
                <div className="flex flex-col">
                  <span className="font-bold">PenTest Payloads</span>
                  <span className="text-[10px] text-[#A1A1AA]">PoC exploit validation suite</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsBadgeOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer"
              >
                <ShieldCheck size={14} className="text-emerald-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Release Gate Badge</span>
                  <span className="text-[10px] text-[#A1A1AA]">Live SVG embed for README</span>
                </div>
              </button>

              <button
                onClick={() => {
                  setIsKbOpen(true);
                  setIsToolsMenuOpen(false);
                }}
                className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2.5 transition-colors cursor-pointer border-t border-white/10 pt-2"
              >
                <BookOpen size={14} className="text-neutral-400" />
                <div className="flex flex-col">
                  <span className="font-bold">Rule Knowledge Base</span>
                  <span className="text-[10px] text-[#A1A1AA]">Press Cmd+K anytime</span>
                </div>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
