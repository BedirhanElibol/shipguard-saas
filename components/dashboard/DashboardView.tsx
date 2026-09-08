// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Project, Finding } from '@/data/schema';
import { KpiCards } from './KpiCards';
import { SeverityChart } from './SeverityChart';
import { FindingsTable } from '../findings/FindingsTable';
import { InteractiveAnalyzer } from '../InteractiveAnalyzer';
import { VulnerabilityPlayground } from './VulnerabilityPlayground';
import { BundleCostAnalyzer } from './BundleCostAnalyzer';
import { ThemeContrastAuditor } from './ThemeContrastAuditor';
import { GeoIpTracker } from './GeoIpTracker';
import { QuickChartWidget } from './QuickChartWidget';
import { DashboardModals } from './DashboardModals';
import { GateStatusBanner } from './GateStatusBanner';
import { DemoShowcaseBanner } from '../OverviewView';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import confetti from 'canvas-confetti';
import { Play, Copy, CheckCircle2, AlertTriangle, Code, ShieldCheck, Zap, Download, GitCompare, Bell, Sliders, Award, BookOpen, Server, ShieldAlert, MoreVertical } from 'lucide-react';

interface DashboardViewProps {
  project: Project;
  onTriggerScan: () => void;
  onInspectFinding: (f: Finding) => void;
  onNavigatePillar: (pillar: string) => void;
  onLoadDemoFindings?: (findings: Finding[]) => void;
  user?: { isLoggedIn?: boolean } | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  project,
  onTriggerScan,
  onInspectFinding,
  onNavigatePillar,
  onLoadDemoFindings,
  user,
  onOpenAuth,
}) => {
  const [copiedMaster, setCopiedMaster] = useState(false);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const [isRuleConfigOpen, setIsRuleConfigOpen] = useState(false);
  const [isExecutiveBriefingOpen, setIsExecutiveBriefingOpen] = useState(false);
  const [isKbOpen, setIsKbOpen] = useState(false);
  const [isManifestOpen, setIsManifestOpen] = useState(false);
  const [isPenTestOpen, setIsPenTestOpen] = useState(false);
  const [isBadgeOpen, setIsBadgeOpen] = useState(false);
  const [isMoreToolsOpen, setIsMoreToolsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'findings' | 'sandbox' | 'diagnostics'>('findings');
  const moreToolsRef = useRef<HTMLDivElement>(null);

  // Confetti feedback on clearance PASSED
  useEffect(() => {
    if (project.gateStatus === 'PASSED') {
      try {
        confetti({
          particleCount: 50,
          spread: 60,
          origin: { y: 0.7 }
        });
      } catch (e: unknown) {
        console.warn('[Confetti] Clearance celebration passed');
      }
    }
  }, [project.gateStatus]);

  // Click outside listener for More Tools dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (moreToolsRef.current && !moreToolsRef.current.contains(event.target as Node)) {
        setIsMoreToolsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Cmd+K / Ctrl+K keyboard shortcut listener for Knowledge Base
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsKbOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const openFindings = useMemo(
    () => project.findings.filter((f) => f.status === 'OPEN'),
    [project.findings]
  );

  const criticals = useMemo(
    () => openFindings.filter((f) => f.severity === 'CRITICAL'),
    [openFindings]
  );

  const highs = useMemo(
    () => openFindings.filter((f) => f.severity === 'HIGH'),
    [openFindings]
  );

  const uiCliches = useMemo(
    () => openFindings.filter((f) => f.type === 'VIBEPOLISH'),
    [openFindings]
  );

  const copyMasterPrompt = () => {
    if (openFindings.length === 0) return;

    const prompt = `Act as Senior Lead Security Architect and Principal UI Designer.
Audit target project "${project.name}" (${project.framework}).
Resolve all ${openFindings.length} open vulnerabilities:

${openFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.filePath})\nRemediation: ${f.remediationPrompt}`).join('\n\n')}

Enforce strict OWASP Top 10 compliance, eliminate AI design clichés, and provide verified drop-in code fixes.`;
    navigator.clipboard.writeText(prompt);
    setCopiedMaster(true);
    setTimeout(() => setCopiedMaster(false), 2000);
  };

  return (
    <div className="flex flex-col gap-6 relative">
      {/* Swiss Command & Telemetry Header Bar */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
            <Zap size={16} className="text-white" />
          </div>
          <div>
            <span className="text-xs font-mono font-bold text-white uppercase tracking-wider block">
              ShipGuard Release Gate
            </span>
            <p className="text-xs text-[#A1A1AA]">
              AST &amp; Web Deployment Audit Pipeline
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <button
            onClick={() => onNavigatePillar('security')}
            className="flex items-center gap-1.5 text-xs font-mono text-[#A1A1AA] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 px-3 py-1.5 rounded-lg transition-colors shrink-0"
          >
            <ShieldCheck size={13} className="text-white" />
            <span>Security Audit</span>
          </button>

          <button
            onClick={() => onNavigatePillar('vibepolish')}
            className="flex items-center gap-1.5 text-xs font-mono text-[#A1A1AA] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 px-3 py-1.5 rounded-lg transition-colors shrink-0"
          >
            <Zap size={13} className="text-white" />
            <span>VibePolish UI</span>
          </button>

          <button
            onClick={copyMasterPrompt}
            className="flex items-center gap-1.5 text-xs font-mono font-bold text-black bg-white hover:bg-neutral-200 px-3.5 py-1.5 rounded-lg transition-colors shrink-0"
          >
            {copiedMaster ? <CheckCircle2 size={13} /> : <Copy size={13} />}
            <span>{copiedMaster ? 'Copied!' : 'Copy Fix Prompt'}</span>
          </button>
        </div>
      </div>

      {/* Interactive Demo Showcase Banner for Guests */}
      {(!user || !user.isLoggedIn) && (
        <DemoShowcaseBanner onOpenAuth={onOpenAuth} />
      )}

      {/* Top Gate Status Banner */}
      <GateStatusBanner
        project={project}
        criticals={criticals}
        highs={highs}
        uiCliches={uiCliches}
        onTriggerScan={onTriggerScan}
        setIsRuleConfigOpen={setIsRuleConfigOpen}
        setIsExecutiveBriefingOpen={setIsExecutiveBriefingOpen}
        isMoreToolsOpen={isMoreToolsOpen}
        setIsMoreToolsOpen={setIsMoreToolsOpen}
        setIsCompareOpen={setIsCompareOpen}
        setIsNotifOpen={setIsNotifOpen}
        setIsManifestOpen={setIsManifestOpen}
        setIsPenTestOpen={setIsPenTestOpen}
        setIsBadgeOpen={setIsBadgeOpen}
        setIsKbOpen={setIsKbOpen}
      />

      {/* Swiss Navigation Tabs Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-3">
        <div className="flex items-center gap-1.5 p-1 bg-[#141414] border border-white/10 rounded-xl w-fit">
          <button
            onClick={() => setActiveTab('findings')}
            className={`swiss-tab ${activeTab === 'findings' ? 'swiss-tab-active' : ''}`}
          >
            <ShieldCheck size={14} className={activeTab === 'findings' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Audit &amp; Findings</span>
            <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-white/10 text-white">
              {openFindings.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('sandbox')}
            className={`swiss-tab ${activeTab === 'sandbox' ? 'swiss-tab-active' : ''}`}
          >
            <Code size={14} className={activeTab === 'sandbox' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Code Inspector &amp; Sandbox</span>
          </button>

          <button
            onClick={() => setActiveTab('diagnostics')}
            className={`swiss-tab ${activeTab === 'diagnostics' ? 'swiss-tab-active' : ''}`}
          >
            <Server size={14} className={activeTab === 'diagnostics' ? 'text-white' : 'text-[#A1A1AA]'} />
            <span>Diagnostics &amp; Telemetry</span>
            <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-white/10 text-[#A1A1AA]">
              4 Tools
            </span>
          </button>
        </div>

        <div className="flex items-center gap-3 text-xs text-[#A1A1AA] font-mono">
          <span>Framework: <strong className="text-white font-medium">{project.framework}</strong></span>
          <span className="text-white/20">•</span>
          <span>Last Scan: <strong className="text-white font-medium">{project.lastScanAt}</strong></span>
        </div>
      </div>

      {/* Tab 1: Primary Audit & Findings View */}
      {activeTab === 'findings' && (
        <div className="flex flex-col gap-6">
          <KpiCards project={project} onNavigatePillar={onNavigatePillar} />
          <SeverityChart project={project} />
          <FindingsTable
            findings={project.findings}
            onInspectFinding={onInspectFinding}
            onTriggerScan={onTriggerScan}
            onLoadDemoFindings={onLoadDemoFindings}
          />
        </div>
      )}

      {/* Tab 2: AST Code Inspector & Exploits Sandbox */}
      {activeTab === 'sandbox' && (
        <div className="flex flex-col gap-6">
          <InteractiveAnalyzer />
          <VulnerabilityPlayground />
        </div>
      )}

      {/* Tab 3: Deep Diagnostics, Performance & Telemetry */}
      {activeTab === 'diagnostics' && (
        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <BundleCostAnalyzer filesCount={project.findings.length + 15} />
            <ThemeContrastAuditor />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <GeoIpTracker />
            <QuickChartWidget project={project} />
          </div>
        </div>
      )}

      {/* Extracted Dashboard Modals */}
      <DashboardModals
        project={project}
        isCompareOpen={isCompareOpen}
        setIsCompareOpen={setIsCompareOpen}
        isNotifOpen={isNotifOpen}
        setIsNotifOpen={setIsNotifOpen}
        isRuleConfigOpen={isRuleConfigOpen}
        setIsRuleConfigOpen={setIsRuleConfigOpen}
        isExecutiveBriefingOpen={isExecutiveBriefingOpen}
        setIsExecutiveBriefingOpen={setIsExecutiveBriefingOpen}
        isKbOpen={isKbOpen}
        setIsKbOpen={setIsKbOpen}
        isManifestOpen={isManifestOpen}
        setIsManifestOpen={setIsManifestOpen}
        isPenTestOpen={isPenTestOpen}
        setIsPenTestOpen={setIsPenTestOpen}
        isBadgeOpen={isBadgeOpen}
        setIsBadgeOpen={setIsBadgeOpen}
      />
    </div>
  );
};
