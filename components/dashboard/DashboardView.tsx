'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import { Project, Finding } from '@/data/schema';
import { KpiCards } from './KpiCards';
import { SeverityChart } from './SeverityChart';
import { FindingsTable } from '../findings/FindingsTable';
import { InteractiveAnalyzer } from '../InteractiveAnalyzer';
import { VulnerabilityPlayground } from './VulnerabilityPlayground';
import { BundleCostAnalyzer } from './BundleCostAnalyzer';
import { ScaLicenseRiskCard } from './ScaLicenseRiskCard';
import { QuickChartWidget } from './QuickChartWidget';
import { DashboardModals, ActiveModalType } from './DashboardModals';
import { GateStatusBanner } from './GateStatusBanner';
import { DemoShowcaseBanner } from '../OverviewView';
import { generateAuditPdfReport } from '@/lib/pdf-exporter';
import confetti from 'canvas-confetti';
import { ShieldCheck, Code, Server } from 'lucide-react';
import { ConnectTargetModal } from '../layout/ConnectTargetModal';
import { ClipboardToastBadge, useClipboardToast } from '../ui/Toast';
import { ComponentErrorBoundary } from '../common/ComponentErrorBoundary';

interface DashboardViewProps {
  project: Project;
  onTriggerScan: (projectOverride?: Project) => void;
  onInspectFinding: (f: Finding) => void;
  onNavigatePillar: (pillar: string) => void;
  onLoadDemoFindings?: (findings: Finding[]) => void;
  user?: { isLoggedIn?: boolean } | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onAddNewProject?: (p: Project) => void;
  onSelectProject?: (p: Project) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  project,
  onTriggerScan,
  onInspectFinding,
  onNavigatePillar,
  onLoadDemoFindings,
  user,
  onOpenAuth,
  onAddNewProject,
  onSelectProject,
}) => {
  const [copiedMaster, setCopiedMaster] = useState(false);
  const [isConnectTargetOpen, setIsConnectTargetOpen] = useState(false);
  const [activeModal, setActiveModal] = useState<ActiveModalType>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'sandbox' | 'diagnostics'>('findings');
  const {
    showToast,
    isVisible: isToastVisible,
    message: toastMessage,
    badge: toastBadge,
    hideToast,
  } = useClipboardToast();

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

  // Cmd+K / Ctrl+K keyboard shortcut listener for Knowledge Base
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setActiveModal((prev: ActiveModalType) => (prev === 'kb' ? null : 'kb'));
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
    showToast('AI prompt copied to clipboard', '[COPIED]');
    setTimeout(() => setCopiedMaster(false), 2000);
  };

  return (
    <div className="flex flex-col gap-6 relative">
      {/* Interactive Demo Showcase Banner for Guests */}
      {(!user || !user.isLoggedIn) && (
        <DemoShowcaseBanner
          onOpenAuth={onOpenAuth}
          onFocusQuickAudit={() => setIsConnectTargetOpen(true)}
        />
      )}

      {/* Top Gate Status Banner */}
      <ComponentErrorBoundary componentName="GateStatusBanner" resetKeys={[project?.id, project?.gateStatus]}>
        <GateStatusBanner
          project={project}
          criticals={criticals}
          highs={highs}
          uiCliches={uiCliches}
          onTriggerScan={onTriggerScan}
          onOpenConnectTarget={() => setIsConnectTargetOpen(true)}
          onOpenModal={(type) => setActiveModal(type)}
        />
      </ComponentErrorBoundary>

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
          <ComponentErrorBoundary componentName="FindingsTable" resetKeys={[project?.id, project?.findings?.length]}>
            <FindingsTable
              findings={project.findings}
              onInspectFinding={onInspectFinding}
              onTriggerScan={onTriggerScan}
              onLoadDemoFindings={onLoadDemoFindings}
              onCopyPrompt={copyMasterPrompt}
              copiedPrompt={copiedMaster}
            />
          </ComponentErrorBoundary>
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
            <ComponentErrorBoundary componentName="ScaLicenseRiskCard" resetKeys={[project?.id]}>
              <ScaLicenseRiskCard />
            </ComponentErrorBoundary>
          </div>
          <QuickChartWidget project={project} />
        </div>
      )}

      {/* Extracted Dashboard Modals */}
      <DashboardModals
        project={project}
        activeModal={activeModal}
        onClose={() => setActiveModal(null)}
      />

      <ClipboardToastBadge
        isVisible={isToastVisible}
        message={toastMessage}
        badge={toastBadge}
        onDismiss={hideToast}
      />

      <ConnectTargetModal
        isOpen={isConnectTargetOpen}
        onClose={() => setIsConnectTargetOpen(false)}
        onAddNewProject={onAddNewProject}
        onSelectProject={(p) => {
          onSelectProject?.(p);
          setIsConnectTargetOpen(false);
        }}
        onTriggerScan={(p) => {
          onTriggerScan(p);
          setIsConnectTargetOpen(false);
        }}
      />
    </div>
  );
};
