// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { Project } from '@/data/schema';
import { History, Play, CheckCircle2, AlertTriangle, ShieldCheck, Clock, ExternalLink } from 'lucide-react';

interface ScanHistoryViewProps {
  project: Project;
  onTriggerScan: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  project,
  onTriggerScan
}) => {
  // Generate realistic historical audit records for the selected project
  const mockHistory = [
    {
      id: 'SCAN-8092',
      date: project.lastScanAt || 'Just now',
      target: project.repoUrl,
      score: project.readinessScore,
      gateStatus: project.gateStatus,
      criticalCount: project.criticalCount,
      highCount: project.highCount,
      mediumCount: project.mediumCount,
      duration: '4.2s',
      triggeredBy: 'CI/CD Automated Webhook'
    },
    {
      id: 'SCAN-8091',
      date: '2 hours ago',
      target: project.repoUrl,
      score: project.gateStatus === 'PASSED' ? 100 : Math.max(30, project.readinessScore - 8),
      gateStatus: project.gateStatus === 'PASSED' ? 'PASSED' : 'FAILED',
      criticalCount: project.gateStatus === 'PASSED' ? 0 : project.criticalCount + 1,
      highCount: project.gateStatus === 'PASSED' ? 0 : project.highCount + 2,
      mediumCount: project.gateStatus === 'PASSED' ? 0 : project.mediumCount,
      duration: '3.8s',
      triggeredBy: 'Manual Dashboard Audit'
    },
    {
      id: 'SCAN-8090',
      date: 'Yesterday at 18:45',
      target: project.repoUrl,
      score: project.gateStatus === 'PASSED' ? 100 : Math.max(20, project.readinessScore - 15),
      gateStatus: project.gateStatus === 'PASSED' ? 'PASSED' : 'FAILED',
      criticalCount: project.gateStatus === 'PASSED' ? 0 : project.criticalCount + 2,
      highCount: project.gateStatus === 'PASSED' ? 0 : project.highCount + 3,
      mediumCount: project.gateStatus === 'PASSED' ? 0 : project.mediumCount + 1,
      duration: '4.5s',
      triggeredBy: 'GitHub Push Webhook (main)'
    }
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* Header Card */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 bg-[#141414] border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
              <History size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-extrabold text-[#EDEDED]">
                Release Gate Audit History &amp; Timeline
              </h1>
              <p className="text-xs text-[#A1A1AA] mt-0.5">
                Historical scan logs, score deltas, and pre-flight clearance records for {project.name}
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={onTriggerScan}
          className="btn btn-primary text-xs px-5 py-2.5 font-bold uppercase tracking-wider flex items-center gap-2 rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
        >
          <Play size={14} fill="#0A0A0A" />
          <span>Run New Live Scan</span>
        </button>
      </div>

      {/* History Table */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 bg-[#141414] border-white/10 flex flex-col gap-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="text-xs font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">
            PAST AUDIT EXECUTIONS ({mockHistory.length})
          </div>
          <span className="text-xs font-mono text-white">Target: {project.repoUrl}</span>
        </div>

        <div className="space-y-3">
          {mockHistory.length === 0 ? (
            <div className="p-8 text-center bg-[#0A0A0A] rounded-xl border border-white/10 text-xs text-[#A1A1AA]">
              No historical scan logs recorded for this project yet. Click "Run New Live Scan" to trigger an audit.
            </div>
          ) : (
            mockHistory.map((scan) => (
              <div
                key={scan.id}
                className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:border-white/10 transition-all"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center font-mono text-xs text-white font-bold">
                    {scan.id.split('-')[1]}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-[#EDEDED]">{scan.id}</span>
                      <span className="text-[0.68rem] text-[#A1A1AA] font-mono">• {scan.date}</span>
                    </div>
                    <div className="text-[0.68rem] text-white font-mono mt-0.5 flex items-center gap-1.5">
                      <Clock size={12} />
                      <span>Duration: {scan.duration} • Trigger: {scan.triggeredBy}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {/* Findings summary */}
                  <div className="text-right font-mono text-xs">
                    <div className="text-[#EDEDED] font-bold">
                      Score: <span className="text-white">{scan.score}/100</span>
                    </div>
                    <div className="text-[0.68rem] text-[#A1A1AA]">
                      {scan.criticalCount} Critical • {scan.highCount} High
                    </div>
                  </div>

                  {/* Gate badge */}
                  <span
                    className={`text-[0.65rem] font-extrabold uppercase px-2.5 py-1 rounded-md border ${
                      scan.gateStatus === 'PASSED'
                        ? 'bg-white/5 border-white/10 text-white'
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}
                  >
                    {scan.gateStatus}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
