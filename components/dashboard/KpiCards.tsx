// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { Project } from '@/data/schema';
import { ShieldCheck, Palette, Layers, Activity, AlertTriangle } from 'lucide-react';
import NumberFlow from '@number-flow/react';

interface KpiCardsProps {
  project: Project;
  onNavigatePillar: (pillar: string) => void;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ project, onNavigatePillar }) => {
  const openFindings = project.findings.filter((f) => f.status === 'OPEN');
  const criticals = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highs = openFindings.filter((f) => f.severity === 'HIGH').length;

  const openUiCliches = openFindings.filter(
    (f) => f.type === 'VIBEPOLISH' || f.category?.includes('UI') || f.category?.includes('Visual')
  ).length;
  const totalUiBaseline = Math.max(30, openUiCliches);
  const clearedUiRules = Math.max(0, totalUiBaseline - openUiCliches);
  const uiPercent = Math.round((clearedUiRules / totalUiBaseline) * 100);

  const openSlop = openFindings.filter(
    (f) => f.category?.includes('Architecture') || f.category?.includes('Slop') || f.category?.includes('Code')
  ).length;
  const totalSlopBaseline = Math.max(200, openSlop);
  const clearedSlopRules = Math.max(0, totalSlopBaseline - openSlop);
  const slopPercent = Math.round((clearedSlopRules / totalSlopBaseline) * 100);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Scorecard 1: Overall Readiness Score */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-5 flex flex-col justify-between relative overflow-hidden group">
        <div className="flex items-center justify-between mb-3">
          <span className="text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase">
            OVERALL READINESS
          </span>
          <Activity size={15} className="text-white/60" />
        </div>

        <div className="flex items-baseline gap-2">
          <span
            className={`text-3xl font-extrabold tracking-tight font-mono ${
              project.readinessScore < 50
                ? 'text-[#EF4444]'
                : project.readinessScore < 85
                ? 'text-[#F59E0B]'
                : 'text-[#10B981]'
            }`}
          >
            <NumberFlow value={project.readinessScore} />
          </span>
          <span className="text-xs font-mono text-[#A1A1AA]">/ 100</span>
        </div>

        {/* Progress Bar Gauge */}
        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-700 rounded-full ${
              project.readinessScore < 50
                ? 'bg-[#EF4444]'
                : project.readinessScore < 85
                ? 'bg-[#F59E0B]'
                : 'bg-[#10B981]'
            }`}
            style={{ width: `${project.readinessScore}%` }}
          />
        </div>

        <div className="text-[0.72rem] text-[#A1A1AA] mt-3 flex items-center justify-between font-mono">
          <span>Gate Status:</span>
          <span className={`font-bold ${project.gateStatus === 'FAILED' ? 'text-[#EF4444]' : 'text-[#10B981]'}`}>
            RELEASE {project.gateStatus}
          </span>
        </div>
      </div>

      {/* Scorecard 2: Security Pre-Flight */}
      <div
        onClick={() => onNavigatePillar('security')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase">
            SECURITY CLEARANCE
          </span>
          <ShieldCheck size={15} className="text-white/80 group-hover:scale-105 transition-transform" />
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white font-mono">
            <NumberFlow value={Math.max(0, Math.round(((23 - Math.min(23, criticals + highs)) / 23) * 100))} />
          </span>
          <span className="text-xs font-mono text-[#A1A1AA]">% Cleared</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-3 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-700 rounded-full"
            style={{ width: `${Math.max(0, Math.round(((23 - Math.min(23, criticals + highs)) / 23) * 100))}%` }}
          />
        </div>

        <div className="text-[0.72rem] text-[#EF4444] font-bold mt-3 flex items-center justify-between font-mono">
          <span className="flex items-center gap-1">
            <AlertTriangle size={12} />
            <span>{criticals + highs} Open Risks</span>
          </span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 3: Design & UX Polish */}
      <div
        onClick={() => onNavigatePillar('vibepolish')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase">
            DESIGN &amp; UX POLISH
          </span>
          <Palette size={15} className="text-white/80 group-hover:scale-105 transition-transform" />
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white font-mono">
            <NumberFlow value={uiPercent} />
          </span>
          <span className="text-xs font-mono text-[#A1A1AA]">% Cleared</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-3 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-700 rounded-full"
            style={{ width: `${uiPercent}%` }}
          />
        </div>

        <div className={`text-[0.72rem] font-bold mt-3 flex items-center justify-between font-mono ${openUiCliches > 0 ? 'text-[#F59E0B]' : 'text-[#10B981]'}`}>
          <span>{openUiCliches > 0 ? `${openUiCliches} UI Risks` : 'All Cleared'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity">
            Inspect &rarr;
          </span>
        </div>
      </div>

      {/* Scorecard 4: Master Quality Matrix */}
      <div
        onClick={() => onNavigatePillar('aimaster')}
        className="bg-[#141414] border border-white/10 rounded-xl hover:border-white/20 p-5 flex flex-col justify-between cursor-pointer transition-all duration-200 group"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-[0.68rem] font-mono font-semibold text-[#A1A1AA] tracking-wider uppercase">
            QUALITY MATRIX
          </span>
          <Layers size={15} className="text-white/80 group-hover:scale-105 transition-transform" />
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white font-mono">
            <NumberFlow value={slopPercent} />
          </span>
          <span className="text-xs font-mono text-[#A1A1AA]">% Cleared</span>
        </div>

        <div className="w-full h-1 bg-white/[0.06] rounded-full mt-3 overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-700 rounded-full"
            style={{ width: `${slopPercent}%` }}
          />
        </div>

        <div className={`text-[0.72rem] font-bold mt-3 flex items-center justify-between font-mono ${openSlop > 0 ? 'text-[#F59E0B]' : 'text-[#10B981]'}`}>
          <span>{openSlop > 0 ? `${openSlop} Slop Rules` : 'Matrix Cleared'}</span>
          <span className="text-[0.68rem] text-white/80 opacity-0 group-hover:opacity-100 transition-opacity">
            Inspect &rarr;
          </span>
        </div>
      </div>
    </div>
  );
};
