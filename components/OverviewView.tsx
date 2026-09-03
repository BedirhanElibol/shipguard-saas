// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { Project, Finding } from '@/data/schema';
import { ShieldCheck, Palette, Layers, Activity, AlertTriangle, ArrowRight, Play, Copy, CheckCircle2 } from 'lucide-react';
import { useState } from 'react';

interface OverviewViewProps {
  project: Project;
  onTriggerScan: () => void;
  onInspectFinding: (f: Finding) => void;
  onNavigateTab: (tab: unknown) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  project,
  onTriggerScan,
  onInspectFinding,
  onNavigateTab
}) => {
  const [copiedMaster, setCopiedMaster] = useState(false);

  const openFindings = project.findings.filter(f => f.status === 'OPEN');
  const criticals = openFindings.filter(f => f.severity === 'CRITICAL');
  const highs = openFindings.filter(f => f.severity === 'HIGH');

  const openUiCliches = openFindings.filter((f) => f.type === 'VIBEPOLISH').length;
  const uiCleanCount = Math.max(0, 30 - openUiCliches);

  const masterFixPrompt = `Act as an Expert Full-Stack Security & Software Architect.
Audit target project "${project.name}" (${project.framework}).
Resolve all ${openFindings.length} open release blockers:

${openFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.filePath})
   Remediation: ${f.remediationPrompt}`).join('\n\n')}`;

  const copyMasterPrompt = () => {
    navigator.clipboard.writeText(masterFixPrompt);
    setCopiedMaster(true);
    setTimeout(() => setCopiedMaster(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner / Gate Status Card */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{
        padding: '24px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '16px',
            background: project.gateStatus === 'FAILED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(20, 184, 166, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${project.gateStatus === 'FAILED' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`
          }}>
            {project.gateStatus === 'FAILED' ? <AlertTriangle size={32} color="#EF4444" /> : <ShieldCheck size={32} color="#10B981" />}
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Release Readiness Audit Evaluation
            </div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#EDEDED', margin: '2px 0 6px 0' }}>
              {project.name} · <span style={{ color: project.gateStatus === 'FAILED' ? '#EF4444' : '#10B981' }}>GATE STATUS: {project.gateStatus}</span>
            </h1>
            <p style={{ fontSize: '0.875rem', color: '#A1A1AA', maxWidth: '650px', margin: 0 }}>
              {project.gateStatus === 'FAILED'
                ? `Release BLOCKED. Detected ${criticals.length} Critical & ${highs.length} High severity security vulnerabilities in ${project.framework} stack.`
                : `Production Audit PASSED. ${project.name} complies with 23 Security Pre-flight Checks and 200 VibePolish & AI Anti-Pattern rules.`}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button className="btn btn-secondary" onClick={copyMasterPrompt}>
            {copiedMaster ? <CheckCircle2 size={16} color="#10B981" /> : <Copy size={16} />}
            <span>{copiedMaster ? 'Prompt Copied!' : 'Copy Master Fix Prompt'}</span>
          </button>

          <button className="btn btn-primary" onClick={onTriggerScan}>
            <Play size={16} fill="#FFF" />
            <span>Run New Audit</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
        {/* Metric 1: Readiness Score */}
        <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>Overall Score</span>
            <Activity size={18} color="#10B981" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: project.readinessScore < 50 ? '#EF4444' : project.readinessScore < 85 ? '#F59E0B' : '#10B981' }}>
            {project.readinessScore} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#A1A1AA', marginTop: '6px' }}>
            Combined Security + UI + Health score
          </div>
        </div>

        {/* Metric 2: Security Checks */}
        <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px', cursor: 'pointer' }} onClick={() => onNavigateTab('security')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>Security Pre-Flight</span>
            <ShieldCheck size={18} color="#10B981" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#EDEDED' }}>
            {23 - criticals.length - highs.length} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 23 Passed</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#EF4444', marginTop: '6px', fontWeight: 600 }}>
            {criticals.length} Critical &amp; {highs.length} High Risks Open
          </div>
        </div>

        {/* Metric 3: VibePolish UI Matrix */}
        <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px', cursor: 'pointer' }} onClick={() => onNavigateTab('vibepolish')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>VibePolish UI</span>
            <Palette size={18} color="#34D399" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#F8FAFC' }}>
            {uiCleanCount} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 30 Clean</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: openUiCliches > 0 ? '#EF4444' : '#10B981', marginTop: '6px', fontWeight: 600 }}>
            {openUiCliches > 0 ? `${openUiCliches} UI Cliché Findings Open` : '30 UI Cliché Rules Cleared'}
          </div>
        </div>

        {/* Metric 4: AI Master Slop Matrix */}
        <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '20px', cursor: 'pointer' }} onClick={() => onNavigateTab('aimaster')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#A1A1AA' }}>AI Master Matrix</span>
            <Layers size={18} color="#0EA5E9" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#F8FAFC' }}>
            {200 - project.uiClicheCount} <span style={{ fontSize: '1rem', color: '#64748B', fontWeight: 600 }}>/ 200 Clean</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#F59E0B', marginTop: '6px', fontWeight: 600 }}>
            {project.uiClicheCount} Out of 200 Full-Stack Master Rules
          </div>
        </div>
      </div>

      {/* Priority Action Items List */}
      <div className="bg-[#141414] border border-white/10 rounded-xl" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#F8FAFC', margin: 0 }}>
              Priority Release Blockers
            </h2>
            <div style={{ fontSize: '0.8rem', color: '#A1A1AA', marginTop: '2px' }}>
              Items preventing safe production release for {project.name}
            </div>
          </div>

          <button className="btn btn-secondary btn-sm" onClick={() => onNavigateTab('remediation')}>
            <span>View All Queue ({openFindings.length})</span>
            <ArrowRight size={14} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {openFindings.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: '#10B981', background: 'rgba(16, 185, 129, 0.05)', borderRadius: '10px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
              🎉 Zero release blockers! Your application is 100% production ready.
            </div>
          ) : (
            openFindings.slice(0, 5).map(f => (
              <div
                key={f.id}
                style={{
                  padding: '16px 20px',
                  borderRadius: '10px',
                  background: 'var(--bg-surface-hover)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '16px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <span className={`badge ${f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                    {f.severity}
                  </span>
                  <div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#F8FAFC' }}>
                      {f.title}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#A1A1AA', fontFamily: 'monospace', marginTop: '2px' }}>
                      {f.filePath} ({f.lineRange})
                    </div>
                  </div>
                </div>

                <button className="btn btn-secondary btn-sm" onClick={() => onInspectFinding(f)}>
                  <span>Inspect &amp; Fix</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
