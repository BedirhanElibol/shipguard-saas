// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Project } from '@/data/schema';
import { FolderGit2, Plus, ArrowRight, Play, ExternalLink, ShieldCheck, Trash2, Zap } from 'lucide-react';
import { NewProjectModal } from '@/components/projects/NewProjectModal';

interface ProjectsViewProps {
  projects: Project[];
  onSelectProject: (p: Project) => void;
  onAddNewProject: (p: Project) => void;
  onTriggerScan: () => void;
  onDeleteProject?: (id: string) => void;
}

export const ProjectsView: React.FC<ProjectsViewProps> = ({
  projects,
  onSelectProject,
  onAddNewProject,
  onTriggerScan,
  onDeleteProject
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-[#141414] p-6 sm:p-8 shadow-lg">
        <div className="relative z-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-white/5 border border-white/10 text-white shadow-lg">
                <FolderGit2 size={22} />
              </div>
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                Connected AI Applications
              </h1>
            </div>
            <p className="text-sm text-[#A1A1AA] max-w-2xl leading-relaxed">
              Connect AI-generated repositories (Cursor, Lovable, Bolt, v0, Replit) or Vercel preview URLs for automated production release gate audits.
            </p>
          </div>

          <button
            className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm bg-white text-black hover:bg-neutral-200 shadow-lg transition-all duration-200 shrink-0"
            onClick={() => setIsModalOpen(true)}
          >
            <Plus size={18} strokeWidth={2.5} />
            <span>Connect New AI App</span>
          </button>
        </div>
      </div>

      {/* Quick Target Presets Bar */}
      <div className="rounded-xl border border-white/10 bg-[#0E0E16]/80 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-white tracking-wider uppercase">
          <Zap size={14} />
          <span>Quick Target Presets:</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: `proj-preset-newday`,
                name: 'newday (Next.js 15 Release Gate)',
                repoUrl: 'local',
                framework: 'Next.js 15',
                providers: ['Supabase', 'Vercel', 'Tailwind v4'],
                lastScanAt: 'Ready for Audit',
                readinessScore: 100,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                uiClicheCount: 0,
                findings: []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>newday (Self Audit)</span>
          </button>

          <button
            type="button"
            onClick={() => {
              const p: Project = {
                id: `proj-preset-carvis`,
                name: 'Carvis-App (Mobile + Capacitor)',
                repoUrl: 'https://github.com/user/example-app',
                framework: 'React + Capacitor',
                providers: ['PostgreSQL', 'Vercel', 'PayTR'],
                lastScanAt: 'Just now',
                readinessScore: 100,
                gateStatus: 'PASSED',
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                uiClicheCount: 0,
                findings: []
              };
              onAddNewProject(p);
              onSelectProject(p);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/15 text-white transition-colors"
          >
            <span>Mobile App Template</span>
          </button>
        </div>
      </div>

      {/* Projects Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {projects.length === 0 ? (
          <div className="col-span-full py-16 px-6 text-center rounded-2xl border border-dashed border-white/15 bg-[#0D0D14] flex flex-col items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-white">
              <FolderGit2 size={24} />
            </div>
            <div>
              <h3 className="text-base font-bold text-white mb-1">No AI Applications Connected Yet</h3>
              <p className="text-xs text-[#A1A1AA] max-w-md">
                Connect your GitHub repository or preview URL to run automated OWASP security and VibePolish audits.
              </p>
            </div>
            <button
              onClick={() => setIsModalOpen(true)}
              className="btn btn-primary px-4 py-2 text-xs font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200"
            >
              Connect First App
            </button>
          </div>
        ) : (
          projects.map((p) => {
            const isFailed = p.gateStatus === 'FAILED';
            const isWarning = p.gateStatus === 'WARNING';

            return (
              <div
                key={p.id}
                className="group relative flex flex-col justify-between rounded-2xl border border-white/10 bg-[#0D0D14] hover:bg-[#11111B] p-5 transition-all duration-200 hover:border-white/20 hover:shadow-lg min-h-[14rem]"
              >
                <div>
                  {/* Top Status & Framework Bar */}
                  <div className="flex items-center justify-between mb-4">
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-bold tracking-wide border ${
                        isFailed
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                          : isWarning
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                          : 'bg-white/5 text-white border-white/10'
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${isFailed ? 'bg-rose-400' : isWarning ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                      <span>GATE: {p.gateStatus}</span>
                    </span>

                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md text-[11px] font-mono font-medium bg-white/5 border border-white/10 text-[#A1A1AA]">
                        {p.framework}
                      </span>
                      {onDeleteProject && (
                        <button
                          onClick={() => {
                            if (confirm(`Remove "${p.name}" from saved projects?`)) {
                              onDeleteProject(p.id);
                            }
                          }}
                          className="p-1 rounded-lg text-[#A1A1AA] hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                          title="Delete Project"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Project Name & Repo Link */}
                  <h2 className="text-base font-extrabold text-white truncate mb-1" title={p.name}>
                    {p.name}
                  </h2>
                  <div className="flex items-center gap-1.5 text-xs font-mono text-[#A1A1AA] truncate mb-4">
                    <ExternalLink size={12} className="shrink-0 text-white/50" />
                    <span className="truncate">{p.repoUrl}</span>
                  </div>

                  {/* Clean direct score indicator without count-up animation */}
                  <div className="flex items-center justify-between py-2 border-t border-white/10 text-xs font-mono">
                    <span className="text-[#A1A1AA]">Readiness Score:</span>
                    <span className={`font-extrabold ${isFailed ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {p.readinessScore}%
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs font-mono text-[#A1A1AA]">
                    <span>Open Findings:</span>
                    <span className="font-bold text-white">{p.findings.length}</span>
                  </div>
                </div>

                {/* Footer Action Buttons */}
                <div className="flex items-center gap-2 pt-4 border-t border-white/10 mt-4">
                  <button
                    onClick={() => onSelectProject(p)}
                    className="flex-1 py-2 rounded-lg text-xs font-mono font-bold bg-white/5 hover:bg-white/10 border border-white/10 text-white flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <span>View Findings</span>
                    <ArrowRight size={13} />
                  </button>

                  <button
                    onClick={() => {
                      onSelectProject(p);
                      onTriggerScan();
                    }}
                    className="px-3 py-2 rounded-lg text-xs font-mono font-bold bg-white text-black hover:bg-neutral-200 flex items-center justify-center gap-1 transition-colors"
                    title="Run Release Gate Audit"
                  >
                    <Play size={12} fill="#0A0A0A" />
                    <span>Audit</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      <NewProjectModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onAddNewProject={onAddNewProject}
      />
    </div>
  );
};
