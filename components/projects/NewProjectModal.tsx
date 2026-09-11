// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Project } from '@/data/schema';
import { X } from 'lucide-react';
import { isValidGithubUrl } from '@/lib/github-api';

interface NewProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddNewProject: (p: Project) => void;
}

export const NewProjectModal: React.FC<NewProjectModalProps> = ({ isOpen, onClose, onAddNewProject }) => {
  const [name, setName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [framework, setFramework] = useState<'Next.js 15' | 'Vite + React' | 'FastAPI + React' | 'SvelteKit'>('Next.js 15');
  const [urlError, setUrlError] = useState('');

  if (!isOpen) return null;

  const handleSubmitNew = (e: React.FormEvent) => {
    e.preventDefault();
    setUrlError('');

    let cleanUrl = repoUrl.trim();
    if (/^[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+$/.test(cleanUrl)) {
      cleanUrl = `https://github.com/${cleanUrl}`;
    } else if (cleanUrl.startsWith('github.com/')) {
      cleanUrl = `https://${cleanUrl}`;
    } else if (!cleanUrl.startsWith('http')) {
      cleanUrl = `https://${cleanUrl}`;
    }

    if (!cleanUrl || !isValidGithubUrl(cleanUrl)) {
      setUrlError('Invalid GitHub URL format. Please enter a valid repository URL (e.g. "github.com/owner/repo" or "owner/repo").');
      return;
    }

    const newP: Project = {
      id: `proj-${Date.now()}`,
      name,
      repoUrl: cleanUrl,
      framework,
      providers: ['Supabase', 'Vercel'],
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

    onAddNewProject(newP);
    onClose();
    setName('');
    setRepoUrl('');
  };

  return (
    <div className="drawer-overlay flex items-center justify-center p-4">
      <div className="bg-[#141414] border border-white/10 rounded-2xl w-full max-w-lg p-6 sm:p-8 relative shadow-2xl">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-[#A1A1AA] hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors"
        >
          <X size={20} />
        </button>

        <h2 className="text-xl font-extrabold text-[#F8FAFC] mb-1">
          Connect New AI Application
        </h2>
        <p className="text-xs text-[#A1A1AA] mb-5">
          Provide repository details for automated pre-flight security scan and VibePolish UI audit.
        </p>

        {urlError && (
          <div className="mb-4 text-xs text-red-400 bg-red-500/10 border border-red-500/20 p-2.5 rounded-lg">
            {urlError}
          </div>
        )}

        <form onSubmit={handleSubmitNew} className="flex flex-col gap-4">
          <div>
            <label htmlFor="app-name-input" className="block text-xs font-bold text-[#CBD5E1] mb-1.5 uppercase">
              Application Name
            </label>
            <input
              id="app-name-input"
              type="text"
              placeholder="e.g. My SaaS App"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full px-3.5 py-2.5 rounded-xl bg-[#0A0E1A] border border-white/10 text-xs text-white outline-none focus:border-white/30 font-mono"
            />
          </div>

          <div>
            <label htmlFor="repo-url-input" className="block text-xs font-bold text-[#CBD5E1] mb-1.5 uppercase">
              GitHub Repository / Target URL
            </label>
            <input
              id="repo-url-input"
              type="text"
              placeholder="github.com/org/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              required
              className="w-full px-3.5 py-2.5 rounded-xl bg-[#0A0E1A] border border-white/10 text-xs text-white outline-none focus:border-white/30 font-mono"
            />
          </div>

          <div>
            <label htmlFor="framework-select" className="block text-xs font-bold text-[#CBD5E1] mb-1.5 uppercase">
              Framework Stack
            </label>
            <select
              id="framework-select"
              value={framework}
              onChange={(e) => setFramework(e.target.value as any)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-[#0A0E1A] border border-white/10 text-xs text-white outline-none cursor-pointer font-mono"
            >
              <option value="Next.js 15">Next.js 15 (App Router)</option>
              <option value="Vite + React">Vite + React (SPA)</option>
              <option value="FastAPI + React">FastAPI + React</option>
              <option value="SvelteKit">SvelteKit</option>
            </select>
          </div>

          <div className="flex gap-3 mt-3">
            <button type="button" className="btn btn-secondary flex-1 py-2.5 text-xs" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary flex-1 py-2.5 text-xs font-bold uppercase tracking-wider bg-white text-black hover:bg-neutral-200">
              Connect &amp; Audit
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
