// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Project } from '@/data/schema';
import { Play, ArrowLeft, FolderGit2, LogOut, User, ChevronDown, Zap } from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';
import { sanitizeTargetUrl } from '@/lib/github-api';
import { ConnectTargetModal } from './ConnectTargetModal';

interface HeaderProps {
  projects: Project[];
  selectedProject: Project;
  onSelectProject: (p: Project) => void;
  onTriggerScan: () => void;
  onNavigateLanding?: () => void;
  onAddNewProject?: (p: Project) => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode: 'signin' | 'signup') => void;
  onSignOut?: () => void;
  onOpenCheckout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  selectedProject,
  onSelectProject,
  onTriggerScan,
  onNavigateLanding,
  onAddNewProject,
  user,
  onOpenAuth,
  onSignOut,
  onOpenCheckout
}) => {
  const [isGithubModalOpen, setIsGithubModalOpen] = useState<boolean>(false);
  const [activeTargetUrl, setActiveTargetUrl] = useState<string>(selectedProject.repoUrl);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState<boolean>(false);
  const userMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setActiveTargetUrl(selectedProject.repoUrl);
  }, [selectedProject]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
    };
    if (isUserMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isUserMenuOpen]);

  const handleTargetUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = sanitizeTargetUrl(activeTargetUrl);
    if (cleaned && cleaned !== selectedProject.repoUrl) {
      onSelectProject({
        ...selectedProject,
        repoUrl: cleaned,
        name: cleaned.replace(/^https?:\/\//, '').split('/')[1] || cleaned.replace(/^https?:\/\//, '').split('/')[0] || selectedProject.name
      });
    }
  };

  return (
    <>
      <header className="h-16 px-4 sm:px-6 bg-[#0E0E12] border-b border-white/10 flex items-center justify-between gap-4 sticky top-0 z-30">
        {/* Left: Brand / Home Link */}
        <div className="flex items-center gap-4">
          {onNavigateLanding && (
            <button
              onClick={onNavigateLanding}
              className="flex items-center gap-1.5 text-xs text-[#A1A1AA] hover:text-white transition-colors"
              title="Return to Landing Page"
            >
              <ArrowLeft size={15} />
              <span className="hidden sm:inline font-mono">Home</span>
            </button>
          )}

          {/* Project Selector Dropdown */}
          <div className="flex items-center gap-2">
            <select
              aria-label="Select Active Project"
              value={selectedProject.id}
              onChange={(e) => {
                const found = projects.find((p) => p.id === e.target.value);
                if (found) onSelectProject(found);
              }}
              className="bg-[#141414] border border-white/10 rounded-lg px-2.5 py-1.5 text-xs font-mono font-bold text-white outline-none cursor-pointer max-w-[180px] sm:max-w-[240px] truncate"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.framework})
                </option>
              ))}
            </select>

            <button
              onClick={() => setIsGithubModalOpen(true)}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white transition-colors"
              title="Connect Repository / Website"
            >
              <FolderGit2 size={15} />
            </button>
          </div>
        </div>

        {/* Center: Quick Target URL Input */}
        <form onSubmit={handleTargetUrlSubmit} className="hidden md:flex items-center flex-1 max-w-md mx-4">
          <input
            type="text"
            aria-label="Target repository or deployment URL"
            value={activeTargetUrl}
            onChange={(e) => setActiveTargetUrl(e.target.value)}
            placeholder="Target GitHub repo or deployment URL..."
            className="w-full bg-[#141414] border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-[#EDEDED] outline-none focus:border-white/30"
          />
        </form>

        {/* Right: Quick Audit Trigger & User Menu */}
        <div className="flex items-center gap-3">
          <button
            onClick={onTriggerScan}
            className="btn btn-primary px-3.5 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 bg-white text-black hover:bg-neutral-200"
          >
            <Play size={12} fill="#0A0A0A" />
            <span>Audit</span>
          </button>

          {/* User Auth Info / Profile Dropdown */}
          {user && user.isLoggedIn ? (
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen((prev) => !prev)}
                className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white/5 text-xs font-mono transition-colors"
              >
                <div className="w-6 h-6 rounded-full bg-white/10 border border-white/20 flex items-center justify-center font-bold text-[10px] text-white">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <span className="hidden sm:inline font-bold text-white max-w-[100px] truncate">
                  {user.name}
                </span>
                <ChevronDown size={12} className="text-[#A1A1AA]" />
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-52 bg-[#141414] border border-white/10 rounded-xl p-2 shadow-2xl z-50 flex flex-col gap-1 text-xs font-mono">
                  <div className="px-3 py-2 border-b border-white/10">
                    <div className="font-bold text-white truncate">{user.name}</div>
                    <div className="text-[10px] text-[#A1A1AA] truncate">{user.email}</div>
                  </div>

                  {onOpenCheckout && (
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onOpenCheckout();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg text-white hover:bg-white/10 flex items-center gap-2"
                    >
                      <Zap size={13} />
                      <span>Upgrade Plan</span>
                    </button>
                  )}

                  {onSignOut && (
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onSignOut();
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg text-red-400 hover:bg-red-500/10 flex items-center gap-2 border-t border-white/10 pt-2"
                    >
                      <LogOut size={13} />
                      <span>Sign Out</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={() => onOpenAuth && onOpenAuth('signin')}
                className="text-xs font-mono text-[#A1A1AA] hover:text-white px-2 py-1 rounded transition-colors"
              >
                Sign In
              </button>
              <button
                onClick={() => onOpenAuth && onOpenAuth('signup')}
                className="btn btn-primary text-xs font-mono px-3 py-1 rounded bg-white text-black hover:bg-neutral-200"
              >
                Sign Up
              </button>
            </div>
          )}
        </div>
      </header>

      <ConnectTargetModal
        isOpen={isGithubModalOpen}
        onClose={() => setIsGithubModalOpen(false)}
        onAddNewProject={onAddNewProject}
        onSelectProject={onSelectProject}
      />
    </>
  );
};
