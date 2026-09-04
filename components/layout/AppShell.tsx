// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Project } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/mockData';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { PageTransition } from '../PageTransition';
import { UserProfile } from '@/components/auth/AuthModal';

interface AppShellProps {
  children?: React.ReactNode;
  activeNav: string;
  onNavigate: (nav: string) => void;
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

export const AppShell: React.FC<AppShellProps> = ({
  children,
  activeNav,
  onNavigate,
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

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] flex flex-col font-sans">
      {/* Top Header with Layout Fixes & Auth Controls */}
      <Header
        projects={projects}
        selectedProject={selectedProject}
        onSelectProject={onSelectProject}
        onTriggerScan={onTriggerScan}
        onNavigateLanding={onNavigateLanding}
        onAddNewProject={onAddNewProject}
        user={user}
        onOpenAuth={onOpenAuth}
        onSignOut={onSignOut}
        onOpenCheckout={onOpenCheckout}
        onNavigateSettings={() => onNavigate('settings')}
      />

      <div className="flex flex-1">
        {/* Left Persistent Sidebar */}
        <Sidebar
          activeNav={activeNav}
          onNavigate={onNavigate}
          user={user}
          onOpenAuth={(mode) => onOpenAuth && onOpenAuth(mode)}
          onNavigateSettings={() => onNavigate('settings')}
        />

        {/* Content Area with Fluid Page Transition */}
        <main className="flex-1 min-w-0 bg-[#0A0A0A] p-6 sm:p-8 overflow-y-auto w-full">
          <PageTransition routeKey={activeNav}>
            {children}
          </PageTransition>
        </main>
      </div>
    </div>
  );
};
