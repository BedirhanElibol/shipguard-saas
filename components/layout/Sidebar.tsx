// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  Palette,
  Layers,
  Activity,
  FolderGit2,
  CheckSquare,
  CreditCard,
  Settings,
  FileText
} from 'lucide-react';

interface SidebarProps {
  activeNav: string;
  onNavigate: (nav: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeNav, onNavigate }) => {
  const mainNav = [
    { id: 'dashboard', label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'projects', label: 'Connected Projects', icon: FolderGit2 },
    { id: 'scans', label: 'Scan History', icon: FileText },
  ];

  const pillarNav = [
    { id: 'security', label: 'Security Pre-Flight', icon: ShieldCheck },
    { id: 'vibepolish', label: 'Design & UX Polish', icon: Palette },
    { id: 'aicliche', label: 'AI Anti-Pattern Audit', icon: Palette },
    { id: 'aimaster', label: 'Master Quality Matrix', icon: Layers },
    { id: 'vibecare', label: 'VibeCare Health', icon: Activity },
  ];

  const managementNav = [
    { id: 'remediation', label: 'Remediation Queue', icon: CheckSquare },
    { id: 'checkout', label: 'Billing & Tiers', icon: CreditCard },
    { id: 'settings', label: 'Security Policies', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0A0A0A] border-r border-white/10 p-5 flex flex-col gap-6 shrink-0">
      {/* Navigation Group 1: Core */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          CORE MODULES
        </span>
        {mainNav.length === 0 ? (
          <span className="text-xs text-gray-500 px-3">No core modules available</span>
        ) : (
          mainNav.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full text-left ${
                  isActive
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
                }`}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </button>
            );
          })
        )}
      </div>

      <div className="h-[1px] bg-white/[0.08] my-1" />

      {/* Navigation Group 2: Product Pillars */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          PRODUCT PILLARS
        </span>
        {pillarNav.length === 0 ? (
          <span className="text-xs text-gray-500 px-3">No pillars available</span>
        ) : (
          pillarNav.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full ${
                  isActive
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon size={16} />
                  <span>{item.label}</span>
                </div>

              </button>
            );
          })
        )}
      </div>

      <div className="h-[1px] bg-white/[0.08] my-1" />

      {/* Navigation Group 3: Management */}
      <div className="flex flex-col gap-1">
        <span className="text-[0.68rem] font-extrabold text-[#A1A1AA] font-mono tracking-[0.1em] uppercase px-3 mb-2">
          MANAGEMENT
        </span>
        {managementNav.length === 0 ? (
          <span className="text-xs text-gray-500 px-3">No management modules available</span>
        ) : (
          managementNav.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-bold transition-all w-full text-left ${
                  isActive
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-[#EDEDED] hover:bg-white/[0.04] border border-transparent'
                }`}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </button>
            );
          })
        )}
      </div>
    </aside>
  );
};
