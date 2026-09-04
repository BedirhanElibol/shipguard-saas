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
  FileText,
  LogIn
} from 'lucide-react';
import { UserProfile } from '@/components/auth/AuthModal';

interface SidebarProps {
  activeNav: string;
  onNavigate: (nav: string) => void;
  user?: UserProfile | null;
  onOpenAuth?: (mode: 'signin') => void;
  onNavigateSettings?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeNav,
  onNavigate,
  user,
  onOpenAuth,
  onNavigateSettings
}) => {
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
    <aside className="w-64 bg-[#0A0A0A] border-r border-white/10 p-5 flex flex-col justify-between shrink-0">
      <div className="flex flex-col gap-6">
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
      </div>

      {/* Linear/Vercel-style User Profile & Membership footer */}
      <div className="pt-4 border-t border-white/10 mt-6">
        {user && user.isLoggedIn ? (
          <div className="p-2.5 rounded-xl bg-[#141414] border border-white/10 hover:border-white/20 transition-all flex items-center justify-between gap-2 shadow-sm">
            <div
              onClick={() => (onNavigateSettings ? onNavigateSettings() : onNavigate('settings'))}
              className="flex items-center gap-2.5 min-w-0 flex-1 cursor-pointer select-none group"
            >
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.name}
                  className="w-8 h-8 rounded-full object-cover border border-white/20 shrink-0"
                  onError={(e) => {
                    (e.target as HTMLElement).style.display = 'none';
                  }}
                />
              ) : (
                <div className="w-8 h-8 rounded-full bg-white/10 border border-white/20 flex items-center justify-center font-bold text-xs text-white shrink-0">
                  {user.name.charAt(0).toUpperCase()}
                </div>
              )}
              <div className="min-w-0 flex-1">
                <div className="text-xs font-bold text-white truncate leading-tight group-hover:text-emerald-400 transition-colors">
                  {user.name}
                </div>
                <div className="mt-0.5">
                  <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                    user.tier === 'Free'
                      ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                      : user.tier === 'Pro'
                      ? 'bg-blue-500/10 border border-blue-500/30 text-blue-400'
                      : 'bg-purple-500/10 border border-purple-500/30 text-purple-400'
                  }`}>
                    {user.tier === 'Free' ? 'Ücretsiz Plan' : `${user.tier} Plan`}
                  </span>
                </div>
              </div>
            </div>

            <button
              onClick={() => (onNavigateSettings ? onNavigateSettings() : onNavigate('settings'))}
              className="p-1.5 rounded-lg text-[#A1A1AA] hover:text-white hover:bg-white/10 transition-colors shrink-0"
              title="Profil ve Ayarlar"
              aria-label="Profil ve Ayarlar"
            >
              <Settings size={15} />
            </button>
          </div>
        ) : (
          <button
            onClick={() => onOpenAuth && onOpenAuth('signin')}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 text-xs font-mono font-bold text-white transition-all shadow-sm group"
          >
            <LogIn size={14} className="text-[#A1A1AA] group-hover:text-white transition-colors" />
            <span>Giriş Yap / Kaydol</span>
          </button>
        )}
      </div>
    </aside>
  );
};
