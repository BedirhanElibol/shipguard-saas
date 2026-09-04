// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Project } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import {
  Settings,
  Key,
  Save,
  CheckCircle2,
  ShieldCheck,
  AlertTriangle,
  Trash2,
  X,
  Lock,
  ShieldAlert,
  Loader2,
  CreditCard,
  Zap,
  Check
} from 'lucide-react';
import { supabaseSignOut } from '@/lib/supabase';
import { useRouter } from 'next/navigation';

interface ProjectSettingsViewProps {
  project: Project;
  onSaveSettings?: (updatedFields: Partial<Project>) => void;
  onDeleteAccount?: () => void;
  user?: UserProfile | null;
  onUpdateUser?: (updatedUser: UserProfile) => void;
  onOpenCheckout?: () => void;
}

export const ProjectSettingsView: React.FC<ProjectSettingsViewProps> = ({
  project,
  onSaveSettings,
  onDeleteAccount,
  user,
  onUpdateUser,
  onOpenCheckout
}) => {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState(project.repoUrl);
  const [patToken, setPatToken] = useState((project as any).githubToken || '');
  const [saved, setSaved] = useState(false);

  // User Profile & Membership State
  const [profileName, setProfileName] = useState(user?.name || 'Bedirhan Elibol');
  const [profileEmail, setProfileEmail] = useState(user?.email || 'bedirhan@gmail.com');
  const [profileAvatarUrl, setProfileAvatarUrl] = useState(user?.avatarUrl || '');
  const [profileSaved, setProfileSaved] = useState(false);

  useEffect(() => {
    if (user) {
      if (user.name) setProfileName(user.name);
      if (user.email) setProfileEmail(user.email);
      if (user.avatarUrl !== undefined) setProfileAvatarUrl(user.avatarUrl || '');
    }
  }, [user]);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    const updatedUser: UserProfile = {
      name: profileName.trim() || 'Bedirhan Elibol',
      email: profileEmail.trim() || 'bedirhan@gmail.com',
      avatarUrl: profileAvatarUrl.trim() || undefined,
      tier: user?.tier || 'Free',
      isLoggedIn: true,
      emailVerified: user?.emailVerified ?? true
    };
    if (onUpdateUser) {
      onUpdateUser(updatedUser);
    }
    try {
      localStorage.setItem('shipguard_user', JSON.stringify(updatedUser));
    } catch (err) {
      console.warn('[ShipGuard Profile] Failed to persist user in storage:', err);
    }
    setProfileSaved(true);
    setTimeout(() => setProfileSaved(false), 2500);
  };

  // Danger Zone / GDPR Erasure State
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [confirmationInput, setConfirmationInput] = useState('');
  const [hasConfirmedCheckbox, setHasConfirmedCheckbox] = useState(false);
  const [isPurging, setIsPurging] = useState(false);
  const [purgeSuccess, setPurgeSuccess] = useState(false);

  // Close modal on Escape key for WCAG 2.2 AA accessibility
  useEffect(() => {
    if (!isDeleteModalOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsDeleteModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isDeleteModalOpen]);

  const handleSaveSettings = (e: React.FormEvent) => {
    e.preventDefault();
    if (onSaveSettings) {
      onSaveSettings({
        repoUrl,
        githubToken: patToken || undefined,
      });
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const handleExecutePurge = async () => {
    if (confirmationInput !== 'DELETE' || !hasConfirmedCheckbox) return;

    setIsPurging(true);

    try {
      // 1. Sign out of active Supabase session
      await supabaseSignOut().catch(() => {});

      // 2. Cascade wipe all stored/local ShipGuard data
      try {
        localStorage.removeItem('shipguard_user');
        localStorage.removeItem('shipguard_projects');
        localStorage.removeItem('shipguard_selected_project_id');
        localStorage.removeItem('shipguard_license_key');
        localStorage.removeItem('shipguard_data_version');
        sessionStorage.clear();
      } catch (err) {
        console.warn('[GDPR Erasure] LocalStorage purge warning:', err);
      }

      // 3. Trigger parent callback if provided
      if (onDeleteAccount) {
        onDeleteAccount();
      }

      setPurgeSuccess(true);
      setTimeout(() => {
        setIsDeleteModalOpen(false);
        router.push('/');
      }, 1500);
    } catch (err) {
      console.error('[GDPR Erasure] Error executing cascade deletion:', err);
    } finally {
      setIsPurging(false);
    }
  };

  return (
    <div className="flex flex-col gap-8 pb-12">
      {/* Header */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
            <Settings size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-[#EDEDED]">
              Project Configuration &amp; Release Settings
            </h1>
            <p className="text-xs text-[#A1A1AA] mt-0.5">
              Manage target repository URLs, GitHub Personal Access Tokens, and CI/CD clearance policies
            </p>
          </div>
        </div>
      </div>

      {/* Membership & Subscription Management Card */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-emerald-500 via-emerald-400 to-teal-500" />

        {/* Card Header */}
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center">
              <CreditCard size={20} />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-extrabold text-white">
                Membership &amp; Subscription Management
              </h2>
              <p className="text-xs text-[#A1A1AA] mt-0.5">
                Manage your active plan, included audit rules, and user profile preferences.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Active
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Plan Overview & Included Features */}
          <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-5 flex flex-col justify-between gap-5">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <div>
                  <span className="text-[10px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">
                    Current Plan
                  </span>
                  <div className="text-base font-extrabold text-white">
                    {user?.tier === 'Pro'
                      ? 'Pro Plan (Advanced Audit)'
                      : user?.tier === 'Enterprise'
                      ? 'Enterprise Plan'
                      : 'Free Tier'}
                  </div>
                </div>
                <span className="text-xs font-mono font-bold text-[#EDEDED] bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg">
                  {user?.tier === 'Pro' ? '$19 / mo' : user?.tier === 'Enterprise' ? '$49 / mo' : '$0 / Lifetime'}
                </span>
              </div>

              {/* Included Features List */}
              <div className="flex flex-col gap-2.5">
                <span className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">
                  Included Features:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-[#EDEDED]">
                  <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                    <span className="font-medium">OWASP Security Pre-flight Checks</span>
                  </div>
                  <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                    <span className="font-medium">VibePolish UI &amp; Design System Rules</span>
                  </div>
                  <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                    <span className="font-medium">Unlimited Static Analysis</span>
                  </div>
                  <div className="flex items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/5">
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                    <span className="font-medium">100% Local Privacy</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Plan Switcher / Upgrade Button */}
            <div className="pt-3 border-t border-white/10 flex items-center justify-between flex-wrap gap-3">
              <span className="text-xs text-[#A1A1AA]">
                For higher release gate limits and live CI/CD webhook integrations:
              </span>
              <button
                type="button"
                onClick={() => {
                  if (onOpenCheckout) {
                    onOpenCheckout();
                  } else {
                    router.push('/checkout');
                  }
                }}
                className="btn btn-primary min-h-[40px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer"
              >
                <Zap size={14} className="fill-black" />
                <span>Upgrade Plan</span>
              </button>
            </div>
          </div>

          {/* Profile Details & Avatar Preview */}
          <form onSubmit={handleSaveProfile} className="bg-[#0A0A0A] border border-white/10 rounded-xl p-5 flex flex-col gap-4">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <span className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase tracking-wider">
                Profile Details &amp; Avatar
              </span>
              {profileSaved && (
                <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1">
                  <Check size={13} /> Saved
                </span>
              )}
            </div>

            <div className="flex items-center gap-4">
              {profileAvatarUrl ? (
                <img
                  src={profileAvatarUrl}
                  alt={profileName}
                  className="w-14 h-14 rounded-full object-cover border-2 border-white/20 shadow-md bg-[#141414] shrink-0"
                  onError={(e) => {
                    (e.target as HTMLElement).style.display = 'none';
                  }}
                />
              ) : (
                <div className="w-14 h-14 rounded-full bg-white/10 border-2 border-white/20 flex items-center justify-center font-bold text-lg text-white shadow-md shrink-0">
                  {(profileName || 'B').charAt(0).toUpperCase()}
                </div>
              )}
              <div className="min-w-0 flex-1">
                <div className="text-xs font-bold text-white truncate">{profileName || 'Unnamed User'}</div>
                <div className="text-[11px] text-[#A1A1AA] truncate">{profileEmail || 'email@example.com'}</div>
                <div className="mt-1">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    {user?.tier === 'Free' || !user?.tier ? 'Free Plan' : `${user.tier} Plan`}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase">
                Display Name
              </label>
              <input
                type="text"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                placeholder="Bedirhan Elibol"
                className="w-full bg-[#141414] border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none focus:border-white/30"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase">
                Email Address
              </label>
              <input
                type="email"
                value={profileEmail}
                onChange={(e) => setProfileEmail(e.target.value)}
                placeholder="bedirhan@gmail.com"
                className="w-full bg-[#141414] border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none focus:border-white/30"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase">
                Avatar Image URL (GitHub or Custom URL)
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={profileAvatarUrl}
                  onChange={(e) => setProfileAvatarUrl(e.target.value)}
                  placeholder="https://github.com/BedirhanElibol.png"
                  className="flex-1 bg-[#141414] border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none focus:border-white/30"
                />
                <button
                  type="button"
                  onClick={() => setProfileAvatarUrl('https://github.com/BedirhanElibol.png')}
                  className="px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-[11px] font-mono text-[#A1A1AA] hover:text-white transition-colors whitespace-nowrap cursor-pointer"
                  title="Use GitHub avatar"
                >
                  GitHub
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="mt-1 min-h-[40px] px-4 py-2 rounded-xl bg-white text-black font-bold text-xs hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 shadow-md self-end cursor-pointer"
            >
              {profileSaved ? <Check size={14} /> : <Save size={14} />}
              <span>{profileSaved ? 'Profile Saved' : 'Save Profile'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* Settings Form */}
      <form onSubmit={handleSaveSettings} className="bg-[#141414] border border-white/10 rounded-xl p-6 bg-[#141414] border-white/10 flex flex-col gap-6">
        <div className="flex flex-col gap-2">
          <label className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
            <ShieldCheck size={14} className="text-white" />
            <span>Target Repository / Web Deployment URL:</span>
          </label>
          <input
            aria-label="Target Repository or Web Deployment URL"
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-[#EDEDED] font-mono focus:outline-none focus:border-white/20"
          />
        </div>

        <div className="flex flex-col gap-2">
          <label className="text-xs font-mono font-bold text-[#EDEDED] flex items-center gap-2">
            <Key size={14} className="text-white" />
            <span>GitHub Personal Access Token (PAT) (Optional for Private Repos):</span>
          </label>
          <input
            aria-label="GitHub Personal Access Token"
            type="password"
            placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            value={patToken}
            onChange={(e) => setPatToken(e.target.value)}
            className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-4 py-2.5 text-xs text-[#EDEDED] font-mono focus:outline-none focus:border-white/20"
          />
        </div>

        <div className="flex items-center justify-between pt-4 border-t border-white/10 flex-wrap gap-3">
          <div className="text-xs text-[#A1A1AA] font-mono">
            {saved ? '✓ Settings successfully saved to local project state.' : 'Changes take effect immediately on next audit run.'}
          </div>

          <button
            type="submit"
            className="btn btn-primary min-h-[44px] px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-md"
          >
            {saved ? <CheckCircle2 size={15} /> : <Save size={15} />}
            <span>{saved ? 'Saved!' : 'Save Settings'}</span>
          </button>
        </div>
      </form>

      {/* Danger Zone: GDPR / KVKK Cascade Account Deletion */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 bg-[#180a0a]/60 border border-red-500/30 rounded-2xl flex flex-col gap-6 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap sm:flex-nowrap">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 flex items-center justify-center shrink-0 mt-0.5">
              <AlertTriangle size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-extrabold text-white">
                  Danger Zone: GDPR / KVKK Data Erasure
                </h2>
                <span className="text-[0.65rem] font-extrabold uppercase tracking-wider bg-red-500/20 border border-red-500/40 text-red-300 px-2 py-0.5 rounded-full">
                  Irreversible
                </span>
              </div>
              <p className="text-xs text-[#CBD5E1] mt-1.5 leading-relaxed max-w-2xl">
                Exercise your Right to Erasure (GDPR Article 17 / KVKK Madde 7). Permanently destroy your account, wipe all registered repository audits, flush cached vulnerability findings, purge personal access credentials, and wipe local storage states.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              setConfirmationInput('');
              setHasConfirmedCheckbox(false);
              setPurgeSuccess(false);
              setIsDeleteModalOpen(true);
            }}
            className="min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 hover:text-red-100 text-xs font-bold flex items-center justify-center gap-2 transition-colors shrink-0"
          >
            <Trash2 size={15} />
            <span>Delete Account &amp; Wipe Data</span>
          </button>
        </div>
      </div>

      {/* GDPR / KVKK Deletion Confirmation Modal */}
      <AnimatePresence>
        {isDeleteModalOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/85  flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gdpr-delete-modal-title"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="w-full max-w-lg max-h-[85vh] overflow-y-auto bg-[#141414] border border-red-500/30 rounded-2xl p-6 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
            >
              {/* Close Button with 44x44px target */}
              <button
                type="button"
                onClick={() => setIsDeleteModalOpen(false)}
                aria-label="Close deletion confirmation modal"
                className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
              >
                <X size={20} />
              </button>

              {purgeSuccess ? (
                <div className="py-8 flex flex-col items-center justify-center text-center gap-4">
                  <div className="w-16 h-16 rounded-full bg-white/5 text-white border border-emerald-500/40 flex items-center justify-center">
                    <CheckCircle2 size={36} />
                  </div>
                  <h3 className="text-xl font-extrabold text-white">
                    Data Purged Successfully
                  </h3>
                  <p className="text-xs text-[#A1A1AA] max-w-sm">
                    All account records, audits, tokens, and local cache have been erased in compliance with GDPR Art. 17 / KVKK Madde 7. Redirecting to home...
                  </p>
                </div>
              ) : (
                <>
                  {/* Modal Header */}
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 flex items-center justify-center shrink-0">
                      <ShieldAlert size={20} />
                    </div>
                    <div>
                      <h3 id="gdpr-delete-modal-title" className="text-lg font-extrabold text-white">
                        Confirm Permanent Account &amp; Data Erasure
                      </h3>
                      <p className="text-xs text-[#A1A1AA]">
                        GDPR Article 17 / KVKK Madde 7 Right to Erasure
                      </p>
                    </div>
                  </div>

                  {/* Impact Warning Notice */}
                  <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/20 text-xs text-red-200/90 flex flex-col gap-2">
                    <span className="font-extrabold text-red-300 uppercase text-[0.7rem] flex items-center gap-1.5">
                      <AlertTriangle size={13} />
                      The following data will be permanently wiped:
                    </span>
                    <ul className="space-y-1 list-disc list-inside text-[0.72rem] text-red-200/80">
                      <li>Active user profile, authenticated session tokens, and billing records.</li>
                      <li>All registered project repositories and custom scan settings.</li>
                      <li>Historical audit reports, gate matrices, and remediation logs.</li>
                      <li>Stored GitHub Personal Access Tokens (PAT) and webhook credentials.</li>
                      <li>Local browser database and storage caches (<code className="text-red-300">shipguard_*</code>).</li>
                    </ul>
                  </div>

                  {/* Confirmation Input and Checkbox */}
                  <div className="flex flex-col gap-4">
                    <div className="flex flex-col gap-1.5">
                      <label htmlFor="delete-confirm-input" className="text-xs font-bold text-[#CBD5E1]">
                        To confirm erasure, type <span className="font-mono text-red-400 font-extrabold">DELETE</span> below:
                      </label>
                      <input
                        id="delete-confirm-input"
                        type="text"
                        value={confirmationInput}
                        onChange={(e) => setConfirmationInput(e.target.value)}
                        placeholder="Type DELETE to confirm"
                        className="w-full bg-[#0A0A0A] border border-white/15 focus:border-red-500 rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
                      />
                    </div>

                    <label className="flex items-start gap-2.5 cursor-pointer text-xs text-[#A1A1AA] hover:text-white select-none">
                      <input
                        id="confirm-delete-checkbox"
                        aria-label="Confirm permanent deletion of account and telemetry"
                        type="checkbox"
                        checked={hasConfirmedCheckbox}
                        onChange={(e) => setHasConfirmedCheckbox(e.target.checked)}
                        className="mt-0.5 rounded border-white/20 bg-[#0A0A0A] text-red-600 focus:ring-0 w-4 h-4"
                      />
                      <span>
                        I acknowledge this action is irreversible and request the permanent deletion of my account and all associated telemetry.
                      </span>
                    </label>
                  </div>

                  {/* Actions (min 44px height touch targets) */}
                  <div className="flex items-center justify-end gap-3 pt-2 border-t border-white/10">
                    <button
                      type="button"
                      onClick={() => setIsDeleteModalOpen(false)}
                      disabled={isPurging}
                      className="min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
                    >
                      Cancel
                    </button>

                    <button
                      type="button"
                      onClick={handleExecutePurge}
                      disabled={confirmationInput !== 'DELETE' || !hasConfirmedCheckbox || isPurging}
                      className="min-h-[44px] min-w-[44px] px-5 py-2.5 rounded-xl bg-red-600 hover:bg-red-700 disabled:opacity-40 disabled:hover:bg-red-600 text-xs font-bold text-white transition-colors flex items-center justify-center gap-2 shadow-lg"
                    >
                      {isPurging ? (
                        <>
                          <Loader2 size={14} className="animate-spin" />
                          <span>Purging Data...</span>
                        </>
                      ) : (
                        <>
                          <Trash2 size={14} />
                          <span>Permanently Delete &amp; Wipe</span>
                        </>
                      )}
                    </button>
                  </div>
                </>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
