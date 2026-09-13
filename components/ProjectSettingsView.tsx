// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import Image from 'next/image';
import { motion, AnimatePresence } from 'framer-motion';
import { Project } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { Settings, Key, Save, Trash2, X, Lock, User, Eye, EyeOff } from 'lucide-react';
import { CheckCircle2, ShieldCheck, ShieldAlert, AlertTriangle, AlertCircle } from 'lucide-react';
import { Loader2, CreditCard, Zap, Check, Calendar, ExternalLink } from 'lucide-react';

import { supabaseSignOut, getSupabase } from '@/lib/supabase';
import { useRouter } from 'next/navigation';
import { verifyLicenseKey, activateUserTier } from '@/lib/stripe-checkout';
import { purgeZelsisStorage } from '@/lib/storage';
import { getSubscriptionValidity, formatRenewalDate } from '@/lib/subscription-utils';

interface ProjectSettingsViewProps {
  project: Project;
  onSaveSettings?: (updatedFields: Partial<Project>) => void;
  onDeleteAccount?: () => void;
  user?: UserProfile | null;
  onUpdateUser?: (updatedUser: UserProfile) => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
  onOpenAuth?: (mode?: 'signin' | 'signup') => void;
}

export const ProjectSettingsView: React.FC<ProjectSettingsViewProps> = ({
  project,
  onSaveSettings,
  onDeleteAccount,
  user,
  onUpdateUser,
  onOpenCheckout,
  onOpenAuth
}) => {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState(project.repoUrl);
  const [patToken, setPatToken] = useState((project as any).githubToken || '');
  const [showPatToken, setShowPatToken] = useState(false);
  const [saved, setSaved] = useState(false);

  // Synchronize form fields when selected project changes
  useEffect(() => {
    setRepoUrl(project.repoUrl || '');
    setPatToken((project as any).githubToken || '');
  }, [project.id, project.repoUrl, (project as any).githubToken]);

  // User Profile & Membership State
  const isAuthenticated = Boolean(user && user.isLoggedIn);
  const isGuest = !isAuthenticated;
  const [profileName, setProfileName] = useState(user?.name || '');
  const [profileEmail, setProfileEmail] = useState(user?.email || '');
  const [profileAvatarUrl, setProfileAvatarUrl] = useState(user?.avatarUrl || '');
  const [profileSaved, setProfileSaved] = useState(false);
  const validity = getSubscriptionValidity(user);

  // Subscription Sync State
  const [isSyncingSub, setIsSyncingSub] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<{ status: 'idle' | 'success' | 'error'; message: string }>({
    status: 'idle',
    message: '',
  });

  const handleSyncSubscription = async () => {
    if (!user?.email) return;
    setIsSyncingSub(true);
    setSyncFeedback({ status: 'idle', message: '' });
    try {
      const supabase = getSupabase();
      const sessionRes = await supabase?.auth.getSession();
      const token = sessionRes?.data?.session?.access_token;

      if (!token) {
        setSyncFeedback({
          status: 'error',
          message: 'Active session required to synchronize subscription status. Please sign in.',
        });
        setIsSyncingSub(false);
        return;
      }

      const res = await fetch('/api/v1/subscription/sync', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ email: user.email }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.active && (data.tier === 'Pro' || data.tier === 'Enterprise')) {
          const validExpiresAt = data.expiresAt || user.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          const updatedUser: UserProfile = {
            ...user,
            tier: data.tier,
            expiresAt: validExpiresAt,
            billingCycle: data.billingCycle || user.billingCycle,
            status: 'active',
          };
          if (onUpdateUser) {
            onUpdateUser(updatedUser);
          }
          localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
          const dateStr = formatRenewalDate(validExpiresAt);
          setSyncFeedback({
            status: 'success',
            message: `Active ${data.tier} subscription confirmed! Renews / valid until: ${dateStr}`,
          });
        } else {
          // Guard against false downgrades: check if local subscription period is still active or valid license held
          const currentLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          const hasValidLicense = Boolean(
            currentLic && verifyLicenseKey(currentLic, user.email).valid
          );
          const isLocallyActive = Boolean(
            user.tier !== 'Free' &&
            (!user.expiresAt || new Date(user.expiresAt).getTime() > Date.now())
          );

          if (isLocallyActive || hasValidLicense) {
            const dateStr = formatRenewalDate(user.expiresAt);
            setSyncFeedback({
              status: 'success',
              message: `Active ${user.tier} plan preserved. Renews / valid until: ${dateStr}`,
            });
          } else {
            const updatedUser: UserProfile = {
              ...user,
              tier: 'Free',
              expiresAt: undefined,
              status: 'canceled',
            };
            if (onUpdateUser) {
              onUpdateUser(updatedUser);
            }
            localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
            setSyncFeedback({
              status: 'error',
              message: `Subscription period ended for ${user.email}. Account reverted to Free Tier.`,
            });
          }
        }
      } else {
        setSyncFeedback({
          status: 'error',
          message: 'Unable to reach subscription verification service.',
        });
      }
    } catch {
      setSyncFeedback({
        status: 'error',
        message: 'Network error checking subscription status.',
      });
    } finally {
      setIsSyncingSub(false);
      setTimeout(() => setSyncFeedback({ status: 'idle', message: '' }), 6000);
    }
  };

  // License Key Activation State
  const [licenseInput, setLicenseInput] = useState('');
  const [licenseFeedback, setLicenseFeedback] = useState<{ status: 'idle' | 'success' | 'error'; message: string }>({
    status: 'idle',
    message: ''
  });

  const handleActivateLicense = (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseInput.trim()) return;

    const result = verifyLicenseKey(licenseInput.trim(), user?.email || profileEmail);
    if (result.valid && (result.tier === 'Pro' || result.tier === 'Enterprise')) {
      activateUserTier(result.tier, licenseInput.trim());
      setLicenseFeedback({
        status: 'success',
        message: `Success! Activated ${result.tier} plan until ${result.expiresAt}. All premium security checks are now unlocked.`
      });
      if (onUpdateUser && user) {
        onUpdateUser({
          ...user,
          tier: result.tier,
          expiresAt: result.expiresAt,
          status: 'active',
          lastVerifiedAt: Date.now(),
        });
      }
    } else {
      setLicenseFeedback({
        status: 'error',
        message: 'Invalid or malformed license key.'
      });
      setTimeout(() => {
        setLicenseFeedback({ status: 'idle', message: '' });
      }, 4000);
    }
  };

  useEffect(() => {
    if (user && user.isLoggedIn) {
      setProfileName(user.name || '');
      setProfileEmail(user.email || '');
      setProfileAvatarUrl(user.avatarUrl || '');
    } else {
      setProfileName('');
      setProfileEmail('');
      setProfileAvatarUrl('');
    }
  }, [user]);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (isGuest || !user) {
      // Do not save fake users or set isLoggedIn: true
      return;
    }
    const updatedUser: UserProfile = {
      ...user,
      name: profileName.trim() || user.name || 'User',
      email: profileEmail.trim() || user.email || '',
      avatarUrl: profileAvatarUrl.trim() || undefined,
      tier: user.tier || 'Free',
      isLoggedIn: true,
      emailVerified: user.emailVerified ?? true,
      expiresAt: user.expiresAt,
      status: user.status,
      gracePeriodUntil: user.gracePeriodUntil,
      billingCycle: user.billingCycle,
      lastVerifiedAt: user.lastVerifiedAt || Date.now(),
    };
    if (onUpdateUser) {
      onUpdateUser(updatedUser);
    }
    try {
      localStorage.setItem('zelsis_user', JSON.stringify(updatedUser));
      localStorage.removeItem('shipguard_user');
    } catch (err) {
      console.warn('[Zelsis Profile] Failed to persist user in storage:', err);
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

  const [isExporting, setIsExporting] = useState(false);
  const handleExportData = async () => {
    if (!isAuthenticated || !user) return;
    setIsExporting(true);
    try {
      const exportData = {
        exportVersion: '1.0',
        exportedAt: new Date().toISOString(),
        framework: ['GDPR Article 20 (Right to Data Portability)', 'CCPA'],
        user: {
          name: user.name,
          email: user.email,
          tier: user.tier,
        },
        activeProject: {
          name: project.name,
          repoUrl: project.repoUrl,
          gateStatus: project.gateStatus,
          readinessScore: project.readinessScore,
          findingsCount: project.findings?.length || 0,
        },
      };
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `zelsis-privacy-export-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[GDPR Export] Failed to export data:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExecutePurge = async () => {
    if (confirmationInput !== 'DELETE' || !hasConfirmedCheckbox) return;

    setIsPurging(true);

    try {
      // 1. Server-side deletion API call for full GDPR/CCPA erasure
      if (isAuthenticated && user?.email) {
        try {
          await fetch('/api/v1/user/delete', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirmation: 'DELETE', email: user.email })
          });
        } catch (apiErr) {
          console.warn('[GDPR Erasure] Server-side deletion notice:', apiErr);
        }
      }

      // 2. Sign out of active Supabase session
      await supabaseSignOut().catch(() => {});

      // 3. Cascade wipe all stored/local Zelsis data
      purgeZelsisStorage(false);

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
            <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold border flex items-center gap-1.5 ${validity.badgeColors.bg} ${validity.badgeColors.border} ${validity.badgeColors.text}`}>
              <span className={`w-2 h-2 rounded-full ${validity.badgeColors.dot} ${validity.isActive ? 'animate-pulse' : ''}`} />
              {validity.isActive ? 'Active' : 'Expired'}
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
                  <div className="text-base font-extrabold text-white flex items-center gap-2">
                    <span>
                      {user?.tier === 'Pro'
                        ? 'Pro Plan (Advanced Audit)'
                        : user?.tier === 'Enterprise'
                        ? 'Enterprise Plan'
                        : 'Free Tier'}
                    </span>
                    {user?.tier && user.tier !== 'Free' && (
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${validity.badgeColors.bg} ${validity.badgeColors.text} ${validity.badgeColors.border}`}>
                        {validity.isActive ? 'ACTIVE' : 'EXPIRED'}
                      </span>
                    )}
                  </div>
                </div>
                <span className="text-xs font-mono font-bold text-[#EDEDED] bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg">
                  {user?.tier === 'Pro' ? '$19 / mo' : user?.tier === 'Enterprise' ? '$49 / mo' : '$0 / Free Tier'}
                </span>
              </div>

              {/* Rich Renewal Widget */}
              {user?.tier && user.tier !== 'Free' ? (
                <div className="p-4 rounded-xl bg-white/[0.03] border border-white/10 flex flex-col gap-3">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${validity.badgeColors.dot} ${validity.isActive ? 'animate-pulse' : ''}`} />
                      <span className="text-lg font-mono font-extrabold text-white">
                        {validity.countdownLabel}
                      </span>
                    </div>
                    <a
                      href="https://polar.sh/purchases"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1.5 transition-colors"
                    >
                      <span>Manage at Polar</span>
                      <ExternalLink size={12} />
                    </a>
                  </div>

                  {/* Visual billing cycle progress bar */}
                  <div className="flex flex-col gap-1.5">
                    <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${validity.badgeColors.bar}`}
                        style={{ width: `${validity.cycleProgressPercent}%` }}
                        role="progressbar"
                        aria-valuenow={validity.cycleProgressPercent}
                        aria-valuemin={0}
                        aria-valuemax={100}
                      />
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-[#A1A1AA]">
                      <div className="flex items-center gap-1.5">
                        <Calendar size={13} className="text-[#A1A1AA] shrink-0" />
                        <span>
                          {validity.isExpired
                            ? `Expired on ${validity.formattedRenewalDate}`
                            : `Renews on ${validity.formattedRenewalDate}`}
                        </span>
                      </div>
                      <span className="font-mono text-[10px]">
                        {validity.cycleProgressPercent}% Cycle Completed
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-1.5 text-xs text-[#A1A1AA]">
                  <Calendar size={13} className="text-emerald-400 shrink-0" />
                  <span>Free Tier &bull; Standard Access</span>
                </div>
              )}

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

            {/* Plan Switcher / Upgrade Button & Subscription Sync */}
            <div className="pt-3 border-t border-white/10 flex items-center justify-between flex-wrap gap-3">
              <span className="text-xs text-[#A1A1AA]">
                Purchased on Polar or need to verify your active plan?
              </span>
              <div className="flex items-center gap-2">
                {isAuthenticated && (
                  <button
                    type="button"
                    onClick={handleSyncSubscription}
                    disabled={isSyncingSub}
                    className="min-h-[40px] px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    {isSyncingSub ? (
                      <>
                        <Loader2 size={13} className="animate-spin text-emerald-400" />
                        <span>Checking...</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck size={14} className="text-emerald-400" />
                        <span>Sync Subscription</span>
                      </>
                    )}
                  </button>
                )}
                {user?.tier === 'Pro' ? (
                  <>
                    <a
                      href="https://polar.sh/purchases"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="min-h-[40px] px-3.5 py-2 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                    >
                      <ExternalLink size={13} />
                      <span>Manage at Polar</span>
                    </a>
                    <button
                      type="button"
                      onClick={() => {
                        if (onOpenCheckout) {
                          onOpenCheckout('Enterprise');
                        } else {
                          router.push('/checkout?plan=enterprise');
                        }
                      }}
                      className="btn btn-primary min-h-[40px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer"
                    >
                      <Zap size={14} className="fill-black" />
                      <span>Upgrade to Enterprise ($49/mo)</span>
                    </button>
                  </>
                ) : user?.tier === 'Enterprise' ? (
                  <a
                    href="https://polar.sh/purchases"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="min-h-[40px] px-3.5 py-2 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-xs flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <ExternalLink size={13} />
                    <span>Manage Subscription at Polar</span>
                  </a>
                ) : (
                  <button
                    type="button"
                    onClick={() => {
                      if (onOpenCheckout) {
                        onOpenCheckout('Pro');
                      } else {
                        router.push('/checkout?plan=pro');
                      }
                    }}
                    className="btn btn-primary min-h-[40px] px-4 py-2 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer"
                  >
                    <Zap size={14} className="fill-black" />
                    <span>Upgrade to Pro ($19/mo)</span>
                  </button>
                )}
              </div>
            </div>
            {syncFeedback.message && (
              <div className={`text-xs font-mono p-3 rounded-xl border ${syncFeedback.status === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'}`}>
                {syncFeedback.message}
              </div>
            )}
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

            {!isAuthenticated && (
              <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-amber-300 text-xs">
                <div className="flex items-center gap-2.5">
                  <AlertCircle size={16} className="shrink-0" />
                  <span>Sign in to customize and link your profile. Profile settings are read-only in guest mode.</span>
                </div>
                {onOpenAuth && (
                  <button
                    type="button"
                    onClick={() => onOpenAuth('signin')}
                    className="min-h-[44px] sm:min-h-[36px] px-3.5 py-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 text-xs font-bold font-mono transition-colors shrink-0 cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <span>Sign In / Register</span>
                  </button>
                )}
              </div>
            )}

            <div className="flex items-center gap-4">
              {profileAvatarUrl ? (
                <Image
                  src={profileAvatarUrl}
                  alt={profileName || 'User Avatar'}
                  width={56}
                  height={56}
                  unoptimized
                  className="w-14 h-14 rounded-full object-cover border-2 border-white/20 shadow-md bg-[#141414] shrink-0"
                  onError={(e) => {
                    (e.currentTarget as HTMLElement).style.display = 'none';
                  }}
                />
              ) : (
                <div className="w-14 h-14 rounded-full bg-white/10 border-2 border-white/20 flex items-center justify-center font-bold text-lg text-white shadow-md shrink-0">
                  {profileName ? (
                    profileName.charAt(0).toUpperCase()
                  ) : (
                    <User size={22} className="text-[#A1A1AA]" />
                  )}
                </div>
              )}
              <div className="min-w-0 flex-1">
                <div className="text-xs font-bold text-white truncate">
                  {profileName || (isAuthenticated ? 'Unnamed Developer' : 'Guest Developer')}
                </div>
                <div className="text-[11px] text-[#A1A1AA] truncate">
                  {profileEmail || (isAuthenticated ? 'email@example.com' : 'Not signed in')}
                </div>
                <div className="mt-1">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    {user?.tier && user.tier !== 'Free' ? `${user.tier} Plan` : isAuthenticated ? 'Free Plan' : 'Guest Mode'}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
                <span>Display Name</span>
                {!isAuthenticated && (
                  <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize and link your profile</span>
                )}
              </label>
              <input
                aria-label="Display Name"
                type="text"
                disabled={!isAuthenticated}
                readOnly={!isAuthenticated}
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                placeholder={!isAuthenticated ? "Sign in to customize and link your profile." : "e.g. Alex Morgan"}
                className={`w-full border rounded-xl px-3.5 py-2 text-xs font-mono outline-none transition-colors ${
                  !isAuthenticated
                    ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed'
                    : 'bg-[#141414] border-white/10 text-white focus:border-white/30 focus-visible:ring-1 focus-visible:ring-emerald-500'
                }`}
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
                <span>Email Address</span>
                {!isAuthenticated && (
                  <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize and link your profile</span>
                )}
              </label>
              <input
                aria-label="Email Address"
                type="email"
                disabled={!isAuthenticated}
                readOnly={!isAuthenticated}
                value={profileEmail}
                onChange={(e) => setProfileEmail(e.target.value)}
                placeholder={!isAuthenticated ? "Sign in to customize and link your profile." : "e.g. alex@example.com"}
                className={`w-full border rounded-xl px-3.5 py-2 text-xs font-mono outline-none transition-colors ${
                  !isAuthenticated
                    ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed'
                    : 'bg-[#141414] border-white/10 text-white focus:border-white/30 focus-visible:ring-1 focus-visible:ring-emerald-500'
                }`}
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] font-mono font-bold text-[#A1A1AA] uppercase flex items-center justify-between">
                <span>Avatar Image URL (GitHub or Custom URL)</span>
                {!isAuthenticated && (
                  <span className="text-[10px] text-amber-400 font-mono font-normal">Sign in to customize</span>
                )}
              </label>
              <div className="flex gap-2">
                <input
                  aria-label="Avatar Image URL"
                  type="text"
                  disabled={!isAuthenticated}
                  readOnly={!isAuthenticated}
                  value={profileAvatarUrl}
                  onChange={(e) => setProfileAvatarUrl(e.target.value)}
                  placeholder={!isAuthenticated ? "Sign in to customize and link your profile." : "https://github.com/username.png"}
                  className={`flex-1 border rounded-xl px-3.5 py-2 text-xs font-mono outline-none transition-colors ${
                    !isAuthenticated
                      ? 'bg-[#0A0A0A] border-white/5 text-[#71717A] cursor-not-allowed'
                      : 'bg-[#141414] border-white/10 text-white focus:border-white/30 focus-visible:ring-1 focus-visible:ring-emerald-500'
                  }`}
                />
                <button
                  type="button"
                  disabled={!isAuthenticated}
                  onClick={() => {
                    if (!isAuthenticated) return;
                    const handle = profileName.trim().replace(/\s+/g, '') || 'github';
                    setProfileAvatarUrl(`https://github.com/${handle}.png`);
                  }}
                  className={`px-3 py-2 border rounded-xl text-[11px] font-mono transition-colors whitespace-nowrap ${
                    !isAuthenticated
                      ? 'bg-white/5 border-white/5 text-[#71717A] cursor-not-allowed'
                      : 'bg-white/5 hover:bg-white/10 border-white/10 text-[#A1A1AA] hover:text-white cursor-pointer'
                  }`}
                  title={!isAuthenticated ? "Sign in to customize avatar" : "Use GitHub avatar"}
                >
                  GitHub
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={!isAuthenticated}
              className={`mt-1 min-h-[44px] px-4 py-2 rounded-xl font-bold text-xs flex items-center justify-center gap-2 shadow-md self-end transition-all ${
                !isAuthenticated
                  ? 'bg-white/5 border border-white/10 text-[#71717A] cursor-not-allowed'
                  : 'bg-white text-black hover:bg-neutral-200 cursor-pointer'
              }`}
            >
              {profileSaved ? <Check size={14} /> : <Save size={14} />}
              <span>
                {!isAuthenticated ? 'Sign In to Save Profile' : profileSaved ? 'Profile Saved' : 'Save Profile'}
              </span>
            </button>
          </form>
        </div>

        {/* License Key Activation Banner */}
        <div className="pt-4 border-t border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-[#0A0A0A] p-4 rounded-xl border border-white/10">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 text-white flex items-center justify-center shrink-0 mt-0.5">
              <Key size={16} />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                Have an Enterprise or Pro License Key?
              </h3>
              <p className="text-[11px] text-[#A1A1AA] mt-0.5">
                Paste your license key to immediately unlock advanced rules and multi-team gate clearance.
              </p>
              {licenseFeedback.status !== 'idle' && (
                <div className={`text-[11px] font-mono mt-1.5 flex items-center gap-1.5 ${licenseFeedback.status === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {licenseFeedback.status === 'success' ? <Check size={12} /> : <AlertTriangle size={12} />}
                  <span>{licenseFeedback.message}</span>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <input
              aria-label="License Key Input"
              type="text"
              placeholder="SG-PRO-2026-..."
              value={licenseInput}
              onChange={(e) => setLicenseInput(e.target.value)}
              className="bg-[#141414] border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none focus:border-white/30 focus-visible:ring-1 focus-visible:ring-emerald-500 uppercase flex-1 md:w-60"
            />
            <button
              type="button"
              onClick={handleActivateLicense}
              className="btn btn-secondary px-4 py-2 rounded-xl text-xs font-mono font-bold whitespace-nowrap bg-white text-black hover:bg-neutral-200 transition-all cursor-pointer"
            >
              Activate
            </button>
          </div>
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
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
            <input
              aria-label="GitHub Personal Access Token"
              type={showPatToken ? 'text' : 'password'}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              value={patToken}
              onChange={(e) => setPatToken(e.target.value)}
              className="w-full bg-transparent py-1.5 text-xs text-[#EDEDED] font-mono focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowPatToken(!showPatToken)}
              aria-label={showPatToken ? 'Hide PAT token' : 'Show PAT token'}
              className="text-[#A1A1AA] hover:text-white transition-colors p-1 shrink-0"
            >
              {showPatToken ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </div>

        <div className="flex items-center justify-between pt-4 border-t border-white/10 flex-wrap gap-3">
          <div className="text-xs text-[#A1A1AA] font-mono">
            {saved ? '✓ Settings successfully saved to local project state.' : 'Changes take effect immediately on next audit run.'}
          </div>

          <button
            type="submit"
            disabled={saved}
            className="btn btn-primary min-h-[44px] px-6 py-2.5 text-xs font-bold uppercase tracking-wider rounded-xl flex items-center justify-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50"
          >
            {saved ? <CheckCircle2 size={15} /> : <Save size={15} />}
            <span>{saved ? 'Saved!' : 'Save Settings'}</span>
          </button>
        </div>
      </form>

      {/* Danger Zone: GDPR  Cascade Account Deletion */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6 sm:p-8 bg-[#180a0a]/60 border border-red-500/30 rounded-2xl flex flex-col gap-6 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap sm:flex-nowrap">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 flex items-center justify-center shrink-0 mt-0.5">
              <AlertTriangle size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-extrabold text-white">
                  {!isAuthenticated
                    ? 'Danger Zone: Clear Local Browser Cache & Scans'
                    : 'Danger Zone: GDPR  Data Erasure'}
                </h2>
                <span className="text-[0.65rem] font-extrabold uppercase tracking-wider bg-red-500/20 border border-red-500/40 text-red-300 px-2 py-0.5 rounded-full">
                  Irreversible
                </span>
              </div>
              <p className="text-xs text-[#CBD5E1] mt-1.5 leading-relaxed max-w-2xl">
                {isAuthenticated
                  ? 'Exercise your Right to Erasure (GDPR Article 17 / CCPA). Permanently destroy your account, wipe all registered repository audits, flush cached vulnerability findings, purge personal access credentials, and wipe local storage states.'
                  : 'Exercise your Right to Erasure (GDPR Article 17 / CCPA). As an unauthenticated guest, this action clears your local browser cache, registered repository audits, and scan history stored on this device.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {isAuthenticated && (
              <button
                type="button"
                onClick={handleExportData}
                disabled={isExporting}
                className="min-h-[44px] px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white text-xs font-bold flex items-center justify-center gap-2 transition-colors shrink-0 cursor-pointer"
              >
                <Save size={14} />
                <span>{isExporting ? 'Exporting...' : 'Export Data (GDPR Art. 20)'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setConfirmationInput('');
                setHasConfirmedCheckbox(false);
                setPurgeSuccess(false);
                setIsDeleteModalOpen(true);
              }}
              className="min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 hover:text-red-100 text-xs font-bold flex items-center justify-center gap-2 transition-colors shrink-0 cursor-pointer"
            >
              <Trash2 size={15} />
              <span>{isAuthenticated ? 'Delete Account & Wipe Data' : 'Clear Local Cache & Wipe Scans'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* GDPR  Deletion Confirmation Modal */}
      <AnimatePresence>
        {isDeleteModalOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-3 sm:p-4 min-h-[100dvh]"
            role="dialog"
            aria-modal="true"
            aria-labelledby="gdpr-delete-modal-title"
            onClick={(e) => { if (e.target === e.currentTarget) setIsDeleteModalOpen(false); }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="w-full max-w-lg max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-red-500/30 rounded-2xl p-5 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
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
                    {isAuthenticated ? 'Data Purged Successfully' : 'Local Cache & Scans Cleared'}
                  </h3>
                  <p className="text-xs text-[#A1A1AA] max-w-sm">
                    {isAuthenticated
                      ? 'All account records, audits, tokens, and local cache have been erased in compliance with GDPR Art. 17 / CCPA. Redirecting to home...'
                      : 'All local scan data, cached repositories, and browser storage have been wiped. Redirecting to home...'}
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
                        {!isAuthenticated
                          ? 'Confirm Local Cache & Scan History Erasure'
                          : 'Confirm Permanent Account & Data Erasure'}
                      </h3>
                      <p className="text-xs text-[#A1A1AA]">
                        {!isAuthenticated
                          ? 'Wipes local browser storage & scan history on this machine'
                          : 'GDPR Article 17 / CCPA Right to Erasure'}
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
                      {!isAuthenticated ? (
                        <>
                          <li>Guest mode session and local browser cache (<code className="text-red-300">zelsis_*</code>).</li>
                          <li>Locally saved project scans and vulnerability findings history on this device.</li>
                          <li>Temporary repository target configurations and local license state.</li>
                          <li>Note: No cloud account credentials exist to purge in Guest Mode.</li>
                        </>
                      ) : (
                        <>
                          <li>Active user profile, authenticated session tokens, and billing records.</li>
                          <li>All registered project repositories and custom scan settings.</li>
                          <li>Historical audit reports, gate matrices, and remediation logs.</li>
                          <li>Stored GitHub Personal Access Tokens (PAT) and webhook credentials.</li>
                          <li>Local browser database and storage caches (<code className="text-red-300">zelsis_*</code>).</li>
                        </>
                      )}
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
                        {!isAuthenticated
                          ? 'I acknowledge this action will permanently clear all local project scans and browser cache on this machine.'
                          : 'I acknowledge this action is irreversible and request the permanent deletion of my account and all associated telemetry.'}
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
                          <span>{!isAuthenticated ? 'Permanently Wipe Local Data' : 'Permanently Delete & Wipe'}</span>
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
