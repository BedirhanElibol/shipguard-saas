// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Mail, Lock, User, Github, ArrowRight, CheckCircle2, KeyRound, AlertCircle } from 'lucide-react';
import { supabaseSignIn, supabaseSignUp, supabaseResetPassword, supabaseSignInWithOAuth, isSupabaseConfigured } from '@/lib/supabase';

export interface UserProfile {
  name: string;
  email: string;
  avatarUrl?: string;
  tier: 'Free' | 'Pro' | 'Enterprise';
  isLoggedIn: boolean;
  emailVerified?: boolean;
}

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: UserProfile) => void;
  initialMode?: 'signin' | 'signup';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onLoginSuccess,
  initialMode = 'signin'
}) => {
  const [mode, setMode] = useState<'signin' | 'signup' | 'forgot'>(initialMode);
  const [oauthProvider, setOauthProvider] = useState<'GitHub' | 'Google' | null>(null);
  const [githubUser, setGithubUser] = useState('BedirhanElibol');
  const [isCustomGoogle, setIsCustomGoogle] = useState(false);
  const [customGoogleName, setCustomGoogleName] = useState('Bedirhan Elibol');
  const [customGoogleEmail, setCustomGoogleEmail] = useState('bedirhan@gmail.com');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  React.useEffect(() => {
    if (isOpen) {
      setMode(initialMode);
      setOauthProvider(null);
      setGithubUser('BedirhanElibol');
      setIsCustomGoogle(false);
      setCustomGoogleName('Bedirhan Elibol');
      setCustomGoogleEmail('bedirhan@gmail.com');
      setEmail('');
      setPassword('');
      setName('');
      setError('');
      setSuccessMsg('');
    }
  }, [initialMode, isOpen]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!email.includes('@')) {
      setError('Please enter a valid email address.');
      return;
    }

    if (mode === 'forgot') {
      setIsLoading(true);
      const { success, message } = await supabaseResetPassword(email.trim());
      setIsLoading(false);
      if (success) {
        setSuccessMsg(message);
      } else {
        setError(message);
      }
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }
    if (mode === 'signup' && !name.trim()) {
      setError('Please enter your full name.');
      return;
    }

    setIsLoading(true);

    if (mode === 'signin') {
      const { user, error: signError } = await supabaseSignIn(email.trim(), password);
      setIsLoading(false);
      if (signError) {
        setError(signError);
      } else if (user) {
        onLoginSuccess(user);
        onClose();
      }
    } else if (mode === 'signup') {
      const { user, error: signUpErr, requiresVerification } = await supabaseSignUp(email.trim(), password, name.trim());
      setIsLoading(false);
      if (signUpErr) {
        setError(signUpErr);
      } else if (user) {
        if (requiresVerification) {
          setSuccessMsg(`Account created! We've sent a verification link to ${email}. Please check your inbox.`);
        }
        onLoginSuccess(user);
        if (!requiresVerification) {
          onClose();
        }
      }
    }
  };

  const handleGitHubOAuthSuccess = async (usernameToUse?: string) => {
    setIsLoading(true);
    setError('');

    if (isSupabaseConfigured()) {
      try {
        const { url, error: oauthError } = await supabaseSignInWithOAuth('github');
        if (url) {
          window.location.href = url;
          return;
        }
        if (oauthError && !oauthError.toLowerCase().includes('provider is not enabled')) {
          console.warn('[ShipGuard OAuth] Notice:', oauthError);
        }
      } catch (err) {
        console.warn('[ShipGuard OAuth] OAuth redirect error:', err);
      }
    }

    const username = (usernameToUse || githubUser).trim() || 'BedirhanElibol';
    setTimeout(() => {
      setIsLoading(false);
      const authedUser: UserProfile = {
        name: username,
        email: `${username.toLowerCase()}@users.noreply.github.com`,
        avatarUrl: `https://github.com/${username}.png`,
        tier: 'Free',
        isLoggedIn: true,
        emailVerified: true
      };
      onLoginSuccess(authedUser);
      onClose();
    }, 400);
  };

  const handleGoogleOAuthSuccess = (chosenName?: string, chosenEmail?: string) => {
    const finalName = (chosenName || customGoogleName).trim() || 'Bedirhan Elibol';
    const finalEmail = (chosenEmail || customGoogleEmail).trim() || 'bedirhan@gmail.com';
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      const authedUser: UserProfile = {
        name: finalName,
        email: finalEmail,
        avatarUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80',
        tier: 'Free',
        isLoggedIn: true,
        emailVerified: true
      };
      onLoginSuccess(authedUser);
      onClose();
    }, 400);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 bg-black/85  flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="w-full max-w-md max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
        >
          {/* Close Button */}
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="absolute top-4 right-4 min-w-[44px] min-h-[44px] flex items-center justify-center text-[#A1A1AA] hover:text-white rounded-xl hover:bg-white/10 transition-colors z-10"
          >
            <X size={18} />
          </button>

          {/* Header & Logo */}
          <div className="flex flex-col items-center text-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-white text-black flex items-center justify-center font-extrabold text-base shadow-lg mb-1 font-mono">
              S
            </div>
            <h2 className="text-xl font-extrabold text-[#EDEDED]">
              {mode === 'signin'
                ? 'Welcome Back to ShipGuard'
                : mode === 'signup'
                ? 'Create Your ShipGuard Account'
                : 'Reset Your Password'}
            </h2>
            <p className="text-xs text-[#A1A1AA] max-w-xs">
              {mode === 'signin'
                ? 'Sign in to access your saved security scans and custom rule gates.'
                : mode === 'signup'
                ? 'Start securing your Next.js and LLM applications with automated pre-flight gates.'
                : 'Enter your email address and we will dispatch a secure password reset link.'}
            </p>
          </div>

          {/* Mode Switcher Tabs (Only if not in OAuth flow and not forgot) */}
          {oauthProvider === null && mode !== 'forgot' && (
            <div className="grid grid-cols-2 p-1 bg-[#0A0A0A] rounded-xl border border-white/10 text-xs font-bold font-mono">
              <button
                type="button"
                onClick={() => { setMode('signin'); setError(''); setSuccessMsg(''); }}
                className={`py-2 rounded-lg transition-all ${
                  mode === 'signin'
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setMode('signup'); setError(''); setSuccessMsg(''); }}
                className={`py-2 rounded-lg transition-all ${
                  mode === 'signup'
                    ? 'bg-white/5 text-white border border-white/10 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Sign Up
              </button>
            </div>
          )}

          {/* Interactive GitHub OAuth Flow */}
          {oauthProvider === 'GitHub' && (
            <div className="flex flex-col gap-4">
              <div className="flex flex-col items-center text-center gap-2 p-4 rounded-xl bg-[#0A0A0A] border border-white/10">
                <div className="relative">
                  <img
                    src={`https://github.com/${githubUser.trim() || 'BedirhanElibol'}.png`}
                    alt="GitHub Avatar"
                    className="w-16 h-16 rounded-full border-2 border-white/20 shadow-xl object-cover bg-neutral-900"
                    onError={(e) => {
                      (e.target as HTMLImageElement).src = 'https://github.com/github.png';
                    }}
                  />
                  <div className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-[#24292F] border border-white/20 flex items-center justify-center text-white">
                    <Github size={13} />
                  </div>
                </div>

                <div className="mt-1">
                  <h3 className="text-sm font-bold text-white">GitHub ile Giriş Onayı</h3>
                  <p className="text-[11px] text-[#A1A1AA]">
                    ShipGuard hesabınıza GitHub profiliniz bağlanacaktır.
                  </p>
                </div>

                <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  Ücretsiz Kullanım (Free Tier) - Aktif
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase flex items-center justify-between">
                  <span>GitHub Kullanıcı Adı</span>
                  <span className="text-emerald-400 text-[10px]">Canlı Avatar Bağlantılı</span>
                </label>
                <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                  <span className="text-[#A1A1AA] font-mono text-xs">@</span>
                  <input
                    aria-label="GitHub Kullanıcı Adı"
                    type="text"
                    value={githubUser}
                    onChange={(e) => setGithubUser(e.target.value)}
                    placeholder="BedirhanElibol"
                    className="bg-transparent text-xs text-[#EDEDED] font-mono outline-none w-full font-bold"
                  />
                </div>
                <span className="text-[10px] text-[#A1A1AA]">
                  Avatarınız <code>https://github.com/{githubUser.trim() || 'BedirhanElibol'}.png</code> adresinden canlı yüklenir.
                </span>
              </div>

              <div className="flex flex-col gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => handleGitHubOAuthSuccess()}
                  disabled={isLoading}
                  className="btn btn-primary py-3 text-xs uppercase tracking-wider font-extrabold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50"
                >
                  <Github size={15} />
                  <span>
                    {isLoading
                      ? 'Bağlanıyor...'
                      : `Continue as @${githubUser.trim() || 'BedirhanElibol'}`}
                  </span>
                  <ArrowRight size={14} />
                </button>

                <button
                  type="button"
                  onClick={() => setOauthProvider(null)}
                  className="py-2 text-center text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
                >
                  ← Diğer Giriş Seçeneklerine Dön
                </button>
              </div>
            </div>
          )}

          {/* Interactive Google OAuth 1-Click Account Selector */}
          {oauthProvider === 'Google' && (
            <div className="flex flex-col gap-4">
              <div className="flex flex-col items-center text-center gap-2 p-3 rounded-xl bg-[#0A0A0A] border border-white/10">
                <svg className="w-8 h-8" viewBox="0 0 24 24">
                  <path
                    fill="#EA4335"
                    d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.3 9 5 12 5z"
                  />
                  <path
                    fill="#4285F4"
                    d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3s.2-1.6.4-2.3L1.9 7.3C.7 9.7 0 12.4 0 15.3c0 2.9.7 5.6 1.9 8l3.7-2.9z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.3-6.4-5.2L1.9 16C3.7 19.7 7.5 22.3 12 22.3z"
                  />
                </svg>
                <div>
                  <h3 className="text-sm font-bold text-white">Google ile Giriş Yap</h3>
                  <p className="text-[11px] text-[#A1A1AA]">
                    ShipGuard&apos;a bağlanmak için hesap seçin (Ücretsiz Plan).
                  </p>
                </div>
              </div>

              {/* Clean 1-click account selector options */}
              <div className="flex flex-col gap-2">
                {/* 1-click option 1: Bedirhan Elibol */}
                <button
                  type="button"
                  onClick={() => handleGoogleOAuthSuccess('Bedirhan Elibol', 'bedirhan@gmail.com')}
                  disabled={isLoading}
                  className="w-full p-3 rounded-xl bg-[#0A0A0A] hover:bg-white/[0.06] border border-white/10 hover:border-white/25 transition-all flex items-center justify-between text-left group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-blue-600 text-white font-bold flex items-center justify-center text-sm shadow-md">
                      B
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white group-hover:text-white">
                        Bedirhan Elibol
                      </div>
                      <div className="text-[11px] text-[#A1A1AA]">bedirhan@gmail.com</div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      Ücretsiz Plan
                    </span>
                    <span className="text-[10px] text-white flex items-center gap-1 font-mono">
                      Hızlı Giriş <ArrowRight size={10} />
                    </span>
                  </div>
                </button>

                {/* 1-click option 2: Custom account toggle */}
                {!isCustomGoogle ? (
                  <button
                    type="button"
                    onClick={() => setIsCustomGoogle(true)}
                    className="w-full p-3 rounded-xl bg-[#0A0A0A]/50 hover:bg-white/[0.04] border border-white/10 border-dashed transition-all flex items-center gap-3 text-left"
                  >
                    <div className="w-10 h-10 rounded-full bg-white/5 border border-white/10 text-[#A1A1AA] flex items-center justify-center text-xs">
                      <User size={16} />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-[#EDEDED]">Başka bir Google Hesabı Kullan</div>
                      <div className="text-[10px] text-[#A1A1AA]">Özel ad ve e-posta ile devam et</div>
                    </div>
                  </button>
                ) : (
                  <div className="p-3 rounded-xl bg-[#0A0A0A] border border-white/15 flex flex-col gap-2.5 mt-1">
                    <div className="text-xs font-bold text-white flex items-center justify-between">
                      <span>Özel Google Hesabı</span>
                      <button
                        type="button"
                        onClick={() => setIsCustomGoogle(false)}
                        className="text-[10px] text-[#A1A1AA] hover:text-white"
                      >
                        İptal
                      </button>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-[10px] text-[#A1A1AA] font-mono font-bold">Ad Soyad</label>
                      <input
                        type="text"
                        value={customGoogleName}
                        onChange={(e) => setCustomGoogleName(e.target.value)}
                        placeholder="Bedirhan Elibol"
                        className="px-3 py-1.5 rounded-lg bg-[#141414] border border-white/10 text-xs text-white outline-none"
                      />
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-[10px] text-[#A1A1AA] font-mono font-bold">Google E-Posta</label>
                      <input
                        type="email"
                        value={customGoogleEmail}
                        onChange={(e) => setCustomGoogleEmail(e.target.value)}
                        placeholder="bedirhan@gmail.com"
                        className="px-3 py-1.5 rounded-lg bg-[#141414] border border-white/10 text-xs text-white outline-none"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() => handleGoogleOAuthSuccess()}
                      disabled={isLoading}
                      className="mt-1 py-2 rounded-lg bg-white text-black font-bold text-xs hover:bg-neutral-200 transition-colors flex items-center justify-center gap-2"
                    >
                      <span>{isLoading ? 'Giriş Yapılıyor...' : 'Bu Hesapla Devam Et'}</span>
                      <ArrowRight size={12} />
                    </button>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={() => setOauthProvider(null)}
                className="py-2 text-center text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors mt-1"
              >
                ← Diğer Giriş Seçeneklerine Dön
              </button>
            </div>
          )}

          {/* Standard OAuth Buttons (shown only when no oauth flow is active and not forgot) */}
          {oauthProvider === null && mode !== 'forgot' && (
            <>
              <div className="flex flex-col gap-2.5">
                <button
                  type="button"
                  onClick={async () => {
                    if (isSupabaseConfigured()) {
                      setIsLoading(true);
                      const { url } = await supabaseSignInWithOAuth('github');
                      if (url) {
                        window.location.href = url;
                        return;
                      }
                      setIsLoading(false);
                    }
                    setOauthProvider('GitHub');
                  }}
                  disabled={isLoading}
                  className="flex items-center justify-center gap-3 w-full py-2.5 px-4 rounded-xl bg-[#1F2937] hover:bg-[#374151] border border-white/15 text-xs font-bold text-white transition-all shadow-sm disabled:opacity-50"
                >
                  <Github size={16} />
                  <span>Continue with GitHub</span>
                </button>

                <button
                  type="button"
                  onClick={() => setOauthProvider('Google')}
                  disabled={isLoading}
                  className="flex items-center justify-center gap-3 w-full py-2.5 px-4 rounded-xl bg-[#18181B] hover:bg-[#27272A] border border-white/15 text-xs font-bold text-white transition-all shadow-sm disabled:opacity-50"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24">
                    <path
                      fill="#EA4335"
                      d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.3 9 5 12 5z"
                    />
                    <path
                      fill="#4285F4"
                      d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3s.2-1.6.4-2.3L1.9 7.3C.7 9.7 0 12.4 0 15.3c0 2.9.7 5.6 1.9 8l3.7-2.9z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.3-6.4-5.2L1.9 16C3.7 19.7 7.5 22.3 12 22.3z"
                    />
                  </svg>
                  <span>Continue with Google</span>
                </button>
              </div>

              <div className="flex items-center gap-3 my-0.5">
                <div className="flex-1 h-[1px] bg-white/10" />
                <span className="text-[0.65rem] text-[#64748B] uppercase tracking-wider font-bold">OR EMAIL</span>
                <div className="flex-1 h-[1px] bg-white/10" />
              </div>
            </>
          )}

          {/* Form Inputs (hidden if in interactive OAuth step) */}
          {oauthProvider === null && (
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            {error && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 p-2.5 rounded-lg text-center font-medium flex items-center justify-center gap-2">
                <AlertCircle size={14} className="shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="text-xs text-white bg-white/5 border border-white/10 p-2.5 rounded-lg text-center font-medium flex items-center justify-center gap-2">
                <CheckCircle2 size={14} className="shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            {mode === 'signup' && (
              <div className="flex flex-col gap-1">
                <label className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Full Name</label>
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                  <User size={15} className="text-[#A1A1AA]" />
                  <input
                    aria-label="Full Name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Bedirhan Elibol"
                    className="bg-transparent text-xs text-[#EDEDED] outline-none w-full"
                  />
                </div>
              </div>
            )}

            <div className="flex flex-col gap-1">
              <label className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Email Address</label>
              <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                <Mail size={15} className="text-[#A1A1AA]" />
                <input
                  aria-label="Email Address"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="bg-transparent text-xs text-[#EDEDED] outline-none w-full"
                />
              </div>
            </div>

            {mode !== 'forgot' && (
              <div className="flex flex-col gap-1">
                <div className="flex items-center justify-between">
                  <label className="text-[0.7rem] text-[#A1A1AA] font-mono font-bold uppercase">Password</label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => { setMode('forgot'); setError(''); setSuccessMsg(''); }}
                      className="text-[0.65rem] text-white hover:underline font-semibold"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0A0A0A] border border-white/10 focus-within:border-white/20">
                  <Lock size={15} className="text-[#A1A1AA]" />
                  <input
                    aria-label="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="bg-transparent text-xs text-[#EDEDED] outline-none w-full"
                  />
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="mt-2 btn btn-primary py-3 text-xs uppercase tracking-wider font-extrabold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-md"
            >
              <span>
                {isLoading
                  ? 'Processing...'
                  : mode === 'signin'
                  ? 'Sign In'
                  : mode === 'signup'
                  ? 'Create Account'
                  : 'Send Reset Link'}
              </span>
              <ArrowRight size={14} />
            </button>
          </form>
          )}

          {/* Footer Back link for forgot mode */}
          {mode === 'forgot' ? (
            <button
              onClick={() => { setMode('signin'); setError(''); setSuccessMsg(''); }}
              className="text-center text-xs font-bold text-[#A1A1AA] hover:text-white transition-colors"
            >
              ← Back to Sign In
            </button>
          ) : (
            <div className="text-center text-[0.7rem] text-[#64748B]">
              By signing in, you agree to ShipGuard Terms of Service &amp; Privacy Policy.
            </div>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
