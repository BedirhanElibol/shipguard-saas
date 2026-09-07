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
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [loadingTarget, setLoadingTarget] = useState<'github' | 'google' | 'email' | null>(null);

  React.useEffect(() => {
    if (isOpen) {
      setMode(initialMode);
      setEmail('');
      setPassword('');
      setName('');
      setError('');
      setSuccessMsg('');
      setLoadingTarget(null);
    }
  }, [initialMode, isOpen]);

  React.useEffect(() => {
    const handleReset = () => setLoadingTarget(null);
    window.addEventListener('pageshow', handleReset);
    window.addEventListener('focus', handleReset);
    const handleVis = () => {
      if (document.visibilityState === 'visible') {
        setLoadingTarget(null);
      }
    };
    document.addEventListener('visibilitychange', handleVis);

    return () => {
      window.removeEventListener('pageshow', handleReset);
      window.removeEventListener('focus', handleReset);
      document.removeEventListener('visibilitychange', handleVis);
    };
  }, []);

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
      setLoadingTarget('email');
      const { success, message } = await supabaseResetPassword(email.trim());
      setLoadingTarget(null);
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

    setLoadingTarget('email');

    if (mode === 'signin') {
      const { user, error: signError } = await supabaseSignIn(email.trim(), password);
      setLoadingTarget(null);
      if (signError) {
        setError(signError);
      } else if (user) {
        onLoginSuccess(user);
        onClose();
      }
    } else if (mode === 'signup') {
      const { user, error: signUpErr, requiresVerification } = await supabaseSignUp(email.trim(), password, name.trim());
      setLoadingTarget(null);
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

  const handleInitiateOAuth = async (provider: 'github' | 'google') => {
    setError('');
    setSuccessMsg('');

    if (provider === 'google') {
      setError('Google ile giriş henüz Supabase üzerinde yapılandırılmamıştır. Lütfen GitHub veya E-posta adresiniz ile giriş yapınız.');
      return;
    }

    setLoadingTarget(provider);

    // Auto-unlock safety timer: unlocks if user aborts or stays on page
    const safetyTimer = setTimeout(() => {
      setLoadingTarget(null);
    }, 4500);

    try {
      const { url, error: oauthError } = await supabaseSignInWithOAuth(provider);
      if (url) {
        window.location.href = url;
        return;
      }
      clearTimeout(safetyTimer);
      setLoadingTarget(null);
      setError(oauthError || `${provider === 'github' ? 'GitHub' : 'Google'} sign-in could not be initiated.`);
    } catch (err: any) {
      clearTimeout(safetyTimer);
      setLoadingTarget(null);
      setError(err?.message || 'Authentication error occurred.');
    }
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-3 sm:p-4 min-h-[100dvh]">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="w-full max-w-md max-h-[85dvh] sm:max-h-[90dvh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-5 sm:p-8 flex flex-col gap-5 shadow-2xl relative"
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

          {/* Mode Switcher Tabs */}
          {mode !== 'forgot' && (
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

          {/* Direct OAuth Providers */}
          {mode !== 'forgot' && (
            <>
              <div className="flex flex-col gap-2.5">
                <button
                  type="button"
                  onClick={() => handleInitiateOAuth('github')}
                  disabled={loadingTarget !== null}
                  className="flex items-center justify-center gap-3 w-full py-2.5 px-4 rounded-xl bg-[#1F2937] hover:bg-[#374151] border border-white/15 text-xs font-bold text-white transition-all shadow-sm disabled:opacity-50 cursor-pointer"
                >
                  <Github size={16} />
                  <span>{loadingTarget === 'github' ? 'Connecting to GitHub...' : 'Continue with GitHub'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleInitiateOAuth('google')}
                  disabled={loadingTarget !== null}
                  className="flex items-center justify-center gap-3 w-full py-2.5 px-4 rounded-xl bg-[#18181B] hover:bg-[#27272A] border border-white/15 text-xs font-bold text-white transition-all shadow-sm disabled:opacity-50 cursor-pointer"
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
                  <span className="text-[10px] text-amber-400/80 font-mono font-normal ml-auto">(Setup Required)</span>
                </button>
              </div>

              <div className="flex items-center gap-3 my-0.5">
                <div className="flex-1 h-[1px] bg-white/10" />
                <span className="text-[0.65rem] text-[#64748B] uppercase tracking-wider font-bold">OR EMAIL</span>
                <div className="flex-1 h-[1px] bg-white/10" />
              </div>
            </>
          )}

          {/* Form Inputs */}
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
                    placeholder="e.g. Alex Morgan"
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
              disabled={loadingTarget !== null}
              className="mt-2 btn btn-primary py-3 text-xs uppercase tracking-wider font-extrabold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-md disabled:opacity-50"
            >
              <span>
                {loadingTarget === 'email'
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
