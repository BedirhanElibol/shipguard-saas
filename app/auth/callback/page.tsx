'use client';

import React, { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { getSupabase, mapSupabaseUserToProfile } from '@/lib/supabase';
import { Shield, Loader2, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

function CallbackHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState<string>('Verifying authentication credentials...');

  useEffect(() => {
    let isMounted = true;

    async function processAuth() {
      const errorParam = searchParams.get('error') || searchParams.get('error_description');
      if (errorParam) {
        if (isMounted) {
          setStatus('error');
          setMessage(decodeURIComponent(errorParam));
        }
        return;
      }

      const supabase = getSupabase();
      if (!supabase) {
        if (isMounted) {
          setStatus('error');
          setMessage('Supabase connection is not configured yet.');
        }
        return;
      }

      try {
        const code = searchParams.get('code');
        if (code) {
          setMessage('Verifying authorization code...');
          const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);
          if (exchangeError) {
            console.warn('[Zelsis OAuth] Code exchange warning:', exchangeError.message);
          }
        }

        const { data: { session }, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw sessionError;

        if (session && session.user) {
          const profile = mapSupabaseUserToProfile(session.user);
          localStorage.setItem('zelsis_user', JSON.stringify(profile));
          localStorage.setItem('shipguard_user', JSON.stringify(profile));
          if (typeof document !== 'undefined') {
            document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(profile))}; path=/; max-age=2592000; SameSite=Lax`;
            document.cookie = `shipguard_user=${encodeURIComponent(JSON.stringify(profile))}; path=/; max-age=2592000; SameSite=Lax`;
          }

          if (isMounted) {
            setStatus('success');
            setMessage(`Welcome, @${profile.name}! Redirecting to dashboard...`);
          }

          setTimeout(() => {
            router.push('/dashboard');
          }, 800);
        } else {
          const { data: { subscription } } = supabase.auth.onAuthStateChange((event, newSession) => {
            if (newSession && newSession.user && isMounted) {
              const profile = mapSupabaseUserToProfile(newSession.user);
              localStorage.setItem('zelsis_user', JSON.stringify(profile));
              localStorage.setItem('shipguard_user', JSON.stringify(profile));
              if (typeof document !== 'undefined') {
                document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(profile))}; path=/; max-age=2592000; SameSite=Lax`;
                document.cookie = `shipguard_user=${encodeURIComponent(JSON.stringify(profile))}; path=/; max-age=2592000; SameSite=Lax`;
              }
              setStatus('success');
              setMessage('Sign in successful! Redirecting...');
              subscription.unsubscribe();
              setTimeout(() => {
                router.push('/dashboard');
              }, 800);
            }
          });

          setTimeout(() => {
            if (isMounted && status === 'loading') {
              setStatus('error');
              setMessage('Session timed out or authorization could not be completed.');
            }
          }, 6000);
        }
      } catch (err: any) {
        console.error('[Zelsis OAuth] Callback error:', err);
        if (isMounted) {
          setStatus('error');
          setMessage(err?.message || 'An unexpected error occurred during authentication.');
        }
      }
    }

    processAuth();

    return () => {
      isMounted = false;
    };
  }, [router, searchParams, status]);

  return (
    <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl backdrop-blur-xl text-center">
      <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-neutral-800/80 border border-neutral-700 flex items-center justify-center">
        {status === 'loading' && <Loader2 className="w-8 h-8 text-emerald-400 animate-spin" />}
        {status === 'success' && <CheckCircle2 className="w-8 h-8 text-emerald-400" />}
        {status === 'error' && <AlertTriangle className="w-8 h-8 text-amber-400" />}
      </div>

      <div className="flex items-center justify-center gap-2 mb-3">
        <Shield className="w-5 h-5 text-emerald-400" />
        <span className="text-sm font-mono uppercase tracking-widest text-neutral-400">Zelsis Auth</span>
      </div>

      <h1 className="text-xl font-bold text-white mb-2">
        {status === 'loading' && 'Signing in with GitHub'}
        {status === 'success' && 'Signed in Successfully'}
        {status === 'error' && 'Authentication Failed'}
      </h1>

      <p className="text-sm text-neutral-400 mb-6 font-mono leading-relaxed">{message}</p>

      {status === 'error' && (
        <div className="space-y-3">
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-xl bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white text-sm font-medium transition-colors"
          >
            Return to Dashboard <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/"
            className="inline-block text-xs text-neutral-500 hover:text-neutral-400 underline underline-offset-4"
          >
            Go to Homepage
          </Link>
        </div>
      )}
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <main className="min-h-screen bg-neutral-950 flex flex-col items-center justify-center px-4">
      <Suspense
        fallback={
          <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-2xl p-8 text-center">
            <Loader2 className="w-8 h-8 text-emerald-400 animate-spin mx-auto mb-4" />
            <p className="text-sm text-neutral-400 font-mono">Loading...</p>
          </div>
        }
      >
        <CallbackHandler />
      </Suspense>
    </main>
  );
}
