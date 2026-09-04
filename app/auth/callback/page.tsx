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
  const [message, setMessage] = useState<string>('GitHub kimliği doğrulanıyor...');

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
          setMessage('Supabase bağlantısı henüz yapılandırılmamış.');
        }
        return;
      }

      try {
        const code = searchParams.get('code');
        if (code) {
          setMessage('Yetkilendirme kodu doğrulanıyor...');
          const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);
          if (exchangeError) {
            console.warn('[ShipGuard OAuth] Code exchange warning:', exchangeError.message);
          }
        }

        const { data: { session }, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw sessionError;

        if (session && session.user) {
          const profile = mapSupabaseUserToProfile(session.user);
          localStorage.setItem('shipguard_user', JSON.stringify(profile));

          if (isMounted) {
            setStatus('success');
            setMessage(`Hoş geldiniz, @${profile.name}! Dashboard'a yönlendiriliyorsunuz...`);
          }

          setTimeout(() => {
            router.push('/dashboard');
          }, 800);
        } else {
          const { data: { subscription } } = supabase.auth.onAuthStateChange((event, newSession) => {
            if (newSession && newSession.user && isMounted) {
              const profile = mapSupabaseUserToProfile(newSession.user);
              localStorage.setItem('shipguard_user', JSON.stringify(profile));
              setStatus('success');
              setMessage('Giriş başarılı! Yönlendiriliyorsunuz...');
              subscription.unsubscribe();
              setTimeout(() => {
                router.push('/dashboard');
              }, 800);
            }
          });

          setTimeout(() => {
            if (isMounted && status === 'loading') {
              setStatus('error');
              setMessage('Oturum süresi doldu veya GitHub yetkilendirmesi tamamlanamadı.');
            }
          }, 6000);
        }
      } catch (err: any) {
        console.error('[ShipGuard OAuth] Callback error:', err);
        if (isMounted) {
          setStatus('error');
          setMessage(err?.message || 'Kimlik doğrulama sırasında beklenmeyen bir hata oluştu.');
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
        <span className="text-sm font-mono uppercase tracking-widest text-neutral-400">ShipGuard Auth</span>
      </div>

      <h1 className="text-xl font-bold text-white mb-2">
        {status === 'loading' && 'GitHub ile Giriş Yapılıyor'}
        {status === 'success' && 'Oturum Başarıyla Açıldı'}
        {status === 'error' && 'Yetkilendirme Başarısız'}
      </h1>

      <p className="text-sm text-neutral-400 mb-6 font-mono leading-relaxed">{message}</p>

      {status === 'error' && (
        <div className="space-y-3">
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-xl bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white text-sm font-medium transition-colors"
          >
            Dashboard'a Dön <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/"
            className="inline-block text-xs text-neutral-500 hover:text-neutral-400 underline underline-offset-4"
          >
            Ana Sayfaya Git
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
            <p className="text-sm text-neutral-400 font-mono">Yükleniyor...</p>
          </div>
        }
      >
        <CallbackHandler />
      </Suspense>
    </main>
  );
}
