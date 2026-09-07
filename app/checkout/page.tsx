'use client';

import React, { Suspense, useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { CheckoutView } from '@/components/checkout/CheckoutView';
import { MOCK_PROJECTS } from '@/data/mockData';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';

function CheckoutPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const planId = searchParams.get('plan') || 'shipguard-core';
  const billing = (searchParams.get('billing') || 'monthly') as 'annual' | 'monthly';
  const isSuccess = searchParams.get('success') === 'true';

  const [user, setUser] = useState<UserProfile | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>('signin');

  useEffect(() => {
    try {
      let savedUserStr = localStorage.getItem('shipguard_user');
      if (!savedUserStr && typeof document !== 'undefined') {
        const match = document.cookie.match(/(^|;)\s*shipguard_user=([^;]+)/);
        if (match && match[2]) {
          savedUserStr = decodeURIComponent(match[2]);
        }
      }
      if (savedUserStr) {
        const parsed = JSON.parse(savedUserStr);
        if (parsed && parsed.isLoggedIn) {
          setUser(parsed);
        }
      }
    } catch (e) {
      console.warn('[CheckoutPage] Failed to read user:', e);
    }
  }, []);

  return (
    <AppShell
      projects={MOCK_PROJECTS}
      activeNav="checkout"
      onNavigate={(nav) => {
        if (nav === 'dashboard') router.push('/dashboard');
        else router.push(`/dashboard?nav=${nav}`);
      }}
      selectedProject={MOCK_PROJECTS[0]}
      onSelectProject={() => {}}
      onTriggerScan={() => router.push('/dashboard?nav=scans')}
      onNavigateLanding={() => router.push('/')}
      user={user}
      onOpenAuth={(mode) => {
        setAuthInitialMode(mode);
        setIsAuthModalOpen(true);
      }}
      onSignOut={() => {
        setUser(null);
        try {
          localStorage.removeItem('shipguard_user');
          if (typeof document !== 'undefined') {
            document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
          }
        } catch (e) {}
      }}
    >
      <CheckoutView
        initialPlanId={planId}
        initialBilling={billing}
        initialSuccess={isSuccess}
        onBackToPricing={() => router.push('/#pricing')}
        user={user}
        onOpenAuth={(mode) => {
          setAuthInitialMode(mode || 'signup');
          setIsAuthModalOpen(true);
        }}
      />

      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        initialMode={authInitialMode}
        onLoginSuccess={(loggedUser) => {
          setUser(loggedUser);
          try {
            localStorage.setItem('shipguard_user', JSON.stringify(loggedUser));
            if (typeof document !== 'undefined') {
              document.cookie = `shipguard_user=${encodeURIComponent(JSON.stringify(loggedUser))}; path=/; max-age=2592000; SameSite=Lax`;
            }
          } catch (e) {}
          setIsAuthModalOpen(false);
        }}
      />
    </AppShell>
  );
}

export default function CheckoutPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-mono text-xs flex items-center justify-center">
        Loading ShipGuard B2B Checkout...
      </div>
    }>
      <CheckoutPageContent />
    </Suspense>
  );
}
