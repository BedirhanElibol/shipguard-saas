'use client';

import React, { Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { AppShell } from '@/components/layout/AppShell';
import { CheckoutView } from '@/components/checkout/CheckoutView';
import { MOCK_PROJECTS } from '@/data/mockData';

function CheckoutPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const planId = searchParams.get('plan') || 'shipguard-core';
  const billing = (searchParams.get('billing') || 'annual') as 'annual' | 'monthly';

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
    >
      <CheckoutView
        initialPlanId={planId}
        initialBilling={billing}
        onBackToPricing={() => router.push('/#pricing')}
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
