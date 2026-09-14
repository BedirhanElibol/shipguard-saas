'use client';

import React from 'react';
import { PricingSection } from '@/components/ui/pricing';
import { useRouter } from 'next/navigation';

export const PricingView: React.FC = () => {
  const router = useRouter();

  const handleSelectPlan = (planId: string, isAnnual: boolean) => {
    const billingParam = isAnnual ? 'annual' : 'monthly';
    router.push(`/checkout?plan=${planId}&billing=${billingParam}`);
  };

  return (
    <PricingSection onSelectPlan={handleSelectPlan} />
  );
};
