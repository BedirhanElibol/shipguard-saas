'use client';

import React from 'react';
import { SmoothScroll } from '@/components/SmoothScroll';
import { Navbar } from '@/components/Navbar';
import { SaasHero } from '@/components/saas/SaasHero';
import { WorkflowSteps } from '@/components/saas/WorkflowSteps';
import { ProductCapabilities } from '@/components/saas/ProductCapabilities';
import { ComparisonTable } from '@/components/saas/ComparisonTable';
import { PricingView } from '@/components/PricingView';
import { FaqSection } from '@/components/saas/FaqSection';
import { FinalCta } from '@/components/saas/FinalCta';
import { Footer } from '@/components/Footer';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  return (
    <SmoothScroll>
      <div className="bg-[#0A0A0A] text-[#EDEDED] min-h-full font-sans selection:bg-white selection:text-black">
        {/* Top Navbar */}
        <Navbar
          onToggleDashboard={() => router.push('/dashboard')}
        />

        {/* Hero Section with dashboard_overview.png and direct repo scan */}
        <SaasHero onOpenDashboard={(repo) => router.push(repo ? `/dashboard?repo=${encodeURIComponent(repo)}&scan=true` : '/dashboard')} />

        {/* 3-Step Interactive Operational Workflow */}
        <WorkflowSteps />

        {/* Product Capabilities Matrix featuring user screenshots */}
        <ProductCapabilities />

        {/* Uncompromising Comparison Table: ShipGuard vs Linters vs Enterprise */}
        <ComparisonTable />

        {/* 3-Tier Pricing Section */}
        <div id="pricing" className="py-20 bg-[#0A0A0A] border-b border-white/10">
          <PricingView />
        </div>

        {/* Developer & Enterprise Architecture FAQ */}
        <FaqSection />

        {/* Final Conversion CTA */}
        <FinalCta />

        {/* Multi-column Directory Footer */}
        <Footer />
      </div>
    </SmoothScroll>
  );
}
