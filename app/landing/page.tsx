'use client';

import React from 'react';
import { SmoothScroll } from '@/components/SmoothScroll';
import { Navbar } from '@/components/Navbar';
import { Hero } from '@/components/Hero';
import { Services } from '@/components/Services';
import { FeaturedWork } from '@/components/FeaturedWork';
import { About } from '@/components/About';
import { Insights } from '@/components/Insights';
import { PricingView } from '@/components/PricingView';
import { Contact } from '@/components/Contact';
import { Footer } from '@/components/Footer';
import { useRouter } from 'next/navigation';

export default function LandingPage() {
  const router = useRouter();

  return (
    <SmoothScroll>
      <div className="bg-[#0A0A0A] text-[#EDEDED] min-h-full font-sans selection:bg-white selection:text-black">
        {/* Top Navbar */}
        <Navbar onToggleDashboard={() => router.push('/dashboard')} />

        {/* Hero Section */}
        <Hero onOpenDashboard={() => router.push('/dashboard')} />

        {/* Services Grid */}
        <Services />

        {/* Featured Work Stacked Cards */}
        <FeaturedWork />

        {/* About Scrub Manifesto */}
        <About />

        {/* Insights Editorial Reveal */}
        <Insights />

        {/* Pricing Section */}
        <div id="pricing" className="py-20 bg-[#0A0A0A] border-b border-white/10">
          <PricingView />
        </div>

        {/* Contact Form */}
        <Contact />

        {/* Footer */}
        <Footer />
      </div>
    </SmoothScroll>
  );
}
