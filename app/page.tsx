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

export default function Home() {
  const router = useRouter();

  return (
    <SmoothScroll>
      <div className="bg-[#0A0A0A] text-[#EDEDED] min-h-full font-sans selection:bg-white selection:text-black">
        {/* Top Navbar */}
        <Navbar
          onToggleDashboard={() => router.push('/dashboard')}
        />

        {/* Hero Section */}
        <Hero onOpenDashboard={() => router.push('/dashboard')} />

        {/* Services Grid (12-Col with Sticky Media Preview) */}
        <Services />

        {/* Featured Work Stacked Cards Deck */}
        <FeaturedWork />

        {/* About Word Scrub Manifesto */}
        <About />

        {/* Insights Mouse-Following Cursor Reveal */}
        <Insights />

        {/* 3-Tier Pricing Section */}
        <div id="pricing" className="py-20 bg-[#0A0A0A] border-b border-white/10">
          <PricingView />
        </div>

        {/* Contact Form & Elastic Magnetic Button */}
        <Contact />

        {/* Multi-column Directory Footer */}
        <Footer />
      </div>
    </SmoothScroll>
  );
}
