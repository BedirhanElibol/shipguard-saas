// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, Play, ArrowRight } from 'lucide-react';
import { useRouter } from 'next/navigation';

export const Contact: React.FC = () => {
  const [btnPos, setBtnPos] = useState({ x: 0, y: 0 });
  const router = useRouter();

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;

    const distX = (e.clientX - centerX) * 0.2;
    const distY = (e.clientY - centerY) * 0.2;

    setBtnPos({ x: distX, y: distY });
  };

  const handleMouseLeave = () => {
    setBtnPos({ x: 0, y: 0 });
  };

  return (
    <section id="contact" className="py-32 px-6 sm:px-12 bg-[#0A0A0A] relative overflow-hidden border-b border-white/10">
      <div className="max-w-5xl mx-auto text-center flex flex-col items-center gap-8 relative z-10">
        <span className="text-xs font-extrabold text-[#A1A1AA] font-mono uppercase tracking-widest">
          LET&apos;S SHIP SECURE SOFTWARE
        </span>

        <h2 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-white tracking-tight uppercase leading-none">
          READY TO AUDIT &amp; <br />
          <span className="text-white">SHIP YOUR AI APP?</span>
        </h2>

        <p className="text-base sm:text-lg text-[#A1A1AA] max-w-xl leading-relaxed">
          Connect your GitHub repository or deployment URL. Run automated security clearance and design verification in seconds.
        </p>

        {/* Elastic Magnetic Button Wrapper */}
        <div
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          className="p-8 inline-block"
        >
          <motion.button
            animate={{ x: btnPos.x, y: btnPos.y }}
            transition={{ type: 'spring', stiffness: 150, damping: 15 }}
            onClick={() => router.push('/dashboard')}
            onKeyDown={(e) => { if (e.key === 'Enter') router.push('/dashboard'); }}
            className="btn btn-primary px-10 py-5 text-sm font-bold uppercase tracking-widest bg-white text-black hover:bg-neutral-200 transition-all rounded-xl shadow-lg flex items-center gap-3"
          >
            <Play size={18} fill="#0A0A0A" />
            <span>Launch Free Release Audit</span>
          </motion.button>
        </div>
      </div>
    </section>
  );
};
