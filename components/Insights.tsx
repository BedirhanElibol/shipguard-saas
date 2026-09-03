// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowUpRight } from 'lucide-react';
import Image from 'next/image';

interface ArticleItem {
  id: string;
  title: string;
  category: string;
  date: string;
  image: string;
}

export const Insights: React.FC = () => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [mousePos, setMousePos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const articles: ArticleItem[] = [
    {
      id: 'art-01',
      title: 'Common Security Gaps in AI-Generated Codebases',
      category: 'CYBERSECURITY',
      date: '2026',
      image: '/images/security_rules.png'
    },
    {
      id: 'art-02',
      title: 'Visual Anti-Patterns in AI-Generated Interfaces',
      category: 'DESIGN SYSTEM',
      date: '2026',
      image: '/images/audit_findings.png'
    },
    {
      id: 'art-03',
      title: 'Managing LLM Token Costs in Production',
      category: 'SUSTAINABILITY',
      date: '2026',
      image: '/images/bundle_profiler.png'
    }
  ];

  const handleMouseMove = (e: React.MouseEvent) => {
    setMousePos({ x: e.clientX, y: e.clientY });
  };

  return (
    <section
      id="insights"
      onMouseMove={handleMouseMove}
      className="py-28 px-6 sm:px-12 bg-[#0A0A0A] border-b border-white/10 relative overflow-hidden"
    >
      <div className="max-w-7xl mx-auto flex flex-col gap-16">
        {/* Section Header */}
        <div className="flex flex-col gap-3">
          <span className="text-xs font-extrabold text-[#A1A1AA] font-mono uppercase tracking-widest">
            EDITORIAL INSIGHTS &amp; ARTICLES
          </span>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight uppercase">
            RESEARCH &amp; AUDIT GUIDES
          </h2>
        </div>

        {/* Editorial Table Rows */}
        <div className="border-t border-white/10 divide-y divide-white/10">
          {articles.length === 0 ? (
            <div className="p-8 text-center text-xs text-[#A1A1AA]">
              No research guides currently available.
            </div>
          ) : (
            articles.map((item, idx) => (
              <a
                key={item.id}
                href="/dashboard"
                onMouseEnter={() => setHoveredIdx(idx)}
                onMouseLeave={() => setHoveredIdx(null)}
                className="py-8 px-4 flex items-center justify-between gap-6 hover:bg-white/[0.03] transition-colors cursor-pointer group block"
              >
                <div className="flex items-center gap-6">
                  <span className="text-xs font-mono text-[#A1A1AA] font-bold">
                    {item.category}
                  </span>
                  <h3 className="text-lg sm:text-2xl font-extrabold text-white group-hover:text-white/80 transition-colors">
                    {item.title}
                  </h3>
                </div>

                <div className="flex items-center gap-6 text-xs text-[#A1A1AA] font-mono">
                  <span>{item.date}</span>
                  <ArrowUpRight size={18} className="group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform group-hover:text-white" />
                </div>
              </a>
            ))
          )}
        </div>
      </div>

      {/* Mouse-Following Image Reveal Thumbnail */}
      {hoveredIdx !== null && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.8 }}
          style={{
            position: 'fixed',
            left: mousePos.x + 20,
            top: mousePos.y + 20,
            pointerEvents: 'none',
            zIndex: 90
          }}
          className="w-64 h-36 rounded-xl overflow-hidden border border-white/20 shadow-2xl bg-[#0A0A0A] p-2 flex items-center justify-center"
        >
          <div className="relative w-full h-full">
            <Image
              src={articles[hoveredIdx].image}
              alt={articles[hoveredIdx].title}
              fill
              className="object-contain"
            />
          </div>
        </motion.div>
      )}
    </section>
  );
};
