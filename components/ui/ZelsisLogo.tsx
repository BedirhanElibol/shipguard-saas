'use client';

import React from 'react';

interface ZelsisLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showWordmark?: boolean;
  className?: string;
}

export const ZelsisLogo: React.FC<ZelsisLogoProps> = ({
  size = 'md',
  showWordmark = true,
  className = ''
}) => {
  const sizeMap = {
    sm: { icon: 20, font: 'text-xs', tracking: 'tracking-[0.18em]' },
    md: { icon: 26, font: 'text-sm', tracking: 'tracking-[0.2em]' },
    lg: { icon: 34, font: 'text-base', tracking: 'tracking-[0.22em]' },
    xl: { icon: 44, font: 'text-xl', tracking: 'tracking-[0.25em]' }
  };

  const current = sizeMap[size];

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* Geometric Precision Release-Gate 'Z' Emblem */}
      <div 
        className="relative flex items-center justify-center shrink-0 rounded-lg p-1 transition-transform group-hover:scale-105"
        style={{ width: current.icon + 10, height: current.icon + 10 }}
      >
        <svg
          width={current.icon}
          height={current.icon}
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="overflow-visible"
        >
          {/* Subtle Glow Filter Definition */}
          <defs>
            <linearGradient id="zelsisGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#FFFFFF" />
              <stop offset="50%" stopColor="#E4E4E7" />
              <stop offset="100%" stopColor="#10B981" />
            </linearGradient>
            <linearGradient id="zelsisGate" x1="0%" y1="100%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10B981" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.4" />
            </linearGradient>
          </defs>

          {/* Outer Gate Bracket - Top Left */}
          <path
            d="M 6 12 L 6 7 L 12 7"
            stroke="rgba(255,255,255,0.3)"
            strokeWidth="1.5"
            strokeLinecap="round"
          />

          {/* Outer Gate Bracket - Bottom Right */}
          <path
            d="M 26 20 L 26 25 L 20 25"
            stroke="rgba(255,255,255,0.3)"
            strokeWidth="1.5"
            strokeLinecap="round"
          />

          {/* Core Geometric 'Z' Release-Gate Glyph */}
          <path
            d="M 8 9.5 L 24 9.5 L 10 22.5 L 24 22.5"
            stroke="url(#zelsisGrad)"
            strokeWidth="2.75"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Central Release Clearance Laser Dot */}
          <circle cx="21" cy="10" r="1.5" fill="#10B981" />
          <circle cx="11" cy="22" r="1.5" fill="#10B981" />
        </svg>
      </div>

      {/* Typography Wordmark */}
      {showWordmark && (
        <span className={`font-black ${current.font} text-white ${current.tracking} uppercase font-mono`}>
          ZEL<span className="text-emerald-400">SIS</span>
        </span>
      )}
    </div>
  );
};

// Backwards-compatible alias for any legacy imports
export const ShipGuardLogo = ZelsisLogo;

