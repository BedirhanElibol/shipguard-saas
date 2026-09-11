'use client';

import React from 'react';

interface ZelsisLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showWordmark?: boolean;
  className?: string;
}

export const ShipGuardLogo: React.FC<ZelsisLogoProps> = ({
  size = 'md',
  showWordmark = true,
  className = ''
}) => {
  const sizeMap = {
    sm: { icon: 20, font: 'text-xs', tracking: 'tracking-[0.16em]' },
    md: { icon: 26, font: 'text-sm', tracking: 'tracking-[0.18em]' },
    lg: { icon: 34, font: 'text-base', tracking: 'tracking-[0.2em]' },
    xl: { icon: 44, font: 'text-xl', tracking: 'tracking-[0.22em]' }
  };

  const current = sizeMap[size];

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* Precision Release-Gate Security Shield Emblem */}
      <div 
        className="relative flex items-center justify-center shrink-0 rounded-lg p-1 transition-transform group-hover:scale-105"
        style={{ width: current.icon + 8, height: current.icon + 8 }}
      >
        <svg
          width={current.icon}
          height={current.icon}
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="overflow-visible"
        >
          <defs>
            <linearGradient id="shipguardShield" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#FFFFFF" />
              <stop offset="50%" stopColor="#E4E4E7" />
              <stop offset="100%" stopColor="#10B981" />
            </linearGradient>
            <linearGradient id="shipguardCore" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#059669" />
            </linearGradient>
          </defs>

          {/* Outer Protective Angular Shield Contour */}
          <path
            d="M 16 3 L 27 7.5 V 15 C 27 22.5 22 27.5 16 29.5 C 10 27.5 5 22.5 5 15 V 7.5 Z"
            stroke="rgba(255,255,255,0.4)"
            strokeWidth="1.75"
            strokeLinejoin="round"
          />

          {/* Inner Release Gate Checkmark / Lock Vector */}
          <path
            d="M 11 16.5 L 14.5 20 L 21.5 12.5"
            stroke="url(#shipguardCore)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Ambient Clearance Laser Pip */}
          <circle cx="16" cy="7" r="1.5" fill="#10B981" />
        </svg>
      </div>

      {/* Typography Wordmark */}
      {showWordmark && (
        <span className={`font-black ${current.font} text-white ${current.tracking} uppercase font-mono`}>
          SHIP<span className="text-emerald-400">GUARD</span>
        </span>
      )}
    </div>
  );
};

// Backwards-compatible alias for existing imports
export const ZelsisLogo = ShipGuardLogo;
