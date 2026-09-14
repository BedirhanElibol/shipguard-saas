'use client';

import React, { useEffect } from 'react';

export const SmoothScroll: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    let lenis: any;
    let animationId: number;

    import('lenis').then((LenisModule) => {
      const Lenis = LenisModule.default;
      lenis = new Lenis({
        duration: 1.2,
        easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        orientation: 'vertical',
        gestureOrientation: 'vertical',
        smoothWheel: true,
        wheelMultiplier: 1,
        touchMultiplier: 2,
      });

      function raf(time: number) {
        if (lenis) lenis.raf(time);
        animationId = requestAnimationFrame(raf);
      }

      animationId = requestAnimationFrame(raf);
    }).catch(err => console.error("Lenis smooth scroll error:", err));

    return () => {
      if (animationId) cancelAnimationFrame(animationId);
      if (lenis && typeof lenis.destroy === 'function') lenis.destroy();
    };
  }, []);

  return <>{children}</>;
};
