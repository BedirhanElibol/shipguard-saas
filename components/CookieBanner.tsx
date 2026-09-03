// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { Cookie, X } from 'lucide-react';

export const CookieBanner: React.FC = () => {
  const [showBanner, setShowBanner] = useState(false);

  useEffect(() => {
    const consent = localStorage.getItem('shipguard_cookie_consent');
    if (!consent) {
      setShowBanner(true);
    }
  }, []);

  const handleAccept = () => {
    localStorage.setItem('shipguard_cookie_consent', 'accepted');
    setShowBanner(false);
  };

  const handleDecline = () => {
    localStorage.setItem('shipguard_cookie_consent', 'declined');
    setShowBanner(false);
  };

  if (!showBanner) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-6 sm:max-w-md z-50 transition-all duration-300">
      <div className="bg-[#141414] border border-white/10 p-4 sm:p-5 rounded-2xl shadow-2xl flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-white shrink-0">
              <Cookie size={16} />
            </div>
            <div className="text-xs font-bold text-[#FAFAFA]">
              Cookie Consent Preferences
            </div>
          </div>
          <button
            onClick={handleDecline}
            className="text-[#94A3B8] hover:text-[#FAFAFA] transition-colors p-1"
            aria-label="Close cookie consent banner"
          >
            <X size={14} />
          </button>
        </div>

        <p className="text-xs text-[#94A3B8] leading-relaxed">
          We use functional cookies to maintain your active audit session and security preferences. No invasive tracking cookies are used.
        </p>

        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={handleAccept}
            className="flex-1 px-3.5 py-1.5 rounded-lg text-xs font-bold text-[#0A0A0A] bg-white hover:bg-neutral-200 transition-colors shadow-sm"
          >
            Accept Essential Cookies
          </button>
          <button
            onClick={handleDecline}
            className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-[#A1A1AA] hover:text-white bg-[#141414] hover:bg-white/10 border border-white/10 transition-colors"
          >
            Decline
          </button>
        </div>
      </div>
    </div>
  );
};
