'use client';

import React, { useEffect } from 'react';
import Script from 'next/script';
import { captureAttribution } from '@/lib/attribution';

declare global {
  interface Window {
    dataLayer?: any[];
    gtag?: (...args: any[]) => void;
    fbq?: (...args: any[]) => void;
    _fbq?: any;
  }
}

const GA_ID = process.env.NEXT_PUBLIC_GA_ID;
const META_PIXEL_ID = process.env.NEXT_PUBLIC_META_PIXEL_ID;

/**
 * Dispatches tracking events to GA4 and Meta Pixel if loaded.
 */
export function trackAnalyticsEvent(eventName: string, params?: Record<string, any>): void {
  if (typeof window === 'undefined') return;

  try {
    // Google Analytics 4 Event
    if (typeof window.gtag === 'function') {
      window.gtag('event', eventName, params);
    }

    // Meta Pixel Event
    if (typeof window.fbq === 'function') {
      const standardMetaEvents: Record<string, string> = {
        scan_started: 'Search',
        view_pricing: 'ViewContent',
        sign_up: 'Lead',
        begin_checkout: 'InitiateCheckout',
        purchase: 'Purchase'
      };
      const metaEvent = standardMetaEvents[eventName] || 'CustomEvent';
      if (metaEvent === 'CustomEvent') {
        window.fbq('trackCustom', eventName, params);
      } else {
        window.fbq('track', metaEvent, params);
      }
    }
  } catch (err) {
    console.debug('[Analytics] Warning dispatching event:', eventName, err);
  }
}

/**
 * Updates Google Consent Mode v2 dynamically upon cookie consent.
 */
export function updateConsentMode(granted: boolean): void {
  if (typeof window === 'undefined' || typeof window.gtag !== 'function') return;
  const status = granted ? 'granted' : 'denied';
  window.gtag('consent', 'update', {
    ad_storage: status,
    analytics_storage: status,
    ad_user_data: status,
    ad_personalization: status
  });
}

export const AnalyticsScripts: React.FC = () => {
  useEffect(() => {
    // Capture URL attribution parameters on client mount
    captureAttribution();
  }, []);

  return (
    <>
      {/* Google Consent Mode v2 Default Initialization */}
      {GA_ID && (
        <>
          <Script id="google-consent-mode" strategy="beforeInteractive">
            {`
              window.dataLayer = window.dataLayer || [];
              function gtag(){dataLayer.push(arguments);}
              gtag('consent', 'default', {
                'ad_storage': 'denied',
                'analytics_storage': 'denied',
                'ad_user_data': 'denied',
                'ad_personalization': 'denied',
                'wait_for_update': 500
              });
            `}
          </Script>
          <Script
            strategy="afterInteractive"
            src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`}
          />
          <Script id="google-analytics-init" strategy="afterInteractive">
            {`
              window.dataLayer = window.dataLayer || [];
              function gtag(){dataLayer.push(arguments);}
              gtag('js', new Date());
              gtag('config', '${GA_ID}', {
                page_path: window.location.pathname,
                send_page_view: true
              });
            `}
          </Script>
        </>
      )}

      {/* Meta Pixel Initialization */}
      {META_PIXEL_ID && (
        <Script id="meta-pixel-init" strategy="afterInteractive">
          {`
            !function(f,b,e,v,n,t,s)
            {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
            n.callMethod.apply(n,arguments):n.queue.push(arguments)};
            if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
            n.queue=[];t=b.createElement(e);t.async=!0;
            t.src=v;s=b.getElementsByTagName(e)[0];
            s.parentNode.insertBefore(t,s)}(window, document,'script',
            'https://connect.facebook.net/en_US/fbevents.js');
            fbq('init', '${META_PIXEL_ID}');
            fbq('track', 'PageView');
          `}
        </Script>
      )}
    </>
  );
};
