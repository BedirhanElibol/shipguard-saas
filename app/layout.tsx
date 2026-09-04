import type { Metadata, Viewport } from 'next';
import './globals.css';
import { OfflineBanner } from '@/components/ui/OfflineBanner';
import { ToastProvider } from '@/lib/toast';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  interactiveWidget: 'resizes-content',
};

function getMetadataBase(): URL {
  const raw = process.env.NEXT_PUBLIC_APP_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null);
  if (!raw || typeof raw !== 'string' || !raw.trim()) {
    return new URL('https://shipguard.dev');
  }
  const trimmed = raw.trim();
  const withProtocol = trimmed.startsWith('http://') || trimmed.startsWith('https://')
    ? trimmed
    : `https://${trimmed}`;
  try {
    return new URL(withProtocol);
  } catch {
    return new URL('https://shipguard.dev');
  }
}

export const metadata: Metadata = {
  metadataBase: getMetadataBase(),
  title: {
    default: 'ShipGuard | AI Codebase Security Clearance & Release Gate',
    template: '%s | ShipGuard',
  },
  description:
    'Prove your application is secure, polished, and ready for production before launch. 23 OWASP security pre-flight checks and automated code verification.',
  keywords: [
    'ShipGuard',
    'Release Gate',
    'Security Audit',
    'OWASP Security',
    'Code Quality',
    'Production Readiness',
    'Next.js 15',
  ],
  alternates: {
    canonical: './',
  },
  openGraph: {
    title: 'ShipGuard | AI Codebase Security Clearance & Release Gate',
    description:
      'Prove your application is secure, polished, and ready for production before launch. 23 OWASP security pre-flight checks and automated code verification.',
    url: 'https://shipguard.dev',
    siteName: 'ShipGuard',
    images: [
      {
        url: '/shipguard-logo.png',
        width: 1200,
        height: 630,
        alt: 'ShipGuard | AI Codebase Security Clearance & Release Gate',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ShipGuard | AI Codebase Security Clearance & Release Gate',
    description:
      'Prove your application is secure, polished, and ready for production before launch.',
    images: ['/shipguard-logo.png'],
  },
  icons: {
    icon: '/shipguard-logo.png',
    shortcut: '/shipguard-logo.png',
    apple: '/shipguard-logo.png',
  },
  manifest: '/manifest.webmanifest',
};

import { CookieBanner } from '@/components/CookieBanner';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark notranslate" translate="no" suppressHydrationWarning>
      <head>
        <title>ShipGuard | AI Codebase Security Clearance &amp; Release Gate</title>
        <meta name="description" content="Prove your application is secure, polished, and ready for production before launch. 23 OWASP security pre-flight checks and automated code verification." />
        <meta property="og:title" content="ShipGuard | AI Codebase Security Clearance &amp; Release Gate" />
        <meta property="og:description" content="Prove your application is secure, polished, and ready for production before launch. 23 OWASP security pre-flight checks and automated code verification." />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://shipguard.dev" />
        <link rel="canonical" href="https://shipguard.dev" />
        {/* Fontshare CDN for Satoshi Font */}
        <link rel="icon" href="/shipguard-logo.png" type="image/png" />
        <link rel="shortcut icon" href="/shipguard-logo.png" type="image/png" />
        <link
          href="https://api.fontshare.com/v2/css?f[]=satoshi@900,700,500,400&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-[#0A0A0A] text-[#EDEDED] antialiased selection:bg-white selection:text-black notranslate" translate="no" suppressHydrationWarning>
        <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-white focus:text-black focus:rounded-md focus:font-mono focus:text-xs">Skip to main content</a>
        <OfflineBanner />
        <ToastProvider>
          <main id="main-content">
            {children}
          </main>
          <CookieBanner />
        </ToastProvider>
      </body>
    </html>
  );
}
