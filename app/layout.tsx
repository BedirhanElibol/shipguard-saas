import type { Metadata, Viewport } from 'next';
import './globals.css';
import { OfflineBanner } from '@/components/ui/OfflineBanner';
import { ToastProvider } from '@/lib/toast';
import { CookieBanner } from '@/components/CookieBanner';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  interactiveWidget: 'resizes-content',
};

function getMetadataBase(): URL {
  const raw = process.env.NEXT_PUBLIC_APP_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null);
  if (!raw || typeof raw !== 'string' || !raw.trim()) {
    return new URL('https://zelsis.com');
  }
  const trimmed = raw.trim();
  const withProtocol = trimmed.startsWith('http://') || trimmed.startsWith('https://')
    ? trimmed
    : `https://${trimmed}`;
  try {
    return new URL(withProtocol);
  } catch {
    return new URL('https://zelsis.com');
  }
}

export const metadata: Metadata = {
  metadataBase: getMetadataBase(),
  title: {
    default: 'Zelsis | Automated Codebase Security & Release Gate',
    template: '%s | Zelsis',
  },
  description:
    'Prove your application is secure, polished, and ready for production before launch. Comprehensive OWASP security pre-flight checks and automated code verification.',
  keywords: [
    'Zelsis',
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
    title: 'Zelsis | Automated Codebase Security & Release Gate',
    description:
      'Prove your application is secure, polished, and ready for production before launch. Comprehensive OWASP security pre-flight checks and automated code verification.',
    url: 'https://zelsis.com',
    siteName: 'Zelsis',
    images: [
      {
        url: '/zelsis-logo.svg',
        width: 1200,
        height: 630,
        alt: 'Zelsis | Automated Codebase Security & Release Gate',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Zelsis | Automated Codebase Security & Release Gate',
    description:
      'Prove your application is secure, polished, and ready for production before launch.',
    images: ['/zelsis-logo.svg'],
  },
  icons: {
    icon: [
      { url: '/favicon.svg?v=2', type: 'image/svg+xml' },
      { url: '/favicon.ico?v=2', sizes: 'any' },
    ],
    shortcut: '/favicon.svg?v=2',
    apple: '/favicon.png?v=2',
  },
  manifest: '/manifest.webmanifest',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark notranslate" translate="no" suppressHydrationWarning>
      <head>
        {/* Fontshare CDN for Satoshi Font */}
        <link
          rel="preconnect"
          href="https://api.fontshare.com"
          crossOrigin="anonymous"
        />
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
