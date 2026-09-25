import { CodeFile } from '@/lib/scanner-engine';

/**
 * Lightweight local development workspace sample files (F-35).
 * Replaced legacy 12MB bundled snapshot with a lightweight demo set to minimize bundle size.
 */
export const WORKSPACE_SOURCE_FILES: CodeFile[] = [
  {
    path: 'app/page.tsx',
    content: `'use client';

import React from 'react';
import Image from 'next/image';

export default function HomePage() {
  return (
    <main className="p-8 bg-[#0A0A0A] text-white min-h-screen">
      <h1 className="text-2xl font-bold">Zelsis Release Gate</h1>
      <p className="max-w-prose text-zinc-400 mt-2">Enterprise security pre-flight engine.</p>
      <Image src="/logo.webp" alt="Zelsis" width={120} height={40} priority />
    </main>
  );
}
`
  },
  {
    path: 'app/layout.tsx',
    content: `import React from 'react';
import './globals.css';

export const metadata = {
  title: 'Zelsis | Production Release Gate',
  description: 'Enterprise security clearance gatekeeper'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0A0A0A] text-[#EDEDED]">{children}</body>
    </html>
  );
}
`
  },
  {
    path: 'package.json',
    content: JSON.stringify(
      {
        name: 'zelsis-workspace',
        version: '1.0.0',
        private: true,
        dependencies: {
          next: '^15.5.0',
          react: '^18.3.1',
          'react-dom': '^18.3.1'
        }
      },
      null,
      2
    )
  },
  {
    path: 'next.config.mjs',
    content: `/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true
};
export default nextConfig;
`
  }
];
