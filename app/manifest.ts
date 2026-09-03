import { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'ShipGuard AI Release Gate',
    short_name: 'ShipGuard',
    description: 'Security Clearance & Design System Pre-flight Release Control for Next.js & LLM Codebases.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0D0D0D',
    theme_color: '#0D0D0D',
    icons: [
      {
        src: '/shipguard-logo.png',
        sizes: '192x192',
        type: 'image/png',
      },
      {
        src: '/shipguard-logo.png',
        sizes: '512x512',
        type: 'image/png',
      },
    ],
  };
}
