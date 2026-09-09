import { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Zelsis AI Release Gate',
    short_name: 'Zelsis',
    description: 'Security Clearance & Design System Pre-flight Release Control for Next.js & LLM Codebases.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0D0D0D',
    theme_color: '#0D0D0D',
    icons: [
      {
        src: '/zelsis-logo.svg',
        sizes: 'any',
        type: 'image/svg+xml',
      },
    ],
  };
}
