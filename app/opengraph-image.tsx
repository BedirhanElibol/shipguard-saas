import { ImageResponse } from 'next/og';

export const runtime = 'edge';
export const alt = 'ShipGuard | AI Codebase Security Clearance & Release Gate';
export const size = {
  width: 1200,
  height: 630,
};
export const contentType = 'image/png';

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          height: '100%',
          width: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#0D0D0D',
          fontFamily: 'sans-serif',
          color: '#FFFFFF',
          position: 'relative',
          padding: '60px',
        }}
      >
        {/* Subtle Accent Glow */}
        <div
          style={{
            position: 'absolute',
            top: '-100px',
            right: '-100px',
            width: '400px',
            height: '400px',
            background: 'rgba(255, 255, 255, 0.03)',
            borderRadius: '50%',
          }}
        />

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '8px 20px',
            backgroundColor: '#141414',
            borderRadius: '100px',
            border: '1px solid #262626',
            marginBottom: '32px',
          }}
        >
          <div
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: '#10B981',
            }}
          />
          <span
            style={{
              fontSize: '14px',
              letterSpacing: '2px',
              color: '#888888',
              fontWeight: 700,
            }}
          >
            SHIPGUARD // RELEASE GATE
          </span>
        </div>

        <h1
          style={{
            fontSize: '54px',
            fontWeight: 900,
            textAlign: 'center',
            margin: '0 0 16px 0',
            lineHeight: 1.1,
            color: '#FFFFFF',
            maxWidth: '900px',
          }}
        >
          AI Codebase Security Clearance &amp; Pre-Flight Control
        </h1>

        <p
          style={{
            fontSize: '22px',
            color: '#888888',
            textAlign: 'center',
            maxWidth: '750px',
            margin: 0,
            lineHeight: 1.4,
          }}
        >
          Prove your application is secure, polished, and ready for production before launch. Automated OWASP verification &amp; design system anti-pattern audit.
        </p>
      </div>
    ),
    {
      ...size,
    }
  );
}
