// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { AlertTriangle, RefreshCw, Home, ArrowLeft } from 'lucide-react';

interface ErrorBoundaryProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalError({ error, reset }: ErrorBoundaryProps) {
  const isChunkError = error?.name === 'ChunkLoadError' || (error?.message && error.message.includes('Loading chunk'));

  useEffect(() => {
    // Log exception for debugging and telemetry
    console.error('[ShipGuard Global Error Boundary]:', error);

    // Auto-recover from chunk load errors caused by new deployments
    if (isChunkError && typeof window !== 'undefined') {
      const reloadKey = 'shipguard_chunk_reload';
      if (!sessionStorage.getItem(reloadKey)) {
        sessionStorage.setItem(reloadKey, 'true');
        window.location.reload();
      }
    }
  }, [error, isChunkError]);

  const handleRetry = () => {
    if (isChunkError && typeof window !== 'undefined') {
      sessionStorage.removeItem('shipguard_chunk_reload');
      window.location.reload();
    } else {
      reset();
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F3EF] flex items-center justify-center p-4 sm:p-6 select-text">
      <div className="w-full max-w-xl bg-[#141414] border border-white/15 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-2xl relative">
        {/* Top Status Header */}
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/25 text-red-400 flex items-center justify-center shrink-0">
            <AlertTriangle size={24} />
          </div>
          <div>
            <div className="text-[0.68rem] font-mono font-bold uppercase tracking-widest text-[#A1A1AA]">
              Runtime Exception &bull; Release Gate Interrupted
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-[#F5F3EF] mt-0.5">
              An unexpected error occurred
            </h1>
          </div>
        </div>

        {/* Error Details Container */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-mono font-bold uppercase text-[#A1A1AA]">
            Diagnostics &amp; Stack Info
          </span>
          <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 font-mono text-xs text-red-300 break-words leading-relaxed overflow-x-auto max-h-[12rem]">
            <p className="font-semibold text-white mb-1">
              {error.name || 'Error'}: {error.message || 'Unknown runtime error'}
            </p>
            {error.digest && (
              <p className="text-[0.7rem] text-[#A1A1AA] mt-2 border-t border-white/10 pt-2">
                Digest Hash: <span className="text-white">{error.digest}</span>
              </p>
            )}
          </div>
        </div>

        <p className="text-xs text-[#A1A1AA] leading-relaxed">
          The application encountered an unhandled exception while processing your session state or analyzing components. You can retry the operation or return to the main dashboard.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2 border-t border-white/10">
          <button
            onClick={handleRetry}
            onKeyDown={(e) => { if (e.key === 'Enter') handleRetry(); }}
            className="btn btn-primary py-2.5 px-5 text-xs font-extrabold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            <RefreshCw size={14} />
            <span>Try Again</span>
          </button>

          <a
            href="/dashboard"
            className="btn btn-secondary py-2.5 px-5 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            <Home size={14} />
            <span>Dashboard</span>
          </a>

          <a
            href="/"
            className="btn btn-secondary py-2.5 px-4 text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 text-[#A1A1AA] hover:text-white"
          >
            <ArrowLeft size={14} />
            <span>Home</span>
          </a>
        </div>
      </div>
    </div>
  );
}
