// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Terminal, Check, Copy, Search } from 'lucide-react';
import { ScanResult } from '@/lib/scanner-engine';

interface TerminalLogWindowProps {
  logs: string[];
  repoUrl: string;
  queuedFilesCount: number;
  scanResult: ScanResult | null;
  terminalLogsRef: React.RefObject<HTMLDivElement | null>;
}

export const TerminalLogWindow: React.FC<TerminalLogWindowProps> = ({
  logs,
  repoUrl,
  queuedFilesCount,
  scanResult,
  terminalLogsRef
}) => {
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [hasCopiedLogs, setHasCopiedLogs] = useState<boolean>(false);

  return (
    <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/10 font-mono text-xs text-[#EDEDED] flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <Terminal size={16} className="text-white" />
          <span className="hidden sm:inline">shipguard-ast-engine --scan --target {repoUrl}</span>
        </div>

        <div className="flex items-center gap-3 flex-1 justify-end">
          <div className="relative max-w-xs w-full sm:w-64">
            <Search size={12} className="absolute left-2.5 top-2.5 text-[#A1A1AA]" />
            <input
              type="text"
              aria-label="Filter terminal logs"
              value={logSearchQuery}
              onChange={(e) => setLogSearchQuery(e.target.value)}
              placeholder="Filter logs (e.g. SEC, WARN)..."
              className="w-full pl-7 pr-3 py-1 bg-[#141414] border border-white/10 rounded-md text-[0.7rem] text-[#EDEDED] outline-none focus:border-white/20 font-mono"
            />
          </div>

          {scanResult && (
            <span className="text-[0.7rem] text-white font-bold hidden lg:inline font-mono">
              {queuedFilesCount} Files Analyzed • {scanResult.findings.length} Open Findings
            </span>
          )}

          <button
            onClick={() => {
              navigator.clipboard.writeText(logs.join('\n'));
              setHasCopiedLogs(true);
              setTimeout(() => setHasCopiedLogs(false), 2000);
            }}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/15 text-[0.7rem] text-gray-300 transition-colors shrink-0"
            title="Copy all terminal log lines to clipboard"
          >
            {hasCopiedLogs ? <Check size={12} className="text-white" /> : <Copy size={12} />}
            <span>{hasCopiedLogs ? 'Logs Copied!' : 'Copy Logs'}</span>
          </button>
        </div>
      </div>

      <div ref={terminalLogsRef as any} className="h-96 overflow-y-auto font-mono text-xs flex flex-col gap-2 p-2 scroll-smooth">
        {logs.length === 0 ? (
          <div className="text-gray-500 italic text-center py-8">
            Initializing AST scanner engine and queuing repository files...
          </div>
        ) : (
          logs
            .filter((log) => !logSearchQuery.trim() || log.toLowerCase().includes(logSearchQuery.toLowerCase()))
            .map((log, i) => {
              const strLog = String(log || '');
              const isError = strLog.includes('CRITICAL') || strLog.includes('FAILED') || strLog.includes('🚨');
              const isWarning = strLog.includes('WARN') || strLog.includes('HIGH') || strLog.includes('⚠️');
              const isHeader = strLog.includes('Phase') || strLog.includes('Executing') || strLog.includes('🚀');

              return (
                <div
                  key={i}
                  className={
                    isError
                      ? 'text-[#EF4444] font-bold'
                      : isWarning
                      ? 'text-[#F59E0B] font-bold'
                      : isHeader
                      ? 'text-white font-bold'
                      : 'text-[#A1A1AA]'
                  }
                >
                  {strLog}
                </div>
              );
            })
        )}
      </div>
    </div>
  );
};
