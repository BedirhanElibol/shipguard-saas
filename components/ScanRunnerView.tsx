'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Project } from '@/data/schema';
import { runStaticCodeScan, ScanResult, CodeFile } from '@/lib/scanner-engine';
import { fetchGithubRepositoryData, isValidGithubUrl, parseGithubUrl } from '@/lib/github-api';
import { isValidWebUrl, fetchWebsiteAuditData } from '@/lib/website-scanner';
import { Terminal, CheckCircle2, Copy, Check, Search, Clock, Zap } from 'lucide-react';
import { TerminalLogWindow } from '@/components/scan/TerminalLogWindow';
import { canAccessLocalAudit } from '@/lib/env-config';

interface ScanRunnerViewProps {
  project: Project;
  onCompleteScan: (updatedResult?: ScanResult) => void;
}

export const ScanRunnerView: React.FC<ScanRunnerViewProps> = ({
  project,
  onCompleteScan
}) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState<number>(0);
  const [isFinished, setIsFinished] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [queuedFilesCount, setQueuedFilesCount] = useState<number>(0);
  const [hasCopiedLogs, setHasCopiedLogs] = useState<boolean>(false);
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [countdownSeconds, setCountdownSeconds] = useState<number>(3);
  const [scanFailureReason, setScanFailureReason] = useState<string | null>(null);
  const terminalLogsRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const onCompleteScanRef = useRef(onCompleteScan);
  const hasCompletedRef = useRef(false);

  useEffect(() => {
    onCompleteScanRef.current = onCompleteScan;
  }, [onCompleteScan]);

  // 1. Terminal Auto-Scroll effect
  useEffect(() => {
    if (terminalLogsRef.current) {
      terminalLogsRef.current.scrollTo({
        top: terminalLogsRef.current.scrollHeight,
        behavior: 'smooth'
      });
    }
  }, [logs]);

  // 2. Live Elapsed Time Counter
  useEffect(() => {
    if (isFinished) return;
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [isFinished]);

  // 3. Countdown timer on completion
  useEffect(() => {
    if (!isFinished) return;
    const timer = setInterval(() => {
      setCountdownSeconds((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [isFinished]);

  // 4. Auto-navigate to Full Audit Report when countdown reaches 0
  useEffect(() => {
    if (!isFinished || !scanResult) return;
    if (countdownSeconds === 0 && !hasCompletedRef.current) {
      hasCompletedRef.current = true;
      onCompleteScanRef.current(scanResult);
    }
  }, [countdownSeconds, isFinished, scanResult]);

  useEffect(() => {
    let isCancelled = false;
    const controller = new AbortController();
    abortControllerRef.current = controller;
    hasCompletedRef.current = false;
    setCountdownSeconds(3);

    async function executeLiveScan() {
      const isLocalOrSelfAudit =
        project.repoUrl === 'local' ||
        project.repoUrl.toLowerCase() === 'local' ||
        project.id === 'proj-zelsis-self' ||
        project.id === 'proj-shipguard-self' ||
        project.id === 'proj-preset-self';
      const isWebTarget = isValidWebUrl(project.repoUrl);

      let filesToScan: CodeFile[] = [];

      if (isLocalOrSelfAudit) {
        if (!canAccessLocalAudit()) {
          if (!isCancelled) {
            setScanFailureReason('Local workspace self-audit is available only in local development.');
            setLogs([
              `[${new Date().toLocaleTimeString()}] [LOCAL] Local workspace self-audit is available only in local development.`,
              `[${new Date().toLocaleTimeString()}] [INFO] Please select a public GitHub repository or live URL target to audit.`
            ]);
          }
          setIsFinished(true);
          return;
        }

        const { WORKSPACE_SOURCE_FILES } = await import('@/data/workspaceFiles');
        filesToScan = WORKSPACE_SOURCE_FILES;
        setQueuedFilesCount(filesToScan.length);
        if (!isCancelled) {
          setLogs([
            `[${new Date().toLocaleTimeString()}] [LOAD] Loaded Repository Files for "${project.name}" (${filesToScan.length} source files queued).`,
            `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${filesToScan.length} files for OWASP Security Clearance, Supply Chain & VibePolish UI rules...`
          ]);
        }
      } else if (isWebTarget) {
        setLogs([
          `[${new Date().toLocaleTimeString()}] [TARGET] Connecting to Live Web Deployment Target: ${project.repoUrl}`
        ]);

        const webData = await fetchWebsiteAuditData(project.repoUrl, controller.signal);

        if (webData && webData.files && webData.files.length > 0) {
          filesToScan = webData.files;
          setQueuedFilesCount(webData.files.length);
          const isHealthy = webData.statusCode >= 200 && webData.statusCode < 400;
          if (!isCancelled) {
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [HEALTH] Link Health Audit: Connected to ${webData.url} (HTTP ${webData.statusCode} ${isHealthy ? 'HEALTHY' : 'UNHEALTHY / BROKEN'}).`,
              `[${new Date().toLocaleTimeString()}] [TARGET] Target Page Title: "${webData.title}" (${webData.crawledPagesCount} subpages crawled).`,
              `[${new Date().toLocaleTimeString()}] [SECURITY] Security Headers Audit: ${webData.securityHeadersMissing.length > 0 ? `Missing ${webData.securityHeadersMissing.join(', ')}` : 'All Security Headers Active'}.`,
              `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${webData.files.length} live web pages & client JS bundles...`
            ]);
          }
        } else {
          if (!isCancelled) {
            setScanFailureReason(`Unable to reach target website "${project.repoUrl}". Verify the URL is live, accessible, and not blocking automated audits.`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] Unable to reach target website "${project.repoUrl}".`,
              `[${new Date().toLocaleTimeString()}] [INFO] Please verify the website URL is active and accessible.`
            ]);
          }
          setIsFinished(true);
          return;
        }
      } else {
        setLogs([
          `[${new Date().toLocaleTimeString()}] [TARGET] Connecting to GitHub Target: ${project.repoUrl}`
        ]);

        if ((project as any).githubToken) {
          setLogs((prev) => [
            ...prev,
            `[${new Date().toLocaleTimeString()}] [AUTH] GitHub Personal Access Token (PAT) detected. Requesting authenticated access...`
          ]);
        }

        const liveData = await fetchGithubRepositoryData(project.repoUrl, (project as any).githubToken, controller.signal);

        if (liveData && liveData.files && liveData.files.length > 0) {
          filesToScan = liveData.files;
          setQueuedFilesCount(liveData.files.length);
          if (!isCancelled) {
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [LOAD] GitHub Repository Verified: Loaded ${liveData.files.length} real source files from "${liveData.name}" (${liveData.description || 'Target Repository'}).`,
              `[${new Date().toLocaleTimeString()}] [SCAN] Auditing ${liveData.files.length} source code files for security clearance & VibePolish UI rules...`
            ]);
          }
        } else {
          if (!isCancelled) {
            setScanFailureReason(`Unable to fetch files from GitHub repository "${project.repoUrl}". For private repositories or to avoid GitHub API rate limits (60 req/hr), add a GitHub Personal Access Token (PAT) in Settings.`);
            setLogs((prev) => [
              ...prev,
              `[${new Date().toLocaleTimeString()}] [ERROR] Unable to fetch files from GitHub repository "${project.repoUrl}".`,
              `[${new Date().toLocaleTimeString()}] [AUTH] If this is a private repository, please add your GitHub Personal Access Token (PAT) in Settings.`
            ]);
          }
          setIsFinished(true);
          return;
        }
      }

      setQueuedFilesCount(filesToScan.length);

      const result = runStaticCodeScan(filesToScan, project.name);
      if (isCancelled || controller.signal.aborted) return;

      setScanResult(result);

      let currentIdx = 0;
      const realLogs = result.logs;
      const stepIntervalMs = 25; // High performance 25ms base interval

      if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {});
      }

      intervalRef.current = setInterval(() => {
        const isHidden = typeof document !== 'undefined' && document.hidden;
        // Batch 25 logs per tick when background tab is throttled by Chrome, 3 logs when active
        const batchSize = isHidden ? 25 : 3;

        if (currentIdx < realLogs.length) {
          const newLogItems: string[] = [];
          for (let b = 0; b < batchSize && currentIdx < realLogs.length; b++) {
            const rawLog = realLogs[currentIdx];
            if (rawLog) {
              const liveTime = new Date().toLocaleTimeString();
              const updatedLog = rawLog.replace(/^\[\d{1,2}:\d{2}:\d{2}(\s?[AP]M)?\]/, `[${liveTime}]`);
              newLogItems.push(updatedLog);
            }
            currentIdx++;
          }

          setLogs((prev) => [...prev, ...newLogItems]);
          const pct = Math.min(100, Math.round((currentIdx / realLogs.length) * 100));
          setProgress(pct);
          if (typeof document !== 'undefined') {
            document.title = `(${pct}%) Zelsis Audit | ${project.name}`;
          }
        } else {
          if (intervalRef.current) clearInterval(intervalRef.current);
          intervalRef.current = null;
          setProgress(100);
          setIsFinished(true);

          if (typeof document !== 'undefined') {
            document.title = `Audit Complete | ${project.name}`;
            if (document.hidden && typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
              new Notification(`Zelsis Audit Completed: ${project.name}`, {
                body: `Release Gate Audit finished successfully with readiness score ${result.score}/100.`,
                icon: '/favicon.ico'
              });
            }
          }
        }
      }, stepIntervalMs);
    }

    executeLiveScan();

    return () => {
      isCancelled = true;
      controller.abort();
      if (typeof document !== 'undefined') {
        document.title = 'Zelsis | Release Gate SaaS';
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [project.name, project.repoUrl]);

  // Warn user on page exit / close when scan is running
  useEffect(() => {
    if (isFinished) return;

    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'A live release gate audit scan is currently running. Leaving or closing this page will cancel the scan.';
      return e.returnValue;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isFinished]);

  const activeFileLog = [...logs].reverse().find(l => l.includes('Opening & AST Inspecting') || l.includes('Inspect'));
  const currentFileName = activeFileLog
    ? activeFileLog.split('Inspecting ')[1] || 'Scanning Source File...'
    : queuedFilesCount === 0
    ? 'Connecting to Remote Target & Resolving Git Tree...'
    : 'Queuing Repository Files...';

  const handleAbortScan = () => {
    if (window.confirm('Are you sure you want to stop and cancel the active Release Gate scan?')) {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      setIsFinished(true);
      onCompleteScan();
    }
  };

  return (
    <div className="flex flex-col gap-5 sm:gap-6 w-full max-w-full overflow-hidden">
      {/* Header & File Inspection Status */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-8 flex flex-col gap-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-lg sm:text-xl font-extrabold text-[#EDEDED] truncate">
              Sequential AST Audit: {project.name}
            </h1>
            <div className="text-xs text-[#A1A1AA] mt-1 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-pulse" />
              <span className="truncate">Automated security clearance &amp; UX quality gates</span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
            {!isFinished && (
              <button
                onClick={handleAbortScan}
                className="btn btn-secondary text-xs px-3 py-1.5 text-red-400 border-red-500/30 hover:bg-red-500/10 font-bold font-mono"
              >
                Abort Audit
              </button>
            )}
            <div className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] font-mono">
              {progress}%
            </div>
          </div>
        </div>

        {/* Current Active File Card */}
        <div className="bg-[#0A0A0A] p-3 sm:p-4 rounded-xl border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0 flex-1 w-full">
            <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center font-mono font-bold text-xs text-white shrink-0">
              AST
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[0.68rem] text-[#A1A1AA] font-bold uppercase tracking-wider font-mono">
                {isFinished ? 'Audit Execution Status:' : 'Currently Inspecting File:'}
              </div>
              <div className="text-xs font-mono font-bold mt-0.5 truncate text-white">
                {isFinished
                  ? scanResult
                    ? `All ${queuedFilesCount} Source Files Inspected & Verified`
                    : (project.repoUrl === 'local' || project.repoUrl.toLowerCase() === 'local') && !canAccessLocalAudit()
                    ? 'Local workspace self-audit is available only in local development.'
                    : 'Audit Terminated'
                  : currentFileName}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono text-[#A1A1AA] shrink-0 w-full sm:w-auto justify-between sm:justify-end">
            <div className="flex items-center gap-1.5 bg-white/5 px-2.5 py-1 rounded border border-white/10 shrink-0">
              <Clock size={12} className="text-white" />
              <span>Elapsed: {Math.floor(elapsedSeconds / 60)}m {elapsedSeconds % 60}s</span>
            </div>
            {queuedFilesCount > 0 && (
              <span className="text-white font-bold hidden md:inline">
                {queuedFilesCount.toLocaleString()} Files
              </span>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
          <div
            className="h-full bg-white transition-all duration-150"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Real-time Terminal Log Window */}
      <TerminalLogWindow
        logs={logs}
        repoUrl={project.repoUrl}
        queuedFilesCount={queuedFilesCount}
        scanResult={scanResult}
        terminalLogsRef={terminalLogsRef}
      />

      {/* Complete Action Banner & Button */}
      {isFinished && (
        <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4 shadow-2xl animate-fade-in">
          {scanResult ? (
            <>
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                  <CheckCircle2 size={24} className="text-white" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-extrabold text-white uppercase tracking-wider">
                      AST CLEARANCE SCAN COMPLETE
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[0.65rem] font-bold ${
                      scanResult.gateStatus === 'FAILED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-white/5 text-white border border-white/10'
                    }`}>
                      GATE: {scanResult.gateStatus}
                    </span>
                    <span className="text-[0.65rem] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded font-mono">
                      Auto-opening report in {countdownSeconds}s...
                    </span>
                  </div>
                  <p className="text-sm font-bold text-[#EDEDED] mt-0.5">
                    Audited {queuedFilesCount} files · Found {scanResult.findings.length} security &amp; UX issues (Readiness Score: {scanResult.score}/100)
                  </p>
                </div>
              </div>

              <button
                className="btn btn-primary px-8 py-4 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 bg-white text-black hover:bg-neutral-200 transition-all"
                onClick={() => {
                  hasCompletedRef.current = true;
                  onCompleteScanRef.current(scanResult);
                }}
              >
                <CheckCircle2 size={18} />
                <span>View Full Audit Report ({scanResult.findings.length} Issues)</span>
              </button>
            </>
          ) : (
            <>
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center shrink-0">
                  <span className="text-red-400 font-bold text-lg font-mono">!</span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-extrabold text-red-400 uppercase tracking-wider">
                      AUDIT RESTRICTED
                    </span>
                  </div>
                  <p className="text-sm font-bold text-[#EDEDED] mt-0.5">
                    {scanFailureReason || ((project.repoUrl === 'local' || project.repoUrl.toLowerCase() === 'local') && !canAccessLocalAudit()
                      ? 'Local workspace self-audit is available only in local development.'
                      : 'Audit execution was stopped before completion.')}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {scanFailureReason?.includes('Settings') && (
                  <a
                    href="/dashboard?nav=settings"
                    className="btn btn-secondary px-5 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 transition-all font-mono"
                    onClick={() => {
                      hasCompletedRef.current = true;
                    }}
                  >
                    <span>Configure in Settings</span>
                  </a>
                )}

                <button
                  className="btn btn-secondary px-6 py-3 text-xs font-bold uppercase tracking-wider rounded-xl shadow-lg shrink-0 flex items-center gap-2 border border-white/10 hover:bg-white/10 text-white transition-all font-mono"
                  onClick={() => {
                    hasCompletedRef.current = true;
                    onCompleteScanRef.current();
                  }}
                >
                  <span>Return to Dashboard</span>
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};
