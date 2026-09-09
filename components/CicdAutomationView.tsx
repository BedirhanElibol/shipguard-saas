// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Terminal, GitPullRequest, ShieldCheck, Copy, CheckCircle2, Download, Settings2, Sliders, CheckSquare, Sparkles, AlertTriangle } from 'lucide-react';

interface CicdAutomationViewProps {
  projectName?: string;
}

export const CicdAutomationView: React.FC<CicdAutomationViewProps> = ({
  projectName = 'Next.js 15 SaaS Starter'
}) => {
  const [failThreshold, setFailThreshold] = useState<'smart' | 'strict' | 'advisory'>('smart');
  const [copiedWorkflow, setCopiedWorkflow] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [enabledGates, setEnabledGates] = useState({
    security: true,
    compliance: true,
    infra: true,
    vibepolish: true,
    vibecare: true
  });
  const [minScore, setMinScore] = useState(85);

  const generateGithubWorkflow = () => {
    const failFlag =
      failThreshold === 'smart'
        ? '--fail-on=critical'
        : failThreshold === 'strict'
        ? `--fail-on=warning --min-score=${minScore}`
        : '--fail-on=none';

    return `name: Zelsis Pre-Flight Release Gate

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  zelsis-audit:
    name: 🛡️ Zelsis Deployment Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Run Zelsis Pre-Flight Gate
        env:
          ZELSIS_API_TOKEN: \${{ secrets.ZELSIS_API_TOKEN }}
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          npx zelsis audit ${failFlag} \\
            --project="${projectName}" \\
            --post-pr-comment=true \\
            --output-report=zelsis-report.json

      - name: Upload Gate Audit Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zelsis-release-scorecard
          path: zelsis-report.json
`;
  };

  const generateZelsisConfig = () => {
    return JSON.stringify(
      {
        $schema: 'https://zelsis.com/schemas/v1/zelsisrc.json',
        projectName,
        minScoreThreshold: minScore,
        failStrategy: failThreshold,
        gates: {
          security: { enabled: enabledGates.security, blockOnOwasp: true },
          legalCompliance: { enabled: enabledGates.compliance, enforceGdprCookieCheck: true, pciCheck: true },
          infraDatabase: { enabled: enabledGates.infra, enforceSupabaseRls: true, blockRootContainers: true },
          designVibePolish: { enabled: enabledGates.vibepolish, banAiCliches: true },
          vibeCareHealth: { enabled: enabledGates.vibecare, enforceWcagFocus: true, enforceCwImage: true }
        },
        ignoreRules: ['UI-201']
      },
      null,
      2
    );
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const downloadFile = (filename: string, content: string) => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header Info */}
      <div className="bg-[#141414] border border-emerald-500/20 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Terminal size={24} className="text-emerald-400" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#EDEDED] m-0">
                Zelsis CI/CD &amp; CLI Automation Hub
              </h1>
              <span className="text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-widest">
                GitHub Actions · Git Hooks · Policy-as-Code · Automated PR Bot
              </span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-[#A1A1AA] mt-3 max-w-3xl leading-relaxed">
            Shift deployment gates left into your active developer pipeline. Automatically enforce security, privacy compliance, and infrastructure checks on every Pull Request before code merges to production.
          </p>
        </div>

        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-bold">
          <GitPullRequest size={16} />
          <span>CI/CD Gate: READY</span>
        </div>
      </div>

      {/* Fail Strategy Threshold Control */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6">
        <h2 className="text-sm font-bold text-[#EDEDED] flex items-center gap-2 mb-4">
          <Sliders size={16} className="text-emerald-400" />
          <span>Smart Fail Threshold Strategy</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <button
            onClick={() => setFailThreshold('smart')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'smart'
                ? 'bg-emerald-500/10 border-emerald-500/40 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-emerald-400">Smart Mode (Recommended)</span>
              <span className="text-[10px] font-mono bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded">High Velocity</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Strictly blocks PR merge on <strong className="text-white">CRITICAL</strong> Security, Legal, or Database violations. Posts informational markdown checklists for VibePolish warnings without breaking builds.
            </p>
          </button>

          <button
            onClick={() => setFailThreshold('strict')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'strict'
                ? 'bg-amber-500/10 border-amber-500/40 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-amber-400">Strict Enforcement</span>
              <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded">Zero Tolerance</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Fails the PR build if overall readiness score drops below <strong className="text-white">{minScore}/100</strong> or if any High/Medium issues remain unaccepted.
            </p>
          </button>

          <button
            onClick={() => setFailThreshold('advisory')}
            className={`p-4 rounded-xl border text-left transition-all ${
              failThreshold === 'advisory'
                ? 'bg-blue-500/10 border-blue-500/40 shadow-sm'
                : 'bg-black/30 border-white/5 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-blue-400">Advisory / Audit Only</span>
              <span className="text-[10px] font-mono bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">Observation</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed m-0">
              Never fails PR builds. Runs complete static AST audits and publishes an official Release Scorecard report directly as a PR comment.
            </p>
          </button>
        </div>

        {failThreshold === 'strict' && (
          <div className="bg-black/40 border border-white/5 rounded-xl p-4 flex items-center justify-between gap-4">
            <div className="text-xs text-zinc-400">
              <span className="font-bold text-white block mb-0.5">Minimum Required Score Threshold:</span>
              <span>PRs with score lower than {minScore}/100 will fail the CI check.</span>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min="60"
                max="95"
                value={minScore}
                onChange={(e) => setMinScore(Number(e.target.value))}
                className="w-32 accent-emerald-500 cursor-pointer"
              />
              <span className="font-mono font-bold text-emerald-400 text-sm">{minScore} / 100</span>
            </div>
          </div>
        )}
      </div>

      {/* GitHub Actions Workflow Block */}
      <div className="bg-[#141414] border border-white/10 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-sm font-bold text-[#EDEDED] flex items-center gap-2 m-0">
              <GitPullRequest size={16} className="text-emerald-400" />
              <span>.github/workflows/zelsis.yml</span>
            </h2>
            <span className="text-xs text-[#A1A1AA]">
              Drop this file into your repository to enforce pre-flight PR gates automatically.
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => copyToClipboard(generateGithubWorkflow(), setCopiedWorkflow)}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-[#EDEDED] text-xs font-mono transition-colors flex items-center gap-1.5"
            >
              {copiedWorkflow ? (
                <>
                  <CheckCircle2 size={14} className="text-emerald-400" />
                  <span className="text-emerald-400 font-bold">Copied</span>
                </>
              ) : (
                <>
                  <Copy size={14} className="text-zinc-400" />
                  <span>Copy Workflow</span>
                </>
              )}
            </button>

            <button
              onClick={() => downloadFile('zelsis.yml', generateGithubWorkflow())}
              className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-[#EDEDED] text-xs font-mono transition-colors flex items-center gap-1.5"
            >
              <Download size={14} className="text-zinc-400" />
              <span>Download</span>
            </button>
          </div>
        </div>

        <div className="bg-black/60 border border-white/5 rounded-xl p-4 overflow-x-auto font-mono text-xs">
          <pre className="text-zinc-300 leading-relaxed m-0">{generateGithubWorkflow()}</pre>
        </div>
      </div>

      {/* Two Column Section: Policy as Code & Local CLI */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Policy as Code .zelsisrc.json */}
        <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-3 mb-3">
              <h2 className="text-sm font-bold text-[#EDEDED] flex items-center gap-2 m-0">
                <Settings2 size={16} className="text-cyan-400" />
                <span>Policy as Code (.zelsisrc.json)</span>
              </h2>
              <button
                onClick={() => copyToClipboard(generateZelsisConfig(), setCopiedConfig)}
                className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-[#EDEDED] text-xs font-mono transition-colors flex items-center gap-1"
              >
                {copiedConfig ? <CheckCircle2 size={13} className="text-emerald-400" /> : <Copy size={13} />}
                <span>{copiedConfig ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <p className="text-xs text-[#A1A1AA] mb-4 leading-relaxed">
              Standardize governance across your engineering team by checking in your custom gate requirements.
            </p>
            <div className="bg-black/60 border border-white/5 rounded-xl p-3.5 overflow-x-auto font-mono text-xs mb-4">
              <pre className="text-cyan-300/90 leading-relaxed m-0">{generateZelsisConfig()}</pre>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 pt-3 border-t border-white/5">
            {Object.keys(enabledGates).map((gateKey) => {
              const k = gateKey as keyof typeof enabledGates;
              return (
                <label key={k} className="flex items-center gap-2 cursor-pointer text-xs font-mono text-zinc-300">
                  <input
                    type="checkbox"
                    checked={enabledGates[k]}
                    onChange={(e) => setEnabledGates({ ...enabledGates, [k]: e.target.checked })}
                    className="rounded accent-emerald-500 cursor-pointer"
                  />
                  <span className="capitalize">{k}</span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Local CLI Command & Pre-commit Hooks */}
        <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold text-[#EDEDED] flex items-center gap-2 mb-3">
              <Terminal size={16} className="text-emerald-400" />
              <span>Local CLI &amp; Pre-Commit Hook</span>
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-4 leading-relaxed">
              Catch vulnerabilities in terminal before code is even committed to Git.
            </p>

            <div className="bg-black/60 border border-white/5 rounded-xl p-4 mb-4">
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block mb-2">
                1. Run Pre-Flight Audit in Terminal
              </span>
              <div className="flex items-center justify-between gap-2 font-mono text-xs text-emerald-400">
                <code>npx zelsis audit --fail-on=critical</code>
                <button
                  onClick={() => copyToClipboard('npx zelsis audit --fail-on=critical', setCopiedCli)}
                  className="p-1 hover:text-white transition-colors"
                  title="Copy CLI command"
                >
                  {copiedCli ? <CheckCircle2 size={14} className="text-emerald-400" /> : <Copy size={14} />}
                </button>
              </div>
            </div>

            <div className="bg-black/60 border border-white/5 rounded-xl p-4">
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block mb-2">
                2. Install Git Pre-Commit Hook (Husky)
              </span>
              <pre className="font-mono text-xs text-zinc-300 leading-relaxed m-0 overflow-x-auto">
{`npx husky add .husky/pre-commit "npx zelsis audit --fail-on=critical"`}
              </pre>
            </div>
          </div>

          <div className="text-xs font-mono text-zinc-500 pt-4 mt-4 border-t border-white/5 flex items-center gap-2">
            <ShieldCheck size={14} className="text-emerald-400 shrink-0" />
            <span>Blocks unvetted API secrets and database leaks before git push.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
