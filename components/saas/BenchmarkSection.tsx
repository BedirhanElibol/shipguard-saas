'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, CheckCircle2, Zap, Lock, Terminal, FileCode2, ArrowRight } from 'lucide-react';

interface BenchmarkItem {
  id: string;
  category: string;
  vulnClass: string;
  targetStack: string;
  cveOwasp: string;
  detected: boolean;
}

const MATRIX_BENCHMARK_16: BenchmarkItem[] = [
  { id: 'BM-01', category: 'Injection', vulnClass: 'Raw SQL Injection', targetStack: 'Node / PostgreSQL / pg', cveOwasp: 'A03:2021-Injection', detected: true },
  { id: 'BM-02', category: 'XSS', vulnClass: 'Unsanitized raw HTML injection (XSS Risk)', targetStack: 'React / Next.js', cveOwasp: 'A03:2021-XSS', detected: true },
  { id: 'BM-03', category: 'Secrets', vulnClass: 'Hardcoded OpenAI API Secret Key', targetStack: 'TypeScript AI Service', cveOwasp: 'A07:2021-Auth Failures', detected: true },
  { id: 'BM-04', category: 'Database', vulnClass: 'Postgres Table Missing Row Level Security (RLS)', targetStack: 'Supabase / PostgreSQL', cveOwasp: 'A01:2021-Broken Access', detected: true },
  { id: 'BM-05', category: 'Secrets', vulnClass: 'Exposed Service Role Key via NEXT_PUBLIC_', targetStack: 'Next.js .env.production', cveOwasp: 'A05:2021-Security Misconfig', detected: true },
  { id: 'BM-06', category: 'SSRF', vulnClass: 'Unvalidated Server-Side fetch() Request', targetStack: 'Next.js Route Handlers', cveOwasp: 'A10:2021-SSRF', detected: true },
  { id: 'BM-07', category: 'RCE', vulnClass: 'Command Injection in child_process.exec', targetStack: 'Node.js Backend', cveOwasp: 'A03:2021-Command Injection', detected: true },
  { id: 'BM-08', category: 'Path Traversal', vulnClass: 'Unsanitized fs.readFileSync path resolution', targetStack: 'Node.js Express / Fastify', cveOwasp: 'A01:2021-Path Traversal', detected: true },
  { id: 'BM-09', category: 'Cryptography', vulnClass: 'Broken Hash Algorithm (MD5 for integrity/passwords)', targetStack: 'Node.js crypto', cveOwasp: 'A02:2021-Crypto Failures', detected: true },
  { id: 'BM-10', category: 'Authentication', vulnClass: 'Unverified JWT Decode (jwt.decode instead of jwt.verify)', targetStack: 'jsonwebtoken / jose', cveOwasp: 'A07:2021-Auth Failures', detected: true },
  { id: 'BM-11', category: 'PRNG', vulnClass: 'Cryptographically Weak Random Token (Math.random)', targetStack: 'Node.js / Browser', cveOwasp: 'A02:2021-Weak Randomness', detected: true },
  { id: 'BM-12', category: 'Session', vulnClass: 'Sensitive Cookie Lacking HttpOnly Flag', targetStack: 'Express / Cookie Parser', cveOwasp: 'A05:2021-Security Misconfig', detected: true },
  { id: 'BM-13', category: 'Redirection', vulnClass: 'Unvalidated Open Redirect (NextResponse.redirect)', targetStack: 'Next.js App Router', cveOwasp: 'A01:2021-Open Redirect', detected: true },
  { id: 'BM-14', category: 'RCE', vulnClass: 'Dynamic Code Execution via String Evaluation', targetStack: 'Node.js JavaScript Engine', cveOwasp: 'A03:2021-Code Execution', detected: true },
  { id: 'BM-15', category: 'Network', vulnClass: 'Wildcard CORS Header with credentials: true', targetStack: 'cors / Express Middleware', cveOwasp: 'A05:2021-Security Misconfig', detected: true },
  { id: 'BM-16', category: 'Database', vulnClass: 'Permissive Supabase RLS Policy (USING Unrestricted)', targetStack: 'Supabase SQL Migrations', cveOwasp: 'A01:2021-Broken Access', detected: true },
];

const NODEGOAT_BENCHMARK: BenchmarkItem[] = [
  { id: 'NG-01', category: 'RCE', vulnClass: 'Remote Code Execution via dynamic tax calculation', targetStack: 'Express / NodeGoat', cveOwasp: 'A03:2021-Injection', detected: true },
  { id: 'NG-02', category: 'NoSQL Injection', vulnClass: 'MongoDB $where Arbitrary JS Injection', targetStack: 'Mongoose / MongoDB', cveOwasp: 'A03:2021-NoSQL Injection', detected: true },
  { id: 'NG-03', category: 'Secrets', vulnClass: 'Hardcoded cookieSecret & cryptoKey in config', targetStack: 'NodeGoat config/env/all.js', cveOwasp: 'A07:2021-Auth Failures', detected: true },
  { id: 'NG-04', category: 'Session', vulnClass: 'Session Cookie Written without HttpOnly', targetStack: 'Express Routes', cveOwasp: 'A05:2021-Security Misconfig', detected: true },
  { id: 'NG-05', category: 'PRNG', vulnClass: 'Session Token Generated with Math.random()', targetStack: 'Session Controller', cveOwasp: 'A02:2021-Crypto Failures', detected: true },
];

export const BenchmarkSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'matrix' | 'nodegoat' | 'comparison'>('matrix');

  return (
    <section id="benchmark" className="py-24 sm:py-32 px-4 sm:px-6 lg:px-12 bg-[#0A0A0A] border-b border-white/10 font-sans relative">
      <div className="max-w-6xl mx-auto flex flex-col gap-12">
        {/* Header */}
        <div className="flex flex-col gap-3 text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 justify-center text-xs font-mono uppercase tracking-widest text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 rounded-full self-center">
            <ShieldCheck size={14} />
            <span>Deterministic Exploit Benchmark</span>
          </div>
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-white tracking-tight">
            100% Detection on Real Exploit Fixtures.
          </h2>
          <p className="text-sm sm:text-base text-zinc-400 leading-relaxed font-sans">
            Unlike surface keyword scanners or slow multi-minute CI jobs, Zelsis is rigorously tested against industry-standard intentional vulnerability matrices and OWASP benchmarks.
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-center gap-2 p-1 rounded-xl bg-[#141414] border border-white/10 max-w-md mx-auto w-full">
          <button
            onClick={() => setActiveTab('matrix')}
            className={`flex-1 py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
              activeTab === 'matrix'
                ? 'bg-white text-black shadow-sm'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            16-Exploit Matrix (16/16)
          </button>
          <button
            onClick={() => setActiveTab('nodegoat')}
            className={`flex-1 py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
              activeTab === 'nodegoat'
                ? 'bg-white text-black shadow-sm'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            OWASP NodeGoat (5/5)
          </button>
          <button
            onClick={() => setActiveTab('comparison')}
            className={`flex-1 py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
              activeTab === 'comparison'
                ? 'bg-white text-black shadow-sm'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Speed &amp; Architecture
          </button>
        </div>

        {/* Tab 1: 16-Exploit Matrix */}
        {activeTab === 'matrix' && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="rounded-2xl border border-white/10 bg-[#121214] overflow-hidden shadow-2xl"
          >
            <div className="p-4 sm:p-6 border-b border-white/10 flex flex-wrap items-center justify-between gap-4 bg-[#0E0E10]">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>Realistic 16-Vulnerability Full-Stack Matrix</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    16 / 16 PASSED (100%)
                  </span>
                </h3>
                <p className="text-xs text-zinc-400 mt-1 font-sans">
                  Evaluated on modern Next.js 15 App Router, Supabase RLS migrations, and Express backend codebases.
                </p>
              </div>
              <div className="text-xs font-mono text-zinc-400 flex items-center gap-3">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={14} className="text-emerald-400" /> Automated Regression Gate</span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141418] border-b border-white/10 text-zinc-400">
                  <tr>
                    <th className="py-3 px-4"># ID</th>
                    <th className="py-3 px-4">Vulnerability Class</th>
                    <th className="py-3 px-4">Target Framework</th>
                    <th className="py-3 px-4">OWASP Classification</th>
                    <th className="py-3 px-4 text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-zinc-300">
                  {MATRIX_BENCHMARK_16.map((item) => (
                    <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-4 text-zinc-400">{item.id}</td>
                      <td className="py-3 px-4 text-white font-medium">{item.vulnClass}</td>
                      <td className="py-3 px-4 text-zinc-400">{item.targetStack}</td>
                      <td className="py-3 px-4 text-zinc-400">{item.cveOwasp}</td>
                      <td className="py-3 px-4 text-center">
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <CheckCircle2 size={11} /> DETECTED
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* Tab 2: OWASP NodeGoat */}
        {activeTab === 'nodegoat' && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="rounded-2xl border border-white/10 bg-[#121214] overflow-hidden shadow-2xl"
          >
            <div className="p-4 sm:p-6 border-b border-white/10 flex flex-wrap items-center justify-between gap-4 bg-[#0E0E10]">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>OWASP NodeGoat Benchmark Suite</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    5 / 5 DETECTED (Gate Blocked)
                  </span>
                </h3>
                <p className="text-xs text-zinc-400 mt-1 font-sans">
                  Official OWASP vulnerable benchmark project assessing Node.js, Express, and MongoDB risk vectors.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141418] border-b border-white/10 text-zinc-400">
                  <tr>
                    <th className="py-3 px-4"># ID</th>
                    <th className="py-3 px-4">NodeGoat Vulnerability</th>
                    <th className="py-3 px-4">Vulnerable Module</th>
                    <th className="py-3 px-4">OWASP Classification</th>
                    <th className="py-3 px-4 text-center">Zelsis Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-zinc-300">
                  {NODEGOAT_BENCHMARK.map((item) => (
                    <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-4 text-zinc-400">{item.id}</td>
                      <td className="py-3 px-4 text-white font-medium">{item.vulnClass}</td>
                      <td className="py-3 px-4 text-zinc-400">{item.targetStack}</td>
                      <td className="py-3 px-4 text-zinc-400">{item.cveOwasp}</td>
                      <td className="py-3 px-4 text-center">
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <CheckCircle2 size={11} /> CRITICAL BLOCKER
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* Tab 3: Speed & Architecture Comparison */}
        {activeTab === 'comparison' && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="grid grid-cols-1 md:grid-cols-3 gap-4"
          >
            <div className="p-6 rounded-2xl border border-white/10 bg-[#121214] flex flex-col justify-between gap-4">
              <div>
                <span className="text-xs font-mono uppercase text-emerald-400 font-bold">Execution Speed</span>
                <h4 className="text-2xl font-extrabold text-white mt-1 tabular-nums">&lt; 3.5 Seconds</h4>
                <p className="text-xs text-zinc-400 mt-2 font-sans leading-relaxed">
                  In-memory AST stream evaluation processes thousands of files directly in RAM. No slow Docker containers or multi-minute CI queues.
                </p>
              </div>
              <div className="text-[11px] font-mono text-zinc-500 border-t border-white/5 pt-3">
                Legacy CI Scanners: 3–8 minutes
              </div>
            </div>

            <div className="p-6 rounded-2xl border border-white/10 bg-[#121214] flex flex-col justify-between gap-4">
              <div>
                <span className="text-xs font-mono uppercase text-emerald-400 font-bold">Code Privacy</span>
                <h4 className="text-2xl font-extrabold text-white mt-1">Zero Retention</h4>
                <p className="text-xs text-zinc-400 mt-2 font-sans leading-relaxed">
                  Ephemeral in-memory buffers are flushed immediately upon score synthesis. Your proprietary code is never persisted to disk, stored in databases, or used for AI model training.
                </p>
              </div>
              <div className="text-[11px] font-mono text-zinc-500 border-t border-white/5 pt-3">
                Cloud SAST: Retains code in cloud buckets
              </div>
            </div>

            <div className="p-6 rounded-2xl border border-white/10 bg-[#121214] flex flex-col justify-between gap-4">
              <div>
                <span className="text-xs font-mono uppercase text-emerald-400 font-bold">Surgical Remediation</span>
                <h4 className="text-2xl font-extrabold text-white mt-1">Unified Git Diffs</h4>
                <p className="text-xs text-zinc-400 mt-2 font-sans leading-relaxed">
                  Every detected vulnerability generates an exact before/after line patch and tailored prompts ready to paste directly into Cursor or Claude Code.
                </p>
              </div>
              <div className="text-[11px] font-mono text-zinc-500 border-t border-white/5 pt-3">
                Abstract alert strings only
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </section>
  );
};
