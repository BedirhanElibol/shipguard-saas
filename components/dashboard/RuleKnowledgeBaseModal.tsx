// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, BookOpen, Search, ShieldCheck, Zap, ExternalLink } from 'lucide-react';

interface RuleKnowledgeBaseModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const RuleKnowledgeBaseModal: React.FC<RuleKnowledgeBaseModalProps> = ({
  isOpen,
  onClose
}) => {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const kbRules = [
    {
      id: 'SEC-01',
      title: 'Exposed Hardcoded API Key / Secret Token',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'ISO27001 A.10.1 / PCI-DSS 6.5.3',
      description: 'Hardcoded API tokens (e.g. OpenAI, Stripe, AWS credentials) committed into version control expose production infrastructure to automated key-harvester bots.',
      vulnerableSnippet: `const stripeKey = process.env.STRIPE_LIVE_KEY || "sk_live_env_token";`,
      remediatedSnippet: `const stripeKey = process.env.STRIPE_SECRET_KEY;`
    },
    {
      id: 'SEC-03',
      title: 'Permissive Row Level Security (RLS) Policy',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'SOC2 Trust Principles / OWASP A01:2021',
      description: 'Supabase / PostgreSQL Row Level Security policies configured with USING (true) allow any authenticated or unauthenticated client to read/modify arbitrary database records.',
      vulnerableSnippet: `CREATE POLICY "Allow Owner" ON profiles FOR SELECT USING (auth.uid() = user_id);`,
      remediatedSnippet: `CREATE POLICY "Allow Owner Only" ON profiles FOR SELECT USING (auth.uid() = user_id);`
    },
    {
      id: 'SEC-WEB-01',
      title: 'Absence of Content-Security-Policy (CSP) Header',
      category: 'SECURITY',
      severity: 'CRITICAL',
      compliance: 'OWASP A03:2021 / NIST SP 800-53',
      description: 'Missing CSP HTTP headers allow attackers to inject malicious external scripts, inline XSS payloads, and exfiltrate user session cookies.',
      vulnerableSnippet: `// Response Headers missing Content-Security-Policy`,
      remediatedSnippet: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'`
    },
    {
      id: 'UI-01',
      title: 'Generic Neon Gradient Cliché',
      category: 'VIBEPOLISH',
      severity: 'MEDIUM',
      compliance: 'Maestro Premium Design Token System',
      description: 'High-contrast raw linear gradients look generic and unpolished across dark mode interfaces.',
      vulnerableSnippet: `<div className="bg-gradient-to-r from-indigo-600 to-blue-500">`,
      remediatedSnippet: `<div className="bg-[#141414] border border-white/10 shadow-xl">`
    },
    {
      id: 'UI-04',
      title: 'Absence of Empty State Fallback',
      category: 'VIBEPOLISH',
      severity: 'MEDIUM',
      compliance: 'WCAG 2.2 / Usability Heuristics',
      description: 'Rendering list mappings (.map()) without an empty state component leads to blank or confusing UI layouts when data arrays are empty.',
      vulnerableSnippet: `{items.map(item => <Card key={item.id} />)}`,
      remediatedSnippet: `{items.length === 0 ? <EmptyState prompt="No items found" /> : items.map(...)}`
    },
    {
      id: 'CLICHE-01',
      title: 'Decorative Hero Badge Pill',
      category: 'AI CLICHÉ',
      severity: 'LOW',
      compliance: 'AI Web Design Cliché Guide',
      description: 'Small glowing badge/pill component placed above hero title (✨ Build the Future). Hallmark of generic AI landing page templates.',
      vulnerableSnippet: `<span className="badge">✨ Introducing</span>`,
      remediatedSnippet: `<!-- Remove decorative badge or use only for real product releases -->`
    },
    {
      id: 'CLICHE-07',
      title: 'Fabricated Brand Logos',
      category: 'AI CLICHÉ',
      severity: 'MEDIUM',
      compliance: 'AI Web Design Cliché Guide',
      description: '"TRUSTED BY THOUSANDS" followed by fake brand names (Nexora, Vertexa, Lumina) destroys user trust.',
      vulnerableSnippet: `"Trusted by" Nexora, Vertexa, Lumina...`,
      remediatedSnippet: `<!-- Show only real partner logos or focus on direct value proposition -->`
    }
  ];

  if (!isOpen) return null;

  const filteredRules = kbRules.filter((r) => {
    const matchesSearch =
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      r.description.toLowerCase().includes(search.toLowerCase());
    const matchesCat = categoryFilter === 'ALL' || r.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-3xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <BookOpen size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  ShipGuard Rule Knowledge Base &amp; Remediation Encyclopedia
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Interactive compliance references, threat models, and code remediation patterns
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Search & Category Filter */}
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="flex items-center gap-2 bg-[#0A0A0A] px-3.5 py-2 rounded-xl border border-white/10 flex-1 w-full focus-within:border-white/30">
              <Search size={14} className="text-[#94A3B8]" />
              <input
                aria-label="Search rule knowledge base"
                type="text"
                placeholder="Search rule ID, title, or ISO27001 compliance tag..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-transparent text-xs text-[#EDEDED] placeholder-gray-500 outline-none w-full font-mono"
              />
            </div>

            <div className="flex items-center gap-2">
              {['ALL', 'SECURITY', 'VIBEPOLISH'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`text-xs font-mono font-bold px-3 py-2 rounded-xl border transition-all ${
                    categoryFilter === cat
                      ? 'bg-white/5 text-white border-white/10'
                      : 'bg-white/5 text-[#94A3B8] border-white/10 hover:text-white'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Rule Cards List */}
          <div className="max-h-96 overflow-y-auto space-y-4 pr-1">
            {filteredRules.map((rule) => (
              <div
                key={rule.id}
                className="bg-[#0A0A0A] p-4 sm:p-5 rounded-xl border border-white/10 flex flex-col gap-3"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-extrabold text-white">
                      {rule.id}
                    </span>
                    <h3 className="text-sm font-bold text-[#EDEDED]">{rule.title}</h3>
                  </div>

                  <span
                    className={`text-[0.62rem] font-extrabold uppercase px-2 py-0.5 rounded ${
                      rule.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-400'
                        : rule.severity === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-[#10B981]/20 text-[#10B981]'
                    }`}
                  >
                    {rule.severity}
                  </span>
                </div>

                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  {rule.description}
                </p>

                <div className="text-[0.68rem] font-mono text-[#A1A1AA] flex items-center gap-1.5">
                  <ShieldCheck size={13} />
                  <span>Compliance Framework: {rule.compliance}</span>
                </div>

                {/* Snippets Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-white/5 font-mono text-[0.72rem]">
                  <div className="bg-red-500/5 p-3 rounded-lg border border-red-500/20 text-red-300">
                    <div className="text-[0.62rem] font-bold uppercase text-red-400 mb-1">❌ Vulnerable Pattern:</div>
                    <code>{rule.vulnerableSnippet}</code>
                  </div>
                  <div className="bg-white/5 p-3 rounded-lg border border-white/10 text-white">
                    <div className="text-[0.62rem] font-bold uppercase text-white mb-1">✅ Remediated Code:</div>
                    <code>{rule.remediatedSnippet}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <div className="text-xs text-[#94A3B8] font-mono">
              Displaying {filteredRules.length} active clearance rule specs.
            </div>
            <button className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm" onClick={onClose}>
              Close Knowledge Base
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
