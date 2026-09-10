// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { Finding } from '@/data/schema';
import { DEMO_AUDIT_FINDINGS } from '@/data/mockData';
import { BulkFixModal } from './BulkFixModal';
import { Search, Filter, ArrowRight, Layers, CheckCircle2, RotateCcw, Play, Zap } from 'lucide-react';

interface FindingsTableProps {
  findings: Finding[];
  onInspectFinding: (f: Finding) => void;
  onTriggerScan?: () => void;
  onLoadDemoFindings?: (demoFindings: Finding[]) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onInspectFinding,
  onTriggerScan,
  onLoadDemoFindings,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [pillarFilter, setPillarFilter] = useState<string>('ALL');
  const [isBulkOpen, setIsBulkOpen] = useState(false);

  const PILLAR_TABS = [
    { id: 'ALL', label: 'All Findings' },
    { id: 'SECURITY', label: 'Security' },
    { id: 'LEGAL_COMPLIANCE', label: 'Legal & Privacy' },
    { id: 'INFRA_DATABASE', label: 'Infra & DB' },
    { id: 'VIBEPOLISH', label: 'VibePolish UI' },
  ];

  const getPillarBadgeStyle = (type: string) => {
    return type === 'LEGAL_COMPLIANCE'
      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      : type === 'INFRA_DATABASE'
      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
      : type === 'SECURITY'
      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
      : type === 'VIBEPOLISH'
      ? 'bg-teal-500/10 text-teal-400 border-teal-500/30'
      : 'bg-blue-500/10 text-blue-400 border-blue-500/30';
  };

  const resetFilters = () => {
    setSearchTerm('');
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setPillarFilter('ALL');
  };

  const filtered = findings.filter((f) => {
    const safeSearch = (searchTerm ?? '').toLowerCase();
    const matchesSearch =
      f.title.toLowerCase().includes(safeSearch) ||
      f.filePath.toLowerCase().includes(safeSearch) ||
      f.category.toLowerCase().includes(safeSearch);

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;
    const matchesPillar = pillarFilter === 'ALL' || f.type === pillarFilter;

    return matchesSearch && matchesSeverity && matchesStatus && matchesPillar;
  });

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-4 sm:p-6 flex flex-col gap-5 bg-[#141414] border-white/10">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-base sm:text-lg font-extrabold text-[#EDEDED]">
              Audit Findings &amp; Risk Inventory
            </h2>
            {findings.length > 0 && (
              <button
                onClick={() => setIsBulkOpen(true)}
                className="btn btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 border-white/10 text-white hover:bg-white/5"
              >
                <Layers size={13} />
                <span>Bulk Remediate .patch</span>
              </button>
            )}
          </div>
          <div className="text-xs text-[#A1A1AA] mt-0.5">
            Operational audit mapping of security vulnerabilities &amp; UI anti-patterns
          </div>
        </div>

        <BulkFixModal
          isOpen={isBulkOpen}
          onClose={() => setIsBulkOpen(false)}
          findings={findings}
          projectName="Target-Project"
        />

        {/* Search & Filters */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          {/* Search Box */}
          <div className="flex items-center gap-2 bg-[#0A0A0A] px-3 py-1.5 rounded-lg border border-white/10 flex-1 sm:w-64">
            <Search size={14} className="text-[#A1A1AA]" />
            <input
              aria-label="Search filter input"
              type="text"
              placeholder="Search findings or files..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent text-xs text-[#EDEDED] outline-none w-full placeholder:text-[#A1A1AA]"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-2 bg-[#0A0A0A] px-3 py-1.5 rounded-lg border border-white/10">
            <Filter size={14} className="text-[#A1A1AA]" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs font-bold text-[#EDEDED] outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-[#141414]">All Severities</option>
              <option value="CRITICAL" className="bg-[#141414] text-[#EF4444]">Critical</option>
              <option value="HIGH" className="bg-[#141414] text-[#F97316]">High</option>
              <option value="MEDIUM" className="bg-[#141414] text-[#F59E0B]">Medium</option>
              <option value="LOW" className="bg-[#141414] text-white">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Pillar Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-white/5">
        {PILLAR_TABS.map((tab) => {
          const isActive = pillarFilter === tab.id;
          const count =
            tab.id === 'ALL'
              ? findings.length
              : findings.filter((f) => f.type === tab.id).length;
          return (
            <button
              key={tab.id}
              onClick={() => setPillarFilter(tab.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all flex items-center gap-2 whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-white text-black font-extrabold shadow-sm'
                  : 'bg-white/5 text-[#A1A1AA] hover:text-white hover:bg-white/10 border border-white/5'
              }`}
            >
              <span>{tab.id === 'LEGAL_COMPLIANCE' ? '⚖️ ' + tab.label : tab.label}</span>
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] ${
                  isActive ? 'bg-black/15 text-black font-bold' : 'bg-white/10 text-[#EDEDED]'
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Mobile Stacked Card View (block md:hidden) */}
      <div className="block md:hidden space-y-3">
        {filtered.length === 0 ? (
          findings.length === 0 ? (
            <div className="p-6 rounded-xl bg-[#0A0A0A] border border-white/10 text-center flex flex-col items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 text-white flex items-center justify-center">
                <CheckCircle2 size={20} className="text-white" />
              </div>
              <div>
                <h3 className="text-sm font-extrabold text-[#EDEDED]">No Audit Findings</h3>
                <p className="text-xs text-[#A1A1AA] mt-1 leading-relaxed">
                  This project has 0 reported vulnerabilities or has not yet undergone release gate scanning.
                </p>
              </div>
              <div className="flex flex-col w-full gap-2 pt-1">
                {onLoadDemoFindings && (
                  <button
                    type="button"
                    onClick={() => onLoadDemoFindings(DEMO_AUDIT_FINDINGS)}
                    className="btn btn-primary py-2.5 px-3 text-xs font-bold w-full flex items-center justify-center gap-2 rounded-xl bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
                  >
                    <Zap size={14} />
                    <span>Load 1-Click Demo Template</span>
                  </button>
                )}
                {onTriggerScan && (
                  <button
                    type="button"
                    onClick={onTriggerScan}
                    className="btn btn-secondary py-2 px-3 text-xs font-mono font-bold w-full flex items-center justify-center gap-2"
                  >
                    <Play size={13} />
                    <span>Run New Audit Scan</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="p-6 rounded-xl bg-[#0A0A0A] border border-white/10 text-center flex flex-col items-center gap-3">
              <p className="text-xs text-[#A1A1AA]">
                No findings match the active search or filter rules.
              </p>
              <button
                type="button"
                onClick={resetFilters}
                className="btn btn-secondary btn-sm text-xs font-mono font-bold flex items-center gap-1.5"
              >
                <RotateCcw size={12} />
                <span>Reset Filters</span>
              </button>
            </div>
          )
        ) : (
          filtered.map((item) => (
            <div
              key={item.id}
              onClick={() => onInspectFinding(item)}
              className="p-4 rounded-xl bg-[#0A0A0A] border border-white/10 hover:border-white/10 transition-all flex flex-col gap-3 cursor-pointer active:scale-[0.99]"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`badge ${
                      item.severity === 'CRITICAL'
                        ? 'badge-critical'
                        : item.severity === 'HIGH'
                        ? 'badge-high'
                        : item.severity === 'MEDIUM'
                        ? 'badge-medium'
                        : 'badge-passed'
                    }`}
                  >
                    {item.severity}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[0.68rem] font-bold font-mono border ${getPillarBadgeStyle(
                      item.type
                    )}`}
                  >
                    {item.type === 'LEGAL_COMPLIANCE' ? '⚖️ Legal & Privacy' : item.type}
                  </span>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[0.68rem] font-bold ${
                    item.status === 'RESOLVED'
                      ? 'bg-white/5 text-white border border-white/10'
                      : 'bg-red-500/10 text-red-400 border border-red-500/30'
                  }`}
                >
                  {item.status}
                </span>
              </div>

              <div>
                <h3 className="text-xs font-extrabold text-[#EDEDED] leading-snug">
                  {item.title}
                </h3>
                <div className="flex flex-wrap items-center gap-2 mt-1.5">
                  <span className="px-1.5 py-0.5 rounded bg-white/10 text-white font-semibold text-[0.68rem]">
                    {item.category}
                  </span>
                  <span className="text-[0.7rem] font-mono text-[#A1A1AA] truncate max-w-[220px]">
                    {item.filePath} ({item.lineRange})
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5 flex items-center justify-end">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onInspectFinding(item);
                  }}
                  className="btn btn-secondary btn-sm text-[0.7rem] px-3 py-1.5 w-full flex items-center justify-center gap-1.5"
                >
                  <span>Inspect &amp; Remediate</span>
                  <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Dense B2B Data Table (Desktop md+) */}
      <div className="hidden md:block overflow-x-auto border border-white/10 rounded-xl">
        <table className="w-full text-left text-xs text-[#EDEDED]">
          <thead className="bg-[#0A0A0A] text-[#A1A1AA] uppercase font-mono font-bold border-b border-white/10">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Pillar</th>
              <th className="py-3 px-4">Finding Title</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Affected Area</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-10 text-center">
                  {findings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center gap-3">
                      <div className="w-12 h-12 rounded-xl bg-white/10 border border-white/20 text-white flex items-center justify-center">
                        <CheckCircle2 size={24} className="text-white" />
                      </div>
                      <div>
                        <h4 className="text-sm font-extrabold text-white">No Audit Findings</h4>
                        <p className="text-xs text-[#A1A1AA] mt-1 max-w-sm">
                          Zero vulnerabilities detected in the active audit scope. Load sample template to inspect and test remediation workflows.
                        </p>
                      </div>
                      <div className="flex items-center gap-3 pt-2">
                        {onLoadDemoFindings && (
                          <button
                            type="button"
                            onClick={() => onLoadDemoFindings(DEMO_AUDIT_FINDINGS)}
                            className="btn btn-primary btn-sm px-4 py-2 text-xs font-bold flex items-center gap-2"
                          >
                            <Zap size={13} />
                            <span>Load 1-Click Demo Template</span>
                          </button>
                        )}
                        {onTriggerScan && (
                          <button
                            type="button"
                            onClick={onTriggerScan}
                            className="btn btn-secondary btn-sm px-4 py-2 text-xs font-bold flex items-center gap-2"
                          >
                            <Play size={13} />
                            <span>Run New Audit Scan</span>
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center gap-2 py-4">
                      <p className="text-xs text-[#A1A1AA]">
                        No findings match the selected search or filter rules.
                      </p>
                      <button
                        type="button"
                        onClick={resetFilters}
                        className="btn btn-secondary btn-sm text-xs font-bold flex items-center gap-1.5"
                      >
                        <RotateCcw size={12} />
                        <span>Clear Filters</span>
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr
                  key={item.id}
                  className="hover:bg-white/[0.04] transition-colors cursor-pointer"
                  onClick={() => onInspectFinding(item)}
                >
                  {/* Severity Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`badge ${
                        item.severity === 'CRITICAL'
                          ? 'badge-critical'
                          : item.severity === 'HIGH'
                          ? 'badge-high'
                          : item.severity === 'MEDIUM'
                          ? 'badge-medium'
                          : 'badge-passed'
                      }`}
                    >
                      {item.severity}
                    </span>
                  </td>

                  {/* Pillar Badge */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[0.68rem] font-bold font-mono border ${getPillarBadgeStyle(
                        item.type
                      )}`}
                    >
                      {item.type === 'LEGAL_COMPLIANCE' ? '⚖️ Legal & Privacy' : item.type}
                    </span>
                  </td>

                  {/* Title */}
                  <td className="py-3.5 px-4 font-bold text-[#EDEDED] max-w-xs truncate">
                    {item.title}
                  </td>

                  {/* Category */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-white/10 text-white font-semibold text-[0.7rem]">
                      {item.category}
                    </span>
                  </td>

                  {/* Affected Area / File Path */}
                  <td className="py-3.5 px-4 font-mono text-[#A1A1AA] max-w-xs truncate">
                    {item.filePath} ({item.lineRange})
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[0.7rem] font-bold ${
                        item.status === 'RESOLVED'
                          ? 'bg-white/5 text-white border border-white/10'
                          : 'bg-red-500/10 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>

                  {/* Action */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onInspectFinding(item);
                      }}
                      className="btn btn-secondary btn-sm text-[0.7rem] px-3 py-1"
                    >
                      <span>Inspect</span>
                      <ArrowRight size={12} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
