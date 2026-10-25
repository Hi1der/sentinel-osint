import React, { useState } from 'react';
import { 
  Shield, 
  Search, 
  Briefcase, 
  ChevronDown, 
  Plus, 
  Activity, 
  ExternalLink,
  Lock,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';

interface TopBarProps {
  onOpenNewCaseModal: () => void;
  onOpenQuickScanModal: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({ onOpenNewCaseModal, onOpenQuickScanModal }) => {
  const { cases, activeCase, setActiveCase, setActiveView, setSearchQuery } = useCase();
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);
  const [globalQuery, setGlobalQuery] = useState('');

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (globalQuery.trim()) {
      setSearchQuery(globalQuery.trim());
      setActiveView('search');
    }
  };

  return (
    <header className="h-14 bg-[#0F172A] border-b border-slate-800 flex items-center justify-between px-4 gap-4 select-none shrink-0 z-30">
      {/* Zone 1: Wordmark & Core Breadcrumb */}
      <div className="flex items-center gap-3 shrink-0">
        <button 
          onClick={() => setActiveView('overview')}
          className="font-bold text-slate-100 tracking-tight text-base whitespace-nowrap font-mono flex items-center gap-2 hover:opacity-90 transition-opacity"
        >
          <div className="w-7 h-7 rounded bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <span>SENTINEL <span className="text-cyan-400">OSINT</span></span>
        </button>

        <div className="hidden lg:flex items-center text-xs text-slate-400 gap-1.5 ml-2 border-l border-slate-800 pl-3">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span className="font-mono text-[11px] text-slate-300">PASSIVE RECON</span>
        </div>
      </div>

      {/* Zone 2: Active Case Selector & Quick Search */}
      <div className="flex-1 max-w-2xl flex items-center gap-3">
        {/* Case Switcher Dropdown */}
        <div className="relative">
          <button
            onClick={() => setCaseDropdownOpen(!caseDropdownOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:border-slate-700 hover:text-slate-100 transition-colors whitespace-nowrap"
            title="Switch Active Investigation Case"
          >
            <Briefcase className="w-3.5 h-3.5 text-cyan-400" />
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-cyan-300 font-medium">{activeCase ? activeCase.case_number : 'NO CASE'}</span>
              <span className="text-slate-500">·</span>
              <span className="max-w-[160px] truncate">{activeCase ? activeCase.title : 'Select Case'}</span>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-500 ml-1" />
          </button>

          {caseDropdownOpen && (
            <div 
              className="absolute left-0 mt-1 w-80 bg-slate-900 border border-slate-700 rounded shadow-xl py-1 z-50 text-xs"
              onMouseLeave={() => setCaseDropdownOpen(false)}
            >
              <div className="px-3 py-1.5 border-b border-slate-800 flex items-center justify-between text-slate-400">
                <span className="font-medium text-[11px] tracking-wider uppercase font-mono">Active Cases</span>
                <button
                  onClick={() => {
                    setCaseDropdownOpen(false);
                    onOpenNewCaseModal();
                  }}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono text-[11px]"
                >
                  <Plus className="w-3 h-3" /> New Case
                </button>
              </div>

              <div className="max-h-60 overflow-y-auto">
                {cases.map((c) => (
                  <button
                    key={c.id}
                    onClick={() => {
                      setActiveCase(c);
                      setCaseDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-2 flex items-start gap-2 hover:bg-slate-800/80 transition-colors ${
                      activeCase?.id === c.id ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : ''
                    }`}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-cyan-300 font-semibold">{c.case_number}</span>
                        {c.is_demo && (
                          <span className="inline-flex items-center gap-1 font-mono text-[10px] text-amber-400">
                            <span className="w-1 h-1 rounded-full bg-amber-400" />
                            DEMO
                          </span>
                        )}
                        <span className="text-[10px] text-slate-500 font-mono ml-auto">{c.status}</span>
                      </div>
                      <p className="text-slate-300 truncate mt-0.5">{c.title}</p>
                      <p className="text-slate-500 text-[11px] font-mono truncate mt-0.5">
                        Scope: {c.scope.domains.join(', ')}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Global Fast Search */}
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={globalQuery}
            onChange={(e) => setGlobalQuery(e.target.value)}
            placeholder="Search FQDN, IP, ASN, SHA-256 hash or evidence ID..."
            className="w-full bg-slate-900 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </form>
      </div>

      {/* Zone 3: Primary Action & User Profile */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onOpenQuickScanModal}
          className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors shadow-sm whitespace-nowrap"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Launch Passive Job</span>
        </button>

        <div className="hidden md:flex items-center gap-2 border-l border-slate-800 pl-3">
          <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[11px] font-mono text-cyan-300">
            SO
          </div>
          <div className="flex flex-col text-left">
            <span className="text-xs text-slate-300 font-mono leading-none">s30408390</span>
            <span className="text-[10px] text-slate-500 font-mono mt-0.5">Authorized Analyst</span>
          </div>
        </div>
      </div>
    </header>
  );
};
