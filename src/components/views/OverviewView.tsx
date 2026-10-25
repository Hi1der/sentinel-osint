import React, { useEffect, useState } from 'react';
import { 
  Shield, 
  Activity, 
  Server, 
  Network, 
  FileCheck2, 
  Layers, 
  Clock, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowUpRight,
  Plus,
  Play,
  Hash,
  Briefcase,
  Share2,
  Globe,
  Radio,
  Sparkles,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Search
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { ScanJob, EvidenceItem, DataSourceStatus } from '../../types/osint.ts';

interface OverviewViewProps {
  onOpenNewCaseModal: () => void;
  onOpenQuickScanModal: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onOpenNewCaseModal, onOpenQuickScanModal }) => {
  const { 
    cases, 
    activeCase, 
    setActiveCase, 
    setActiveView, 
    stats, 
    refreshStats,
    openEvidenceInInspector,
    showNotification 
  } = useCase();

  const [recentJobs, setRecentJobs] = useState<ScanJob[]>([]);
  const [recentEvidence, setRecentEvidence] = useState<EvidenceItem[]>([]);
  const [sources, setSources] = useState<DataSourceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Quick Recon Bar state
  const [quickTarget, setQuickTarget] = useState('');
  const [quickRunning, setQuickRunning] = useState(false);
  const [selectedCollectors, setSelectedCollectors] = useState<string[]>([
    'col_doh_cloudflare',
    'col_rdap',
    'col_crt_sh'
  ]);

  const loadData = async () => {
    try {
      const [jobsData, evidenceData, sourcesData] = await Promise.all([
        api.fetchJobs(),
        api.fetchEvidence(),
        api.fetchDataSources()
      ]);
      setRecentJobs(jobsData.slice(0, 6));
      setRecentEvidence(evidenceData.slice(0, 8));
      setSources(sourcesData);
    } catch (err) {
      console.error('Failed to load overview data', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    if (activeCase && activeCase.scope.domains.length > 0) {
      setQuickTarget(activeCase.scope.domains[0].replace(/^\*\./, ''));
    }
  }, [activeCase]);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await refreshStats();
    await loadData();
    showNotification('info', 'Workspace data refreshed.');
  };

  const toggleCollector = (id: string) => {
    setSelectedCollectors(prev => 
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleExecuteQuickRecon = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) {
      showNotification('error', 'Select or create an active case first.');
      return;
    }
    if (!quickTarget.trim()) {
      showNotification('error', 'Please enter a target domain or IP.');
      return;
    }
    if (selectedCollectors.length === 0) {
      showNotification('error', 'Select at least one passive collector.');
      return;
    }

    setQuickRunning(true);
    try {
      const job = await api.dispatchJob({
        case_id: activeCase.id,
        target_identifier: quickTarget.trim(),
        target_type: /^(\d{1,3}\.){3}\d{1,3}$/.test(quickTarget.trim()) ? 'IP' : 'DOMAIN',
        collectors_selected: selectedCollectors
      });
      showNotification('success', `Recon job dispatched for ${quickTarget.trim()}. Running in background.`);
      await loadData();
      await refreshStats();
    } catch (err: any) {
      showNotification('error', err.message || 'Failed to dispatch recon job');
    } finally {
      setQuickRunning(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Executive Command Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-lg bg-slate-900 border border-slate-800 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100 tracking-tight font-sans">
              Intelligence Operations Cockpit
            </h1>
            <span className="text-slate-500 text-xs">·</span>
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse inline-block" />
              STRICT PASSIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Real-time passive threat intelligence correlation. Automated RFC 8484 DoH, ICANN/RIR RDAP, Sectigo Certificate Transparency, and RIPE Stat routing.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="p-2 rounded bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
            title="Refresh workspace telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
          <button
            onClick={onOpenNewCaseModal}
            className="px-3.5 py-2 rounded bg-slate-950 hover:bg-slate-800 text-slate-200 text-xs font-medium border border-slate-800 transition-colors flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-400" />
            <span>New Case</span>
          </button>
          <button
            onClick={onOpenQuickScanModal}
            className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors shadow-sm flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Advanced Dispatcher</span>
          </button>
        </div>
      </div>

      {/* One-Click Rapid Reconnaissance Command Center */}
      <div className="p-4 rounded-lg bg-slate-900/80 border border-cyan-900/40 shadow-sm space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold font-sans text-slate-200 tracking-wide uppercase">
              Rapid Target Reconnaissance
            </span>
            <span className="text-slate-500 text-xs">·</span>
            <span className="text-xs text-cyan-300 font-mono">
              Active Context: {activeCase?.case_number || 'No Case'}
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-400">
            Scope Authorized: <span className="text-slate-200 font-semibold">{activeCase?.scope.domains.join(', ') || 'N/A'}</span>
          </div>
        </div>

        <form onSubmit={handleExecuteQuickRecon} className="flex flex-col lg:flex-row items-stretch lg:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
              placeholder="Enter in-scope domain or IP (e.g. ironshield-telemetry.org)"
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 font-mono focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          {/* Collector Quick Toggles */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            {[
              { id: 'col_doh_cloudflare', label: 'DNS (DoH)' },
              { id: 'col_rdap', label: 'RDAP Whois' },
              { id: 'col_crt_sh', label: 'crt.sh Logs' },
              { id: 'col_bgpview', label: 'BGP Routing' },
              { id: 'col_github_recon', label: 'Person OSINT' },
            ].map(col => {
              const isSelected = selectedCollectors.includes(col.id);
              return (
                <button
                  type="button"
                  key={col.id}
                  onClick={() => toggleCollector(col.id)}
                  className={`px-2.5 py-1.5 rounded text-xs transition-colors border font-sans ${
                    isSelected
                      ? 'bg-cyan-950/80 text-cyan-300 border-cyan-700/80 font-medium'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {col.label}
                </button>
              );
            })}
          </div>

          <button
            type="submit"
            disabled={quickRunning || !quickTarget.trim()}
            className="px-5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 shadow-sm whitespace-nowrap"
          >
            {quickRunning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Collecting...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Execute Recon</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Interactive KPI Stat Cards (Clickable navigation) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button
          onClick={() => setActiveView('investigations')}
          className="text-left p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800/80 transition-all hover:bg-slate-900/90 group"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-medium group-hover:text-cyan-300 transition-colors">Active Cases</span>
            <Briefcase className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2 tabular-nums">
            {stats?.active_cases || 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1 flex items-center justify-between">
            <span>Total: {stats?.total_cases || 0} cases</span>
            <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-cyan-400 transition-colors" />
          </div>
        </button>

        <button
          onClick={() => setActiveView('graph')}
          className="text-left p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800/80 transition-all hover:bg-slate-900/90 group"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-medium group-hover:text-blue-300 transition-colors">Correlated Entities</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2 tabular-nums">
            {stats?.total_entities || 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1 flex items-center justify-between">
            <span>{stats?.total_relationships || 0} relationships</span>
            <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-blue-400 transition-colors" />
          </div>
        </button>

        <button
          onClick={() => setActiveView('evidence')}
          className="text-left p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800/80 transition-all hover:bg-slate-900/90 group"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-medium group-hover:text-emerald-300 transition-colors">Evidence Vault</span>
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2 tabular-nums">
            {stats?.total_evidence || 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1 flex items-center justify-between">
            <span>{stats?.demo_items_count || 0} marked demo</span>
            <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-emerald-400 transition-colors" />
          </div>
        </button>

        <button
          onClick={() => setActiveView('audit')}
          className="text-left p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-800/80 transition-all hover:bg-slate-900/90 group"
        >
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-medium group-hover:text-purple-300 transition-colors">Audit Ledger</span>
            <Hash className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2 tabular-nums">
            {stats?.audit_chain_length || 0}
          </div>
          <div className="text-[11px] text-emerald-400 font-mono mt-1 flex items-center justify-between">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" /> SHA-256 Valid
            </span>
            <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-purple-400 transition-colors" />
          </div>
        </button>
      </div>

      {/* Quick Workflows / Module Fast-Nav Strip */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { id: 'graph', label: 'Entity Graph', desc: 'Interactive Topology', icon: Share2, color: 'text-cyan-400' },
          { id: 'domain', label: 'Domain Intel', desc: 'RDAP & WHOIS', icon: Globe, color: 'text-blue-400' },
          { id: 'dns', label: 'DNS Explorer', desc: 'DoH Record Queries', icon: Network, color: 'text-indigo-400' },
          { id: 'certificates', label: 'Certificates', desc: 'crt.sh CT Logs', icon: FileCheck2, color: 'text-amber-400' },
          { id: 'ip-asn', label: 'IP & ASN', desc: 'RIPE Stat Routing', icon: Server, color: 'text-emerald-400' },
          { id: 'reports', label: 'AI Analyst', desc: 'Gemini Threat Dossier', icon: Sparkles, color: 'text-purple-400' },
        ].map(mod => {
          const Icon = mod.icon;
          return (
            <button
              key={mod.id}
              onClick={() => setActiveView(mod.id as any)}
              className="p-3 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 transition-all text-left flex flex-col justify-between"
            >
              <div className="flex items-center justify-between w-full">
                <Icon className={`w-4 h-4 ${mod.color}`} />
                <ArrowUpRight className="w-3 h-3 text-slate-600 hover:text-slate-300" />
              </div>
              <div className="mt-3">
                <span className="text-xs font-semibold text-slate-200 block">{mod.label}</span>
                <span className="text-[10px] text-slate-500 font-mono block mt-0.5">{mod.desc}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Main Grid: Active Cases & Passive Jobs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2 Cols): Active Cases & Recent Evidence */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Cases Section */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Authorized Investigation Cases
                </h2>
              </div>
              <button
                onClick={() => setActiveView('investigations')}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
              >
                View All <ArrowUpRight className="w-3 h-3" />
              </button>
            </div>

            <div className="divide-y divide-slate-800/80">
              {cases.map((c) => {
                const isSelected = activeCase?.id === c.id;
                return (
                  <div
                    key={c.id}
                    className={`p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/40 transition-colors ${
                      isSelected ? 'bg-cyan-950/20' : ''
                    }`}
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className="font-bold text-cyan-400">{c.case_number}</span>
                        <span className="text-slate-600">·</span>
                        <span className={`text-[11px] ${
                          c.priority === 'CRITICAL' ? 'text-rose-400' :
                          c.priority === 'HIGH' ? 'text-amber-400' :
                          'text-slate-300'
                        }`}>
                          {c.priority}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-400 text-[11px]">{c.status}</span>
                        {c.is_demo && (
                          <>
                            <span className="text-slate-600">·</span>
                            <span className="text-amber-400/90 text-[11px]">DEMO</span>
                          </>
                        )}
                      </div>
                      <h3 className="text-xs font-semibold text-slate-200">{c.title}</h3>
                      <div className="flex items-center gap-1 text-[11px] font-mono text-slate-400">
                        <span className="text-slate-500">Authorized Scope:</span>
                        <span className="truncate max-w-md text-slate-300">{c.scope.domains.join(', ')}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {isSelected ? (
                        <span className="px-3 py-1.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-xs font-mono font-medium flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Active Target
                        </span>
                      ) : (
                        <button
                          onClick={() => {
                            setActiveCase(c);
                            showNotification('info', `Active case switched to ${c.case_number}`);
                          }}
                          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors border border-slate-700"
                        >
                          Select Case
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Recent Evidence Vault Items */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Recent Telemetry & Observations
                </h2>
              </div>
              <button
                onClick={() => setActiveView('evidence')}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
              >
                Vault Register <ArrowUpRight className="w-3 h-3" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-2.5">Evidence ID</th>
                    <th className="px-4 py-2.5">Target</th>
                    <th className="px-4 py-2.5">Provider</th>
                    <th className="px-4 py-2.5">Observation Summary</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {recentEvidence.map((ev) => (
                    <tr key={ev.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-2.5 text-cyan-400 font-medium">
                        {ev.id}
                        {ev.is_demo && (
                          <span className="text-amber-400 text-[10px] ml-1.5 font-normal">
                            (DEMO)
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-slate-200 font-medium">{ev.target_identifier}</td>
                      <td className="px-4 py-2.5 text-slate-400">{ev.source_provider}</td>
                      <td className="px-4 py-2.5 text-slate-300 truncate max-w-xs">{ev.normalized_value}</td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          onClick={() => openEvidenceInInspector(ev)}
                          className="text-cyan-400 hover:text-cyan-300 font-medium hover:underline text-[11px]"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column: Running / Recent Jobs & Source Health */}
        <div className="space-y-6">
          {/* Job Monitor Snippet */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Live Job Queue
                </h2>
              </div>
              <button
                onClick={() => setActiveView('jobs')}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
              >
                Monitor <ArrowUpRight className="w-3 h-3" />
              </button>
            </div>

            <div className="divide-y divide-slate-800/60 p-2 space-y-2">
              {recentJobs.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-500 font-mono">
                  No reconnaissance jobs currently running.
                </div>
              ) : (
                recentJobs.map((job) => (
                  <div key={job.job_id} className="p-3 rounded bg-slate-950 border border-slate-800/80 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-300 font-semibold truncate max-w-[150px]">
                        {job.target_identifier}
                      </span>
                      <span className={`font-mono text-[11px] font-medium flex items-center gap-1 ${
                        job.status === 'COMPLETED' ? 'text-emerald-400' :
                        job.status === 'RUNNING' ? 'text-blue-400 animate-pulse' :
                        job.status === 'FAILED' ? 'text-rose-400' :
                        'text-slate-400'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          job.status === 'COMPLETED' ? 'bg-emerald-400' :
                          job.status === 'RUNNING' ? 'bg-blue-400 animate-ping' :
                          'bg-slate-400'
                        }`} />
                        {job.status}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono flex justify-between">
                      <span>{job.collectors_selected.length} collectors</span>
                      <span>{new Date(job.started_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Data Sources Health */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Active Intelligence Integrations
                </h2>
              </div>
              <button
                onClick={() => setActiveView('sources')}
                className="text-xs text-cyan-400 hover:text-cyan-300"
              >
                Configure
              </button>
            </div>

            <div className="p-3 space-y-2">
              {sources.map((src) => (
                <div key={src.id} className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-slate-800/80 text-xs">
                  <div className="min-w-0 pr-2">
                    <span className="font-medium text-slate-200 block truncate">{src.name}</span>
                    <span className="text-[11px] text-slate-500 font-mono block">
                      Limit: {src.rate_limit_per_min} req/min · Today: {src.requests_today}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 font-medium shrink-0 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                    {src.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
