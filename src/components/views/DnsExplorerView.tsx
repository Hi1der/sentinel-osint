import React, { useEffect, useState } from 'react';
import { 
  Network, 
  Search, 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  RotateCw, 
  Layers, 
  ExternalLink,
  Copy,
  Check,
  Radio,
  Clock,
  AlertTriangle
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { EvidenceItem } from '../../types/osint.ts';
import { SUPPORTED_DNS_RECORD_TYPES, DnsRecordType } from '../../utils/dnsValidation.ts';

export const DnsExplorerView: React.FC = () => {
  const { activeCase, openEvidenceInInspector, showNotification, refreshStats } = useCase();
  const [dnsEvidence, setDnsEvidence] = useState<EvidenceItem[]>([]);
  const [targetDomain, setTargetDomain] = useState('');
  const [selectedRecordTypes, setSelectedRecordTypes] = useState<DnsRecordType[]>([
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'
  ]);
  const [selectedResolver, setSelectedResolver] = useState<'col_doh_cloudflare' | 'col_doh_google' | 'auto'>('col_doh_cloudflare');
  const [scopeCheckResult, setScopeCheckResult] = useState<{ in_scope: boolean; reason?: string } | null>(null);
  const [checkingScope, setCheckingScope] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [lastExecutionResult, setLastExecutionResult] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');

  const loadDnsEvidence = async () => {
    try {
      const ev = await api.fetchEvidence(activeCase?.id);
      setDnsEvidence(ev.filter((e) => e.collector_id.includes('doh') || e.collector_id.includes('dns') || e.source_provider.toLowerCase().includes('dns')));
    } catch (err) {
      console.error('Failed to load DNS evidence', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDnsEvidence();
    if (activeCase && activeCase.scope.domains.length > 0) {
      // Pre-fill target with first authorized apex domain
      const firstDomain = activeCase.scope.domains[0].replace(/^\*\./, '');
      setTargetDomain(firstDomain);
      setScopeCheckResult(null);
    }
  }, [activeCase]);

  const toggleRecordType = (type: DnsRecordType) => {
    setSelectedRecordTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  const selectAllRecordTypes = () => {
    setSelectedRecordTypes([...SUPPORTED_DNS_RECORD_TYPES]);
  };

  const clearRecordTypes = () => {
    setSelectedRecordTypes([]);
  };

  const handleValidateScope = async () => {
    if (!activeCase || !targetDomain.trim()) return;
    setCheckingScope(true);
    try {
      const res = await api.validateScope(activeCase.id, targetDomain.trim());
      setScopeCheckResult(res);
    } catch (err: any) {
      setScopeCheckResult({ in_scope: false, reason: err.message });
    } finally {
      setCheckingScope(false);
    }
  };

  const handleExecuteDns = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) {
      showNotification('error', 'Select an active investigation case first.');
      return;
    }
    if (!targetDomain.trim()) {
      showNotification('error', 'Enter a target domain name.');
      return;
    }
    if (selectedRecordTypes.length === 0) {
      showNotification('error', 'Select at least one DNS record type to query.');
      return;
    }

    setExecuting(true);
    setLastExecutionResult(null);

    try {
      const res = await api.executeDnsCollectionApi({
        case_id: activeCase.id,
        target_domain: targetDomain.trim(),
        record_types: selectedRecordTypes,
        resolver: selectedResolver,
      });

      setLastExecutionResult(res.result);
      showNotification('success', `DNS collection completed: ${res.result.successful_queries} successful observations.`);
      await loadDnsEvidence();
      await refreshStats();
    } catch (err: any) {
      showNotification('error', err.message || 'DNS collection failed');
      setLastExecutionResult({
        overall_status: 'FAILED',
        error: err.message,
        records: []
      });
    } finally {
      setExecuting(false);
    }
  };

  const filteredEvidence = dnsEvidence.filter((e) => {
    if (!searchFilter.trim()) return true;
    const q = searchFilter.toLowerCase();
    return (
      e.id.toLowerCase().includes(q) ||
      e.target_identifier.toLowerCase().includes(q) ||
      e.normalized_value.toLowerCase().includes(q) ||
      e.source_provider.toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto text-xs">
      {/* Top Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-md">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Passive DNS-over-HTTPS (DoH) Reconnaissance
            </h1>
            <span className="text-slate-500 font-mono text-xs">·</span>
            <span className="text-cyan-400 font-mono text-xs">
              RFC 8484
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative DNS record collection via allowlisted Cloudflare (1.1.1.1) and Google (8.8.8.8) DoH resolvers.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">Total Records:</span>
          <span className="px-2.5 py-1 rounded bg-slate-800 text-cyan-300 border border-slate-700 tabular-nums">
            {dnsEvidence.length}
          </span>
        </div>
      </div>

      {/* Query Console Card */}
      <form onSubmit={handleExecuteDns} className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <span className="font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            DoH Query Controller
          </span>

          {activeCase && (
            <div className="flex items-center gap-2 text-slate-400 font-mono text-[11px]">
              <span>Active Case Scope:</span>
              <span className="text-cyan-300 font-medium">{activeCase.scope.domains.join(', ')}</span>
            </div>
          )}
        </div>

        {/* Target Domain Input & Scope Checker */}
        <div className="space-y-1.5">
          <label className="font-medium text-slate-300 flex items-center justify-between">
            <span>Target Hostname / FQDN *</span>
            <span className="text-slate-500 font-mono text-[11px]">Normalized (lowercase, trailing root dot stripped)</span>
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              required
              value={targetDomain}
              onChange={(e) => {
                setTargetDomain(e.target.value);
                setScopeCheckResult(null);
              }}
              placeholder="e.g. ironshield-telemetry.org or payvault-gateway.io"
              className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500 shadow-inner"
            />
            <button
              type="button"
              onClick={handleValidateScope}
              disabled={checkingScope || !targetDomain.trim()}
              className="px-3 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium border border-slate-700 transition-colors whitespace-nowrap disabled:opacity-50"
            >
              {checkingScope ? 'Validating...' : 'Validate Scope'}
            </button>
          </div>
        </div>

        {/* Scope Feedback */}
        {scopeCheckResult && (
          <div
            className={`p-2.5 rounded text-xs border ${
              scopeCheckResult.in_scope
                ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
                : 'bg-red-950/60 border-red-800 text-red-200'
            }`}
          >
            <div className="flex items-center gap-1.5 font-semibold">
              {scopeCheckResult.in_scope ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Target Authorized Within Case Scope</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  <span>Target Out of Scope (Query Prohibited)</span>
                </>
              )}
            </div>
            {scopeCheckResult.reason && (
              <p className="mt-1 text-[11px] opacity-90 font-mono">{scopeCheckResult.reason}</p>
            )}
          </div>
        )}

        {/* Record Types Selector */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-medium text-slate-300">Select Record Types ({selectedRecordTypes.length}/7)</span>
            <div className="flex gap-2 text-[11px] text-cyan-400">
              <button type="button" onClick={selectAllRecordTypes} className="hover:underline">Select All</button>
              <span className="text-slate-600">·</span>
              <button type="button" onClick={clearRecordTypes} className="hover:underline">Clear</button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
            {SUPPORTED_DNS_RECORD_TYPES.map((type) => {
              const active = selectedRecordTypes.includes(type);
              return (
                <button
                  type="button"
                  key={type}
                  onClick={() => toggleRecordType(type)}
                  className={`py-2 px-3 rounded border font-mono font-bold text-center transition-all ${
                    active
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-300 shadow-sm'
                      : 'bg-slate-950 border-slate-800 text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {type}
                </button>
              );
            })}
          </div>
        </div>

        {/* Resolver Strategy & Execution Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-2 border-t border-slate-800">
          <div className="flex items-center gap-3">
            <span className="font-medium text-slate-300">Resolver:</span>
            <div className="flex gap-2">
              {[
                { id: 'col_doh_cloudflare', label: 'Cloudflare (1.1.1.1)' },
                { id: 'col_doh_google', label: 'Google (8.8.8.8)' },
                { id: 'auto', label: 'Auto Fallback' },
              ].map((res) => (
                <button
                  type="button"
                  key={res.id}
                  onClick={() => setSelectedResolver(res.id as any)}
                  className={`px-2.5 py-1 rounded border text-[11px] font-mono transition-colors ${
                    selectedResolver === res.id
                      ? 'bg-slate-800 border-cyan-500 text-cyan-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {res.label}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={executing || !targetDomain.trim() || selectedRecordTypes.length === 0}
            className="px-5 py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
          >
            {executing ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                <span>Executing Passive Queries...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Execute Passive DNS Query</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Live Execution Feedback Card (if query executed) */}
      {lastExecutionResult && (
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-mono text-slate-200 font-bold uppercase flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Execution Report: {lastExecutionResult.target}
            </span>
            <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
              <span className={`w-1.5 h-1.5 rounded-full ${
                lastExecutionResult.overall_status === 'COMPLETED'
                  ? 'bg-emerald-400'
                  : lastExecutionResult.overall_status === 'PARTIAL_SUCCESS'
                  ? 'bg-amber-400'
                  : 'bg-red-400'
              }`} />
              {lastExecutionResult.overall_status}
            </span>
          </div>

          <div className="space-y-2 font-mono text-[11px]">
            {lastExecutionResult.records?.map((rec: any, idx: number) => (
              <div key={idx} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-400 font-bold">
                    {rec.record_type}
                  </span>
                  <span className="text-slate-300 truncate max-w-xl">{rec.normalized_summary}</span>
                </div>
                <div className="flex items-center gap-2 text-slate-500 text-[10px] shrink-0">
                  <span>{rec.resolver_used}</span>
                  <span className={`px-1.5 py-0.2 rounded border ${
                    rec.is_successful
                      ? 'bg-emerald-950/80 border-emerald-800 text-emerald-400'
                      : 'bg-red-950/80 border-red-800 text-red-400'
                  }`}>
                    {rec.outcome}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Historical DNS Observations Register */}
      <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-lg space-y-2">
        <div className="px-4 py-3 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/60 font-mono">
          <span className="font-semibold text-slate-200">
            Observed DNS Evidence Register ({filteredEvidence.length})
          </span>
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter domain, value, hash..."
              className="w-full bg-slate-900 border border-slate-800 rounded pl-8 pr-3 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="bg-slate-950/80 text-slate-400 text-[10px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Evidence ID</th>
                <th className="px-4 py-3">Domain</th>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Observed Records / Answers</th>
                <th className="px-4 py-3">SHA-256 Digest</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvidence.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    No DNS evidence records collected yet for active case.
                  </td>
                </tr>
              ) : (
                filteredEvidence.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => openEvidenceInInspector(ev)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 text-cyan-400 font-bold">
                      {ev.id}
                    </td>
                    <td className="px-4 py-3 text-slate-100 font-medium">
                      {ev.target_identifier}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {ev.source_provider}
                    </td>
                    <td className="px-4 py-3 text-slate-300 truncate max-w-sm">
                      {ev.normalized_value}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-[10px]">
                      {ev.content_hash.slice(0, 12)}…
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-300">
                        <span className={`w-1.5 h-1.5 rounded-full ${ev.is_demo ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                        {ev.is_demo ? 'DEMO' : 'LIVE'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(evt) => {
                          evt.stopPropagation();
                          openEvidenceInInspector(ev);
                        }}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] border border-slate-700"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
