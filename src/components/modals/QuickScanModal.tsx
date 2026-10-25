import React, { useState, useEffect } from 'react';
import { X, Activity, ShieldCheck, ShieldAlert, CheckCircle2, AlertTriangle, Layers, ArrowRight } from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';

interface QuickScanModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const QuickScanModal: React.FC<QuickScanModalProps> = ({ isOpen, onClose }) => {
  const { activeCase, showNotification, setActiveView, quickScanPrefill } = useCase();

  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('DOMAIN');
  const [selectedCollectors, setSelectedCollectors] = useState<string[]>([
    'col_doh_cloudflare',
    'col_crt_sh',
  ]);
  const [scopeCheckResult, setScopeCheckResult] = useState<{ in_scope: boolean; reason?: string } | null>(null);
  const [checkingScope, setCheckingScope] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync with prefill if passed
  useEffect(() => {
    if (quickScanPrefill) {
      setTarget(quickScanPrefill.target);
      setTargetType(quickScanPrefill.targetType || 'DOMAIN');
      if (quickScanPrefill.collectors && quickScanPrefill.collectors.length > 0) {
        setSelectedCollectors(quickScanPrefill.collectors);
      }
      setScopeCheckResult(null);
    }
  }, [quickScanPrefill, isOpen]);

  if (!isOpen) return null;

  const toggleCollector = (id: string) => {
    setSelectedCollectors((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleValidateScope = async () => {
    if (!activeCase || !target.trim()) return;
    setCheckingScope(true);
    setError(null);
    try {
      const res = await api.validateScope(activeCase.id, target.trim());
      setScopeCheckResult(res);
    } catch (err: any) {
      setError(err.message || 'Scope check failed');
    } finally {
      setCheckingScope(false);
    }
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeCase) {
      setError('An active investigation case must be selected first.');
      return;
    }
    if (!target.trim()) {
      setError('Target identifier is required.');
      return;
    }
    if (selectedCollectors.length === 0) {
      setError('Select at least one passive collector.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const job = await api.dispatchJob({
        case_id: activeCase.id,
        target_identifier: target.trim(),
        target_type: targetType,
        collectors_selected: selectedCollectors,
      });

      showNotification('success', `Passive scan job #${job.job_id.slice(-6)} queued in Job Monitor.`);
      onClose();
      setActiveView('jobs');
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch job');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-[#0F172A] border border-slate-700 rounded-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Launch Passive Reconnaissance Job</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleLaunch} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-200 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Active Case Context */}
          <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
            <div className="min-w-0">
              <span className="text-[10px] text-slate-500 font-mono uppercase block">Active Scope Context</span>
              <span className="font-mono text-cyan-300 font-medium truncate block">
                {activeCase ? `${activeCase.case_number} · ${activeCase.title}` : 'No Case Selected'}
              </span>
            </div>
            {activeCase?.is_demo && (
              <span className="inline-flex items-center gap-1 font-mono text-[10px] text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                DEMO CASE
              </span>
            )}
          </div>

          {/* Target Type Segmented Control */}
          <div className="space-y-1.5">
            <label className="font-medium text-slate-300 block">Target Type</label>
            <div className="grid grid-cols-4 gap-1.5 p-1 bg-slate-950 rounded border border-slate-800 font-mono text-[11px]">
              {[
                { id: 'DOMAIN', label: 'Domain' },
                { id: 'IP', label: 'IP Addr' },
                { id: 'ASN', label: 'ASN' },
                { id: 'EMAIL_DOMAIN', label: 'Email / Org' },
              ].map((t) => (
                <button
                  type="button"
                  key={t.id}
                  onClick={() => setTargetType(t.id)}
                  className={`py-1 rounded text-center transition-colors ${
                    targetType === t.id
                      ? 'bg-slate-800 text-cyan-300 font-semibold shadow-xs border border-slate-700'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Target Input & Scope Verification */}
          <div className="space-y-1.5">
            <label className="font-medium text-slate-300 flex items-center justify-between">
              <span>Target Identifier *</span>
              <span className="text-[10px] text-slate-500 font-mono">Passive Lookup Only</span>
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                required
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value);
                  setScopeCheckResult(null);
                }}
                placeholder="e.g. ironshield-telemetry.org or 198.51.100.42"
                className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
              <button
                type="button"
                onClick={handleValidateScope}
                disabled={checkingScope || !target.trim()}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium border border-slate-700 transition-colors whitespace-nowrap disabled:opacity-50"
              >
                {checkingScope ? 'Checking...' : 'Check Scope'}
              </button>
            </div>

            {/* Scope Pre-fill helpers from Active Case */}
            {activeCase && (activeCase.scope.domains.length > 0 || activeCase.scope.ipRanges.length > 0) && (
              <div className="flex items-center gap-1.5 pt-1 flex-wrap text-[11px] font-mono text-slate-400">
                <span className="text-slate-500 text-[10px]">Pre-fill:</span>
                {activeCase.scope.domains.map((dom) => {
                  const clean = dom.replace(/^\*\./, '');
                  return (
                    <button
                      key={clean}
                      type="button"
                      onClick={() => {
                        setTarget(clean);
                        setTargetType('DOMAIN');
                        setScopeCheckResult(null);
                      }}
                      className="text-cyan-400 hover:underline hover:text-cyan-300 transition-colors"
                    >
                      {clean}
                    </button>
                  );
                })}
                {activeCase.scope.ipRanges.map((ip) => (
                  <button
                    key={ip}
                    type="button"
                    onClick={() => {
                      setTarget(ip.split('/')[0]);
                      setTargetType('IP');
                      setScopeCheckResult(null);
                    }}
                    className="text-emerald-400 hover:underline hover:text-emerald-300 transition-colors"
                  >
                    {ip}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Scope Check Result Feedback */}
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
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Target Authorized Within Case Scope</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                    <span>Target Out of Scope (Query Rejected)</span>
                  </>
                )}
              </div>
              {scopeCheckResult.reason && (
                <p className="mt-1 text-[11px] opacity-90 font-mono">{scopeCheckResult.reason}</p>
              )}
            </div>
          )}

          {/* Collector Selection */}
          <div className="space-y-2">
            <span className="font-medium text-slate-300 block">Select Passive Collectors</span>
            <div className="space-y-1.5">
              {[
                { id: 'col_doh_cloudflare', name: 'Cloudflare DNS over HTTPS', desc: 'Queries authoritative A, AAAA, MX, NS, TXT, SOA via RFC 8484' },
                { id: 'col_crt_sh', name: 'Sectigo crt.sh Certificate Logs', desc: 'Passive Certificate Transparency SAN & Issuer enumeration' },
                { id: 'col_bgpview', name: 'BGPView / RIPE Stat Routing', desc: 'Queries ASN allocation and BGP announced IP prefixes' },
                { id: 'col_rdap', name: 'ICANN / RIR RDAP Registration', desc: 'Authoritative registrar and registration window lookup' },
                { id: 'col_github_recon', name: 'Developer & Person OSINT', desc: 'Passive GitHub developer profile and RFC 5322 email/MX validation' },
              ].map((c) => (
                <label
                  key={c.id}
                  onClick={() => toggleCollector(c.id)}
                  className={`flex items-start gap-2.5 p-2 rounded border cursor-pointer transition-colors ${
                    selectedCollectors.includes(c.id)
                      ? 'bg-slate-900 border-cyan-700/80'
                      : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedCollectors.includes(c.id)}
                    onChange={() => {}}
                    className="mt-0.5 rounded text-cyan-600 focus:ring-0 bg-slate-900 border-slate-700"
                  />
                  <div className="flex-1 min-w-0">
                    <span className="font-medium text-slate-200 block">{c.name}</span>
                    <span className="text-[11px] text-slate-500 block leading-tight">{c.desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors disabled:opacity-50 flex items-center gap-1.5"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>{submitting ? 'Dispatching...' : 'Dispatch Job'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
