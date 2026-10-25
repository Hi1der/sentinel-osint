import React, { useState } from 'react';
import { 
  X, 
  Copy, 
  Check, 
  ShieldAlert, 
  ShieldCheck, 
  Calendar, 
  Hash, 
  ExternalLink,
  Layers,
  FileCode,
  Tag,
  Network,
  Globe,
  Server,
  FileCheck2,
  Play,
  RotateCw,
  Search,
  Compass
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';

export const ContextualInspector: React.FC = () => {
  const { 
    isInspectorOpen, 
    setIsInspectorOpen, 
    selectedEntity, 
    selectedEvidence,
    activeCase,
    openQuickScan,
    showNotification,
    refreshStats,
    setActiveView
  } = useCase();

  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [pivotLoading, setPivotLoading] = useState<string | null>(null);

  if (!isInspectorOpen || (!selectedEntity && !selectedEvidence)) {
    return null;
  }

  const handleCopy = (text: string, type: 'hash' | 'raw') => {
    navigator.clipboard.writeText(text);
    if (type === 'hash') {
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } else {
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 2000);
    }
  };

  const handleQuickDns = async (domain: string) => {
    if (!activeCase) {
      showNotification('error', 'Select an active case first.');
      return;
    }
    setPivotLoading('dns');
    try {
      const res = await api.executeDnsCollectionApi({
        case_id: activeCase.id,
        target_domain: domain,
        record_types: ['A', 'AAAA', 'MX', 'NS', 'TXT'],
        resolver: 'col_doh_cloudflare'
      });
      showNotification('success', `DoH DNS resolved for ${domain}: ${res.result?.successful_queries || 0} records.`);
      await refreshStats();
      setActiveView('dns');
    } catch (err: any) {
      showNotification('error', err.message || 'DNS query failed');
    } finally {
      setPivotLoading(null);
    }
  };

  const handleQuickRdap = async (target: string) => {
    if (!activeCase) {
      showNotification('error', 'Select an active case first.');
      return;
    }
    setPivotLoading('rdap');
    try {
      const res = await api.executeRdapLookupApi({
        case_id: activeCase.id,
        target
      });
      if (res.success) {
        showNotification('success', `RDAP registration retrieved for ${target}.`);
        await refreshStats();
        setActiveView('domain');
      } else {
        showNotification('error', `RDAP notice: ${res.result?.error || 'No records returned'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'RDAP lookup failed');
    } finally {
      setPivotLoading(null);
    }
  };

  const handleQuickCrt = async (domain: string) => {
    if (!activeCase) {
      showNotification('error', 'Select an active case first.');
      return;
    }
    setPivotLoading('crt');
    try {
      const res = await api.executeCrtLookupApi({
        case_id: activeCase.id,
        target_domain: domain
      });
      if (res.success) {
        showNotification('success', `crt.sh retrieved ${res.result?.total_certs_found || 0} certificates for ${domain}.`);
        await refreshStats();
        setActiveView('certificates');
      } else {
        showNotification('error', `crt.sh notice: ${res.result?.error || 'No records'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'Certificate lookup failed');
    } finally {
      setPivotLoading(null);
    }
  };

  const handleQuickBgp = async (ip: string) => {
    if (!activeCase) {
      showNotification('error', 'Select an active case first.');
      return;
    }
    setPivotLoading('bgp');
    try {
      const res = await api.executeBgpLookupApi({
        case_id: activeCase.id,
        target_ip: ip
      });
      if (res.success) {
        showNotification('success', `BGP routing retrieved for ${ip}: ${res.result?.routing_data?.prefix || 'Prefix mapped'}`);
        await refreshStats();
        setActiveView('ip-asn');
      } else {
        showNotification('error', `BGP notice: ${res.result?.error || 'No routing information'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'BGP lookup failed');
    } finally {
      setPivotLoading(null);
    }
  };

  return (
    <aside className="w-96 bg-[#0B0F19] border-l border-slate-800 flex flex-col h-[calc(100vh-3.5rem)] shrink-0 z-20 text-xs shadow-2xl">
      {/* Header */}
      <div className="h-12 border-b border-slate-800 px-4 flex items-center justify-between bg-slate-900/50">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold text-slate-200">
            {selectedEvidence ? 'Evidence Provenance' : 'Entity Inspector'}
          </span>
          {(selectedEntity?.is_demo || selectedEvidence?.is_demo) && (
            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-amber-400">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              DEMO
            </span>
          )}
        </div>
        <button
          onClick={() => setIsInspectorOpen(false)}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          title="Close Inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {selectedEntity && (
          <>
            {/* Entity Overview */}
            <div className="p-3.5 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-[11px]">
                <span className="uppercase font-mono tracking-wider text-cyan-400 font-semibold">{selectedEntity.entity_type}</span>
                <span className="font-mono text-slate-400 tabular-nums">
                  Confidence {Math.round(selectedEntity.confidence_score * 100)}%
                </span>
              </div>
              <div className="font-mono text-slate-100 text-sm font-semibold break-all">
                {selectedEntity.canonical_value}
              </div>
            </div>

            {/* Quick Pivots Action Strip */}
            <div className="p-3 rounded bg-slate-900/80 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono uppercase tracking-wider">
                <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                  <Compass className="w-3.5 h-3.5 text-cyan-400" />
                  Quick Pivots
                </span>
                <span className="text-[10px] text-slate-500">Passive Only</span>
              </div>

              <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
                {(selectedEntity.entity_type === 'DOMAIN' || selectedEntity.entity_type === 'SUBDOMAIN') && (
                  <>
                    <button
                      onClick={() => handleQuickDns(selectedEntity.canonical_value)}
                      disabled={!!pivotLoading}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {pivotLoading === 'dns' ? <RotateCw className="w-3 h-3 animate-spin" /> : <Network className="w-3 h-3" />}
                      <span>Query DoH</span>
                    </button>

                    <button
                      onClick={() => handleQuickRdap(selectedEntity.canonical_value)}
                      disabled={!!pivotLoading}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {pivotLoading === 'rdap' ? <RotateCw className="w-3 h-3 animate-spin" /> : <Globe className="w-3 h-3" />}
                      <span>Lookup RDAP</span>
                    </button>

                    <button
                      onClick={() => handleQuickCrt(selectedEntity.canonical_value)}
                      disabled={!!pivotLoading}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {pivotLoading === 'crt' ? <RotateCw className="w-3 h-3 animate-spin" /> : <FileCheck2 className="w-3 h-3" />}
                      <span>crt.sh Logs</span>
                    </button>

                    <button
                      onClick={() => openQuickScan({
                        target: selectedEntity.canonical_value,
                        targetType: 'DOMAIN',
                        collectors: ['col_doh_cloudflare', 'col_crt_sh', 'col_rdap']
                      })}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-200 border border-cyan-800 transition-colors"
                    >
                      <Play className="w-3 h-3 text-cyan-400" />
                      <span>Full Scan</span>
                    </button>
                  </>
                )}

                {selectedEntity.entity_type === 'IP_ADDRESS' && (
                  <>
                    <button
                      onClick={() => handleQuickBgp(selectedEntity.canonical_value)}
                      disabled={!!pivotLoading}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {pivotLoading === 'bgp' ? <RotateCw className="w-3 h-3 animate-spin" /> : <Server className="w-3 h-3" />}
                      <span>Trace BGP</span>
                    </button>

                    <button
                      onClick={() => handleQuickRdap(selectedEntity.canonical_value)}
                      disabled={!!pivotLoading}
                      className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {pivotLoading === 'rdap' ? <RotateCw className="w-3 h-3 animate-spin" /> : <Globe className="w-3 h-3" />}
                      <span>RDAP IP</span>
                    </button>

                    <button
                      onClick={() => openQuickScan({
                        target: selectedEntity.canonical_value,
                        targetType: 'IP',
                        collectors: ['col_bgpview', 'col_rdap']
                      })}
                      className="col-span-2 flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-200 border border-cyan-800 transition-colors"
                    >
                      <Play className="w-3 h-3 text-cyan-400" />
                      <span>Scan IP in Recon Queue</span>
                    </button>
                  </>
                )}

                {selectedEntity.entity_type === 'ASN' && (
                  <button
                    onClick={() => openQuickScan({
                      target: selectedEntity.canonical_value,
                      targetType: 'ASN',
                      collectors: ['col_bgpview']
                    })}
                    className="col-span-2 flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-purple-950/60 hover:bg-purple-900/60 text-purple-200 border border-purple-800 transition-colors"
                  >
                    <Server className="w-3 h-3 text-purple-400" />
                    <span>Investigate ASN Routing</span>
                  </button>
                )}

                {(selectedEntity.entity_type === 'ORGANIZATION' || selectedEntity.entity_type === 'EMAIL_DOMAIN' || selectedEntity.entity_type === 'URL') && (
                  <button
                    onClick={() => openQuickScan({
                      target: selectedEntity.canonical_value,
                      targetType: selectedEntity.entity_type === 'EMAIL_DOMAIN' ? 'EMAIL_DOMAIN' : 'DOMAIN',
                      collectors: ['col_github_recon', 'col_rdap']
                    })}
                    className="col-span-2 flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    <Search className="w-3 h-3 text-cyan-400" />
                    <span>Open in Recon Scanner</span>
                  </button>
                )}
              </div>
            </div>

            {/* Timestamps */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase text-slate-500">Observation Window</span>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">First Seen:</span>
                  <span className="text-slate-200 tabular-nums">{new Date(selectedEntity.first_seen).toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Last Seen:</span>
                  <span className="text-slate-200 tabular-nums">{new Date(selectedEntity.last_seen).toLocaleString()}</span>
                </div>
              </div>
            </div>

            {/* Metadata Fields */}
            {selectedEntity.metadata && Object.keys(selectedEntity.metadata).length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[11px] font-mono uppercase text-slate-500">Attributes & Annotations</span>
                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1.5 font-mono text-[11px]">
                  {Object.entries(selectedEntity.metadata).map(([key, val]) => (
                    <div key={key} className="flex flex-col">
                      <span className="text-slate-500 text-[10px] uppercase">{key}</span>
                      <span className="text-slate-200 break-all">{Array.isArray(val) ? val.join(', ') : String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {selectedEvidence && (
          <>
            {/* Evidence Target */}
            <div className="p-3.5 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-400 text-[11px]">
                <span className="font-mono text-cyan-400 font-semibold">{selectedEvidence.id}</span>
                <span className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-300">
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    selectedEvidence.verification_status === 'VERIFIED'
                      ? 'bg-emerald-400'
                      : selectedEvidence.verification_status === 'DEMO'
                      ? 'bg-amber-400'
                      : 'bg-slate-400'
                  }`} />
                  {selectedEvidence.verification_status}
                </span>
              </div>
              <div className="font-mono text-slate-100 text-sm font-semibold break-all">
                {selectedEvidence.target_identifier}
              </div>
              <div className="text-slate-400 text-[11px]">
                Normalized: <span className="font-mono text-slate-200">{selectedEvidence.normalized_value}</span>
              </div>
            </div>

            {/* Source Provenance */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase text-slate-500">Collector Provenance</span>
              <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Provider:</span>
                  <span className="text-slate-200 font-mono font-medium">{selectedEvidence.source_provider}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Retrieval:</span>
                  <span className="text-slate-200 font-mono tabular-nums">{new Date(selectedEvidence.retrieval_timestamp).toLocaleString()}</span>
                </div>
                {selectedEvidence.source_url && (
                  <div className="flex flex-col mt-1">
                    <span className="text-slate-400 mb-0.5">Source URL:</span>
                    <a
                      href={selectedEvidence.source_url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-cyan-400 hover:underline font-mono text-[10px] break-all flex items-center gap-1"
                    >
                      {selectedEvidence.source_url} <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                    </a>
                  </div>
                )}
              </div>
            </div>

            {/* SHA-256 Content Hash */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-500">
                <span className="flex items-center gap-1">
                  <Hash className="w-3 h-3 text-cyan-400" />
                  SHA-256 Digest
                </span>
                <button
                  onClick={() => handleCopy(selectedEvidence.content_hash, 'hash')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 lowercase"
                >
                  {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHash ? 'copied' : 'copy'}</span>
                </button>
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-cyan-300 break-all select-all">
                {selectedEvidence.content_hash}
              </div>
            </div>

            {/* Raw Telemetry Payload */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-500">
                <span className="flex items-center gap-1">
                  <FileCode className="w-3 h-3 text-cyan-400" />
                  Raw Response Payload
                </span>
                <button
                  onClick={() => handleCopy(JSON.stringify(selectedEvidence.raw_payload, null, 2), 'raw')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 lowercase"
                >
                  {copiedRaw ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedRaw ? 'copied' : 'copy json'}</span>
                </button>
              </div>
              <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 overflow-x-auto max-h-60 leading-relaxed">
                {JSON.stringify(selectedEvidence.raw_payload, null, 2)}
              </pre>
            </div>
          </>
        )}
      </div>
    </aside>
  );
};
