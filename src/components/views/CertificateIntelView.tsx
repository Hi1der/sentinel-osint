import React, { useEffect, useState } from 'react';
import { 
  FileCheck2, 
  Search, 
  Calendar, 
  ShieldCheck, 
  Lock, 
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { Entity, EvidenceItem } from '../../types/osint.ts';

export const CertificateIntelView: React.FC = () => {
  const { activeCase, openEntityInInspector, openEvidenceInInspector, showNotification } = useCase();
  const [certEntities, setCertEntities] = useState<Entity[]>([]);
  const [certEvidence, setCertEvidence] = useState<EvidenceItem[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [queryingCt, setQueryingCt] = useState(false);

  const loadData = async () => {
    try {
      const [ent, ev] = await Promise.all([
        api.fetchEntities(activeCase?.id),
        api.fetchEvidence(activeCase?.id),
      ]);
      setCertEntities(ent.filter((e) => e.entity_type === 'SSL_CERTIFICATE'));
      setCertEvidence(ev.filter((e) => e.collector_id.includes('crt')));
    } catch (err) {
      console.error('Failed to load certificate intel', err);
    }
  };

  useEffect(() => {
    loadData();
    if (activeCase?.scope?.domains?.[0]) {
      const firstDomain = activeCase.scope.domains[0].replace(/^\*\./, '');
      setSelectedTarget(firstDomain);
    }
  }, [activeCase]);

  const handleQueryCt = async (targetDomain?: string) => {
    const domain = targetDomain || selectedTarget;
    if (!activeCase || !domain) return;
    setQueryingCt(true);
    try {
      const res = await api.executeCrtLookupApi({
        case_id: activeCase.id,
        target_domain: domain,
      });
      if (res.success) {
        showNotification(
          'success', 
          `crt.sh retrieved ${res.result?.total_certs_found || 0} certificates and ${res.result?.all_discovered_subdomains?.length || 0} subdomains.`
        );
        await loadData();
      } else {
        showNotification('error', `Certificate Transparency error: ${res.result?.error || 'No certificates returned'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'CT log query failed');
    } finally {
      setQueryingCt(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-amber-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              TLS/SSL Certificate & Transparency Intelligence
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Public Certificate Transparency log monitoring via Sectigo crt.sh. Subject Alternative Name (SAN) discovery and CA issuer profiling.
          </p>
        </div>

        {/* Live CT Query Action */}
        {activeCase && (
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              placeholder="e.g. defense-corp.org"
              className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-amber-500 w-48"
            />
            <button
              onClick={() => handleQueryCt()}
              disabled={queryingCt || !selectedTarget.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50 font-mono"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${queryingCt ? 'animate-spin' : ''}`} />
              <span>{queryingCt ? 'Querying crt.sh...' : 'Query crt.sh'}</span>
            </button>
          </div>
        )}
      </div>

      <div className="space-y-4">
        {certEntities.length === 0 ? (
          <div className="p-10 text-center text-slate-500 font-mono text-xs bg-slate-900 rounded-lg border border-slate-800 space-y-3">
            <Lock className="w-10 h-10 text-slate-700 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">No TLS/SSL certificate entities registered in current case scope.</p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Execute a real-time Certificate Transparency query using the button above to ingest public certificates and enumerate subdomains.
            </p>
          </div>
        ) : (
          certEntities.map((cert) => {
            const isExpired = cert.metadata?.is_expired;

            return (
              <div
                key={cert.id}
                onClick={() => openEntityInInspector(cert)}
                className="p-5 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-700/80 transition-all cursor-pointer space-y-3 text-xs shadow-md"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-amber-400 font-semibold text-xs">
                      {cert.display_value}
                    </span>
                    <span className="text-slate-600 font-mono">·</span>
                    <span className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-300">
                      <span className={`w-1.5 h-1.5 rounded-full ${isExpired ? 'bg-red-400' : 'bg-emerald-400'}`} />
                      {isExpired ? 'EXPIRED' : 'VALID'}
                    </span>
                  </div>
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-400">
                    <span className={`w-1.5 h-1.5 rounded-full ${cert.is_demo ? 'bg-amber-400' : 'bg-cyan-400'}`} />
                    {cert.is_demo ? 'DEMO RECORD' : 'VERIFIED CT LOG'}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 space-y-1">
                    <span className="text-slate-500 block uppercase text-[10px]">Issuer Authority</span>
                    <span className="text-slate-200">{cert.metadata?.issuer || 'Unknown CA'}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 space-y-1">
                    <span className="text-slate-500 block uppercase text-[10px]">Serial Number</span>
                    <span className="text-slate-300 truncate block">{cert.canonical_value}</span>
                  </div>
                </div>

                {cert.metadata?.sans && (
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase block">Subject Alternative Names (SANs)</span>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {cert.metadata.sans.slice(0, 10).map((san: string) => (
                        <span key={san} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300">
                          {san}
                        </span>
                      ))}
                      {cert.metadata.sans.length > 10 && (
                        <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-500">
                          +{cert.metadata.sans.length - 10} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
