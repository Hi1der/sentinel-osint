import React, { useEffect, useState } from 'react';
import { 
  Globe, 
  Search, 
  ShieldCheck, 
  CheckCircle2, 
  ShieldAlert, 
  Layers, 
  ExternalLink,
  BookOpen,
  RefreshCw,
  Server
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { Entity, EvidenceItem } from '../../types/osint.ts';

export const DomainIntelView: React.FC = () => {
  const { activeCase, openEntityInInspector, openEvidenceInInspector, showNotification } = useCase();
  const [domainEntities, setDomainEntities] = useState<Entity[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [queryingRdap, setQueryingRdap] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [ent, ev] = await Promise.all([
        api.fetchEntities(activeCase?.id),
        api.fetchEvidence(activeCase?.id),
      ]);
      setDomainEntities(ent.filter((e) => e.entity_type === 'DOMAIN' || e.entity_type === 'SUBDOMAIN'));
      setEvidenceList(ev);
    } catch (err) {
      console.error('Failed to load domain intel', err);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeCase]);

  const handleQueryRdap = async (domain: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!activeCase) return;
    setQueryingRdap(domain);
    try {
      const res = await api.executeRdapLookupApi({
        case_id: activeCase.id,
        target: domain,
      });
      if (res.success) {
        showNotification('success', `RDAP registration retrieved for ${domain}`);
        await loadData();
      } else {
        showNotification('error', `RDAP lookup notice: ${res.result?.error || 'No records returned'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'RDAP lookup failed');
    } finally {
      setQueryingRdap(null);
    }
  };

  const filtered = domainEntities.filter((d) =>
    searchQuery ? d.canonical_value.toLowerCase().includes(searchQuery.toLowerCase()) : true
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Domain & Subdomain Intelligence
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated domain assets, authoritative RDAP registration metadata, subdelegated FQDNs, and active DNS resolution bindings.
          </p>
        </div>

        <div className="relative w-full md:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter domains or subdomains..."
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Scope Banner */}
      {activeCase && (
        <div className="p-3 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">Authorized Domain Scope for {activeCase.case_number}:</span>
          <span className="text-cyan-300 font-semibold">{activeCase.scope.domains.join(', ')}</span>
        </div>
      )}

      {/* Domain Entities Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.length === 0 ? (
          <div className="col-span-full p-8 text-center text-slate-500 font-mono text-xs bg-slate-900 rounded-lg border border-slate-800 space-y-2">
            <Globe className="w-8 h-8 text-slate-700 mx-auto" />
            <p>No domain entities identified in current case scope.</p>
            <p className="text-[11px] text-slate-600 font-sans">
              Run DNS resolution or launch a passive reconnaissance job to correlate target domains.
            </p>
          </div>
        ) : (
          filtered.map((d) => {
            const rdapEv = evidenceList.find(
              (e) => e.target_identifier === d.canonical_value && e.collector_id.includes('rdap')
            );
            const rdapData = rdapEv?.raw_payload?.data || rdapEv?.raw_payload;

            return (
              <div
                key={d.id}
                onClick={() => openEntityInInspector(d)}
                className="p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-700/80 transition-all cursor-pointer space-y-3 text-xs shadow-md"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-cyan-400 uppercase font-semibold">
                    {d.entity_type}
                  </span>
                  {d.is_demo && (
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-amber-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                      DEMO
                    </span>
                  )}
                  <span className="font-mono text-slate-400 text-[10px] tabular-nums">
                    {Math.round(d.confidence_score * 100)}% Conf
                  </span>
                </div>

                <div className="font-mono font-semibold text-slate-100 text-sm break-all">
                  {d.canonical_value}
                </div>

                {/* RDAP Summary Badge if available */}
                {rdapData ? (
                  <div className="p-2 rounded bg-cyan-950/30 border border-cyan-800/40 text-[11px] font-mono space-y-1">
                    <div className="flex justify-between text-cyan-300">
                      <span>Registrar:</span>
                      <span className="truncate max-w-[140px] text-right text-slate-200">
                        {rdapData.registrar || 'Protected / Redacted'}
                      </span>
                    </div>
                    {rdapData.registration_date && (
                      <div className="flex justify-between text-slate-400">
                        <span>Registered:</span>
                        <span className="text-slate-300">{rdapData.registration_date.slice(0, 10)}</span>
                      </div>
                    )}
                    {rdapData.expiration_date && (
                      <div className="flex justify-between text-slate-400">
                        <span>Expires:</span>
                        <span className="text-slate-300">{rdapData.expiration_date.slice(0, 10)}</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span>First Seen:</span>
                      <span className="text-slate-200">{new Date(d.first_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Last Seen:</span>
                      <span className="text-slate-200">{new Date(d.last_seen).toLocaleDateString()}</span>
                    </div>
                  </div>
                )}

                {/* Action Bar */}
                <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
                  <button
                    type="button"
                    onClick={(e) => handleQueryRdap(d.canonical_value, e)}
                    disabled={queryingRdap === d.canonical_value}
                    className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-mono border border-slate-700 transition-colors disabled:opacity-50"
                  >
                    <BookOpen className="w-3 h-3 text-cyan-400" />
                    <span>{queryingRdap === d.canonical_value ? 'Querying...' : 'Query RDAP'}</span>
                  </button>

                  <span className="text-slate-500 hover:text-slate-300 text-[11px] font-mono">
                    Inspect →
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
