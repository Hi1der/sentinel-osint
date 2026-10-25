import React, { useEffect, useState } from 'react';
import { 
  Server, 
  Search, 
  Network, 
  Globe, 
  Layers, 
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { Entity, EvidenceItem } from '../../types/osint.ts';

export const IpAsnView: React.FC = () => {
  const { activeCase, openEntityInInspector, showNotification } = useCase();
  const [ipEntities, setIpEntities] = useState<Entity[]>([]);
  const [asnEntities, setAsnEntities] = useState<Entity[]>([]);
  const [queryingIp, setQueryingIp] = useState<string | null>(null);
  const [manualIp, setManualIp] = useState('');

  const loadData = async () => {
    try {
      const ent = await api.fetchEntities(activeCase?.id);
      setIpEntities(ent.filter((e) => e.entity_type === 'IP_ADDRESS'));
      setAsnEntities(ent.filter((e) => e.entity_type === 'ASN'));
    } catch (err) {
      console.error('Failed to load IP/ASN data', err);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeCase]);

  const handleQueryBgp = async (ip: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!activeCase || !ip.trim()) return;
    setQueryingIp(ip);
    try {
      const res = await api.executeBgpLookupApi({
        case_id: activeCase.id,
        target_ip: ip.trim(),
      });
      if (res.success) {
        showNotification('success', `BGP routing retrieved for ${ip}: ${res.result?.routing_data?.prefix || 'Prefix mapped'}`);
        await loadData();
      } else {
        showNotification('error', `BGP query notice: ${res.result?.error || 'No routing information'}`);
      }
    } catch (err: any) {
      showNotification('error', err.message || 'BGP lookup failed');
    } finally {
      setQueryingIp(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              IP Address & Autonomous System (ASN) Intelligence
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            BGP routing allocations, autonomous system boundaries, announced IP prefixes via RIPE Stat NCC.
          </p>
        </div>

        {/* Manual Query Bar */}
        {activeCase && (
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={manualIp}
              onChange={(e) => setManualIp(e.target.value)}
              placeholder="e.g. 198.51.100.42"
              className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 w-44"
            />
            <button
              onClick={() => handleQueryBgp(manualIp)}
              disabled={queryingIp === manualIp || !manualIp.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50 font-mono"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${queryingIp === manualIp ? 'animate-spin' : ''}`} />
              <span>Query BGP</span>
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* IP Addresses Column */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-mono text-xs font-semibold text-slate-200 uppercase">
              Resolved IP Entities ({ipEntities.length})
            </span>
          </div>

          <div className="space-y-2">
            {ipEntities.length === 0 ? (
              <div className="p-6 text-center text-slate-500 font-mono text-xs bg-slate-950 rounded border border-slate-800">
                No resolved IP entities in active case. Run DNS A/AAAA queries to correlate target IPs.
              </div>
            ) : (
              ipEntities.map((ip) => (
                <div
                  key={ip.id}
                  onClick={() => openEntityInInspector(ip)}
                  className="p-3 rounded bg-slate-950 border border-slate-800 hover:border-cyan-700/80 transition-colors cursor-pointer space-y-2 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-emerald-400 font-bold">{ip.canonical_value}</span>
                    <span className="text-slate-500 text-[10px]">{ip.metadata?.version || 'IPv4'}</span>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
                    <span className="text-[10px] text-slate-500">
                      Discovered: {new Date(ip.first_seen).toLocaleDateString()}
                    </span>
                    <button
                      type="button"
                      onClick={(e) => handleQueryBgp(ip.canonical_value, e)}
                      disabled={queryingIp === ip.canonical_value}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] border border-slate-700 transition-colors disabled:opacity-50"
                    >
                      {queryingIp === ip.canonical_value ? 'Querying...' : 'Query BGP →'}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ASN Column */}
        <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 shadow-md">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-mono text-xs font-semibold text-slate-200 uppercase">
              Autonomous Systems ({asnEntities.length})
            </span>
          </div>

          <div className="space-y-2">
            {asnEntities.length === 0 ? (
              <div className="p-6 text-center text-slate-500 font-mono text-xs bg-slate-950 rounded border border-slate-800">
                No ASN entities registered in active case. Query BGP routing on an IP to correlate its transit provider.
              </div>
            ) : (
              asnEntities.map((asn) => (
                <div
                  key={asn.id}
                  onClick={() => openEntityInInspector(asn)}
                  className="p-3 rounded bg-slate-950 border border-slate-800 hover:border-purple-700/80 transition-colors cursor-pointer space-y-1.5 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-purple-400 font-bold">{asn.canonical_value}</span>
                    <span className="text-slate-500 text-[10px]">{asn.metadata?.country || 'GLOBAL'}</span>
                  </div>
                  <div className="text-slate-300 text-xs font-sans font-medium">
                    {asn.metadata?.holder || asn.display_value}
                  </div>
                  {asn.metadata?.prefix && (
                    <div className="text-slate-400 text-[11px]">
                      Announced Prefix: <span className="text-cyan-300">{asn.metadata.prefix}</span>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
