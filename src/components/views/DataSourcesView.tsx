import React, { useEffect, useState } from 'react';
import { 
  Radio, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  ExternalLink,
  Lock,
  RotateCw,
  Info
} from 'lucide-react';
import * as api from '../../services/api.ts';
import { DataSourceStatus } from '../../types/osint.ts';

export const DataSourcesView: React.FC = () => {
  const [sources, setSources] = useState<DataSourceStatus[]>([]);
  const [loading, setLoading] = useState(true);

  const loadSources = async () => {
    try {
      const data = await api.fetchDataSources();
      setSources(data);
    } catch (err) {
      console.error('Failed to load sources', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSources();
  }, []);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Passive Data Integrations & Ingestion Sources
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Registered public reconnaissance APIs operating under strict token bucket rate limits, automated circuit breakers, and zero active probing.
          </p>
        </div>

        <button
          onClick={loadSources}
          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors flex items-center gap-1.5 self-start md:self-auto"
        >
          <RotateCw className="w-3.5 h-3.5" />
          <span>Refresh Health</span>
        </button>
      </div>

      {/* Compliance Box */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-3 text-xs text-slate-400">
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-slate-200">Ethical & Passive Ingestion Policy</span>
          <p className="leading-relaxed">
            All configured providers query authoritative public infrastructure registries without interacting with target mailboxes, proprietary internal networks, or authentication barriers. Circuit breakers automatically trip upon 5 consecutive HTTP 429/5xx errors to protect upstream servers.
          </p>
        </div>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sources.map((src) => (
          <div key={src.id} className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 text-xs shadow-md">
            <div className="flex items-start justify-between gap-2">
              <div>
                <span className="font-mono text-cyan-400 text-[10px] uppercase font-bold block">{src.type}</span>
                <h3 className="text-sm font-semibold text-slate-100 mt-0.5">{src.name}</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-400">
                {src.status}
              </span>
            </div>

            <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-300 space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-500">Endpoint:</span>
                <span className="truncate max-w-[200px] text-slate-300">{src.endpoint}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Rate Limit:</span>
                <span className="text-cyan-300 tabular-nums">{src.rate_limit_per_min} req / min</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Requests Today:</span>
                <span className="text-slate-200 tabular-nums">{src.requests_today} queries</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Circuit Breaker:</span>
                <span className={src.circuit_breaker_open ? 'text-red-400' : 'text-emerald-400'}>
                  {src.circuit_breaker_open ? 'TRIPPED (OPEN)' : 'NOMINAL (CLOSED)'}
                </span>
              </div>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
              {src.compliance_note}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};
