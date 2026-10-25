import React, { useEffect, useState } from 'react';
import { 
  Archive, 
  Search, 
  Filter, 
  Copy, 
  Check, 
  ExternalLink, 
  Hash, 
  ShieldCheck, 
  Layers,
  FileCode
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { EvidenceItem } from '../../types/osint.ts';

export const EvidenceVaultView: React.FC = () => {
  const { activeCase, openEvidenceInInspector } = useCase();
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [filterVerification, setFilterVerification] = useState('ALL');
  const [filterCaseOnly, setFilterCaseOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadEvidence() {
      try {
        const data = await api.fetchEvidence(filterCaseOnly && activeCase ? activeCase.id : undefined);
        setEvidenceList(data);
      } catch (err) {
        console.error('Failed to load evidence', err);
      } finally {
        setLoading(false);
      }
    }
    loadEvidence();
  }, [filterCaseOnly, activeCase]);

  const filteredEvidence = evidenceList.filter((e) => {
    if (filterVerification !== 'ALL' && e.verification_status !== filterVerification) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        e.id.toLowerCase().includes(q) ||
        e.target_identifier.toLowerCase().includes(q) ||
        e.source_provider.toLowerCase().includes(q) ||
        e.content_hash.toLowerCase().includes(q) ||
        e.normalized_value.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleCopyHash = (e: React.MouseEvent, hash: string, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Archive className="w-4 h-4 text-emerald-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Evidence Vault & Provenance Register
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-evident archive of raw observation telemetry, source provenance citations, and deterministic SHA-256 payload digests.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Total Items:</span>
          <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 tabular-nums">
            {filteredEvidence.length}
          </span>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded border border-slate-800 text-xs">
            {['ALL', 'VERIFIED', 'DEMO', 'UNVERIFIED'].map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerification(v)}
                className={`px-3 py-1 rounded transition-colors ${
                  filterVerification === v
                    ? 'bg-slate-800 text-cyan-300 font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          {activeCase && (
            <label className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={filterCaseOnly}
                onChange={(e) => setFilterCaseOnly(e.target.checked)}
                className="rounded text-cyan-500 focus:ring-0 bg-slate-800 border-slate-700"
              />
              <span>Filter active case only ({activeCase.case_number})</span>
            </label>
          )}
        </div>

        <div className="relative w-full md:w-80">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search evidence ID, target, provider or hash..."
            className="w-full bg-slate-900 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Evidence Table */}
      <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Evidence ID</th>
                <th className="px-4 py-3">Target Identifier</th>
                <th className="px-4 py-3">Source Provider</th>
                <th className="px-4 py-3">Observation</th>
                <th className="px-4 py-3">SHA-256 Digest</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {filteredEvidence.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    No evidence records matching current criteria.
                  </td>
                </tr>
              ) : (
                filteredEvidence.map((e) => (
                  <tr
                    key={e.id}
                    onClick={() => openEvidenceInInspector(e)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 font-semibold text-cyan-400">
                      {e.id}
                    </td>
                    <td className="px-4 py-3 text-slate-100 font-medium">
                      {e.target_identifier}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {e.source_provider}
                    </td>
                    <td className="px-4 py-3 text-slate-300 truncate max-w-xs">
                      {e.normalized_value}
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate max-w-[120px] font-mono text-[10px] text-slate-500">
                          {e.content_hash}
                        </span>
                        <button
                          onClick={(evt) => handleCopyHash(evt, e.content_hash, e.id)}
                          className="text-cyan-400 hover:text-cyan-300 p-0.5"
                          title="Copy SHA-256 Hash"
                        >
                          {copiedId === e.id ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          e.verification_status === 'VERIFIED'
                            ? 'bg-emerald-400'
                            : e.verification_status === 'DEMO'
                            ? 'bg-amber-400'
                            : 'bg-slate-400'
                        }`} />
                        {e.verification_status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => openEvidenceInInspector(e)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] transition-colors border border-slate-700"
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
