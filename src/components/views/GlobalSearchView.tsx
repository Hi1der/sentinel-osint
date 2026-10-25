import React, { useState, useEffect } from 'react';
import { Search, Globe, Server, FileCheck2, Briefcase, Layers, ArrowRight } from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { Entity, EvidenceItem, InvestigationCase } from '../../types/osint.ts';

export const GlobalSearchView: React.FC = () => {
  const { 
    cases, 
    openEntityInInspector, 
    openEvidenceInInspector, 
    setActiveCase, 
    setActiveView,
    searchQuery 
  } = useCase();

  const [query, setQuery] = useState(searchQuery || '');
  const [entities, setEntities] = useState<Entity[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [activeTab, setActiveTab] = useState<'ALL' | 'CASES' | 'ENTITIES' | 'EVIDENCE'>('ALL');
  const [searched, setSearched] = useState(false);
  const [searching, setSearching] = useState(false);

  const executeSearch = async (searchTerm: string) => {
    if (!searchTerm.trim()) return;

    setSearching(true);
    setSearched(true);
    try {
      const [ent, ev] = await Promise.all([api.fetchEntities(), api.fetchEvidence()]);
      const q = searchTerm.toLowerCase();

      setEntities(
        ent.filter(
          (x) =>
            x.canonical_value.toLowerCase().includes(q) ||
            x.display_value.toLowerCase().includes(q) ||
            x.id.toLowerCase().includes(q)
        )
      );

      setEvidence(
        ev.filter(
          (x) =>
            x.target_identifier.toLowerCase().includes(q) ||
            x.content_hash.toLowerCase().includes(q) ||
            x.normalized_value.toLowerCase().includes(q) ||
            x.id.toLowerCase().includes(q)
        )
      );
    } catch (err) {
      console.error('Search failed', err);
    } finally {
      setSearching(false);
    }
  };

  useEffect(() => {
    if (searchQuery && searchQuery.trim()) {
      setQuery(searchQuery);
      executeSearch(searchQuery);
    }
  }, [searchQuery]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    executeSearch(query);
  };

  const matchingCases = cases.filter(
    (c) =>
      c.title.toLowerCase().includes(query.toLowerCase()) ||
      c.case_number.toLowerCase().includes(query.toLowerCase()) ||
      c.scope.domains.some((d) => d.toLowerCase().includes(query.toLowerCase()))
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header & Search Bar */}
      <div className="p-6 rounded-lg bg-slate-900 border border-slate-800 space-y-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 font-sans">
            Global Enterprise Threat Search
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Query across investigation cases, resolved entities, evidence provenance items, and SHA-256 hashes.
          </p>
        </div>

        <form onSubmit={handleSearch} className="relative">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            required
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search FQDN, IP, ASN, SHA-256 digest, evidence ID (e.g. ironshield-telemetry.org, 198.51.100.42)..."
            className="w-full bg-slate-950 border border-slate-700 rounded pl-10 pr-24 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 font-mono focus:outline-none focus:border-cyan-500 shadow-inner"
          />
          <button
            type="submit"
            disabled={searching}
            className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition-colors"
          >
            {searching ? 'Searching...' : 'Search'}
          </button>
        </form>

        {/* Filter Tabs */}
        {searched && (
          <div className="flex items-center gap-1.5 pt-2 border-t border-slate-800 text-xs">
            <span className="text-slate-500 text-[11px] font-mono mr-2">Filter View:</span>
            {[
              { id: 'ALL', label: 'All Results' },
              { id: 'CASES', label: `Cases (${matchingCases.length})` },
              { id: 'ENTITIES', label: `Entities (${entities.length})` },
              { id: 'EVIDENCE', label: `Evidence (${evidence.length})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-3 py-1 rounded text-xs transition-colors ${
                  activeTab === tab.id
                    ? 'bg-slate-800 text-cyan-300 font-medium border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {searched && (
        <div className="space-y-6">
          {/* Matching Cases */}
          {(activeTab === 'ALL' || activeTab === 'CASES') && matchingCases.length > 0 && (
            <div className="space-y-3">
              <span className="font-mono text-xs uppercase font-semibold text-slate-400">
                Matching Cases ({matchingCases.length})
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {matchingCases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => {
                      setActiveCase(c);
                      setActiveView('investigations');
                    }}
                    className="p-3.5 rounded bg-slate-900 border border-slate-800 hover:border-cyan-700/80 cursor-pointer space-y-1 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-cyan-400 font-bold">{c.case_number}</span>
                      <span className="text-slate-500 text-[10px]">{c.status}</span>
                    </div>
                    <div className="font-semibold text-slate-200">{c.title}</div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      Scope: {c.scope.domains.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Matching Entities */}
          {(activeTab === 'ALL' || activeTab === 'ENTITIES') && (
            <div className="space-y-3">
              <span className="font-mono text-xs uppercase font-semibold text-slate-400">
                Correlated Entities ({entities.length})
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {entities.map((ent) => (
                  <div
                    key={ent.id}
                    onClick={() => openEntityInInspector(ent)}
                    className="p-3 rounded bg-slate-900 border border-slate-800 hover:border-cyan-700/80 cursor-pointer text-xs font-mono space-y-1"
                  >
                    <div className="flex justify-between text-slate-500 text-[10px]">
                      <span className="text-cyan-400 font-bold">{ent.entity_type}</span>
                      <span className="tabular-nums">{Math.round(ent.confidence_score * 100)}% Conf</span>
                    </div>
                    <div className="text-slate-100 font-semibold truncate">{ent.canonical_value}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Matching Evidence */}
          {(activeTab === 'ALL' || activeTab === 'EVIDENCE') && (
            <div className="space-y-3">
              <span className="font-mono text-xs uppercase font-semibold text-slate-400">
                Evidence Items ({evidence.length})
              </span>
              <div className="space-y-2">
                {evidence.map((ev) => (
                  <div
                    key={ev.id}
                    onClick={() => openEvidenceInInspector(ev)}
                    className="p-3 rounded bg-slate-900 border border-slate-800 hover:border-cyan-700/80 cursor-pointer text-xs font-mono flex items-center justify-between gap-4"
                  >
                    <div className="min-w-0">
                      <span className="text-cyan-400 font-bold mr-2">{ev.id}</span>
                      <span className="text-slate-200 font-semibold">{ev.target_identifier}</span>
                      <span className="text-slate-400 ml-2">· {ev.source_provider}</span>
                    </div>
                    <span className="text-slate-500 text-[10px] shrink-0 tabular-nums">
                      {ev.content_hash.slice(0, 12)}…
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
