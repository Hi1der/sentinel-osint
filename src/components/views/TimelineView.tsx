import React, { useEffect, useState } from 'react';
import { Clock, Calendar, Layers, ShieldCheck } from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { EvidenceItem } from '../../types/osint.ts';

export const TimelineView: React.FC = () => {
  const { activeCase, openEvidenceInInspector } = useCase();
  const [timelineItems, setTimelineItems] = useState<EvidenceItem[]>([]);

  useEffect(() => {
    async function loadData() {
      try {
        const ev = await api.fetchEvidence(activeCase?.id);
        const sorted = [...ev].sort((a, b) => new Date(b.retrieval_timestamp).getTime() - new Date(a.retrieval_timestamp).getTime());
        setTimelineItems(sorted);
      } catch (err) {
        console.error('Failed to load timeline', err);
      }
    }
    loadData();
  }, [activeCase]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <h1 className="text-lg font-bold text-slate-100 font-sans">
            Investigation Chronology & Temporal Timeline
          </h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Chronological sequence of observations and source retrieval events with verifiable timestamps.
        </p>
      </div>

      {timelineItems.length === 0 ? (
        <div className="p-8 text-center text-slate-500 font-mono text-xs bg-slate-900 rounded-lg border border-slate-800 space-y-2">
          <Clock className="w-8 h-8 text-slate-700 mx-auto" />
          <p>No observation events recorded in active case chronology.</p>
          <p className="text-[11px] text-slate-600 font-sans">
            Execute DNS or passive recon queries to generate verifiable timeline events with tamper-evident timestamps.
          </p>
        </div>
      ) : (
        <div className="relative border-l border-slate-800 ml-4 space-y-6 pb-6">
          {timelineItems.map((item, idx) => (
          <div key={item.id} className="relative pl-6">
            <div className="absolute -left-1.5 top-1 w-3 h-3 rounded-full bg-cyan-500 border-2 border-[#0B0F19]" />
            <div 
              onClick={() => openEvidenceInInspector(item)}
              className="p-4 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-700/80 transition-all cursor-pointer space-y-2 text-xs shadow-md"
            >
              <div className="flex items-center justify-between text-slate-500 font-mono text-[11px]">
                <span>{new Date(item.retrieval_timestamp).toLocaleString()}</span>
                <span className="text-cyan-400 font-bold">{item.id}</span>
              </div>
              <div className="font-semibold text-slate-200">
                Observation for: <span className="font-mono text-cyan-300">{item.target_identifier}</span>
              </div>
              <p className="text-slate-400 font-mono text-[11px]">
                {item.source_provider} · {item.normalized_value}
              </p>
            </div>
          </div>
        ))}
        </div>
      )}
    </div>
  );
};
