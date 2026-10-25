import React, { useState } from 'react';
import { 
  Briefcase, 
  Plus, 
  CheckCircle2, 
  Archive, 
  Trash2, 
  Edit3, 
  ShieldAlert, 
  Layers, 
  Tag,
  Check,
  Search,
  Filter
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { InvestigationCase, CaseStatus } from '../../types/osint.ts';

interface InvestigationsViewProps {
  onOpenNewCaseModal: () => void;
}

export const InvestigationsView: React.FC<InvestigationsViewProps> = ({ onOpenNewCaseModal }) => {
  const { cases, activeCase, setActiveCase, refreshCases, showNotification } = useCase();
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCaseDetail, setSelectedCaseDetail] = useState<InvestigationCase | null>(activeCase || cases[0] || null);

  const filteredCases = cases.filter((c) => {
    if (filterStatus !== 'ALL' && c.status !== filterStatus) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        c.title.toLowerCase().includes(q) ||
        c.case_number.toLowerCase().includes(q) ||
        c.scope.domains.some((d) => d.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleUpdateStatus = async (caseId: string, newStatus: CaseStatus) => {
    try {
      await api.updateCase(caseId, { status: newStatus });
      await refreshCases();
      showNotification('success', `Case status updated to ${newStatus}.`);
    } catch (err: any) {
      showNotification('error', `Failed to update status: ${err.message}`);
    }
  };

  const handleDeleteCase = async (c: InvestigationCase) => {
    if (!window.confirm(`Permanently delete case ${c.case_number}? This action is cryptographically logged.`)) {
      return;
    }
    try {
      await api.deleteCase(c.id);
      await refreshCases();
      if (activeCase?.id === c.id) {
        setActiveCase(cases.find((x) => x.id !== c.id) || null);
      }
      showNotification('success', `Case ${c.case_number} deleted.`);
    } catch (err: any) {
      showNotification('error', `Failed to delete case: ${err.message}`);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Investigation Workspace
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Maintain case dossiers, define strict target scope boundaries, and coordinate passive reconnaissance missions.
          </p>
        </div>

        <button
          onClick={onOpenNewCaseModal}
          className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors shadow-sm flex items-center gap-1.5 self-start md:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded border border-slate-800 text-xs w-full md:w-auto">
          {['ALL', 'ACTIVE', 'ARCHIVED', 'CLOSED'].map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={`px-3 py-1 rounded transition-colors ${
                filterStatus === s
                  ? 'bg-slate-800 text-cyan-300 font-medium'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-80">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search cases, numbers or domains..."
            className="w-full bg-slate-900 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Split Layout: Cases List & Selected Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Cases List (2 Cols) */}
        <div className="lg:col-span-2 space-y-3">
          {filteredCases.length === 0 ? (
            <div className="p-8 rounded-lg bg-slate-900 border border-slate-800 text-center space-y-2">
              <Briefcase className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-xs text-slate-400 font-medium">No investigation cases found matching filter.</p>
              <button
                onClick={onOpenNewCaseModal}
                className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium inline-block mt-2"
              >
                Create New Case
              </button>
            </div>
          ) : (
            filteredCases.map((c) => {
              const isActiveTarget = activeCase?.id === c.id;
              const isSelectedForInspect = selectedCaseDetail?.id === c.id;

              return (
                <div
                  key={c.id}
                  onClick={() => setSelectedCaseDetail(c)}
                  className={`p-4 rounded-lg border transition-all cursor-pointer ${
                    isSelectedForInspect
                      ? 'bg-slate-900 border-cyan-500/80 shadow-md'
                      : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5 flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-cyan-400 font-bold text-xs">{c.case_number}</span>
                        {c.is_demo && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950 border border-amber-800 text-amber-300 font-mono text-[10px]">
                            DEMO
                          </span>
                        )}
                        <span className={`px-1.5 py-0.2 rounded font-mono text-[10px] border ${
                          c.priority === 'CRITICAL' ? 'bg-red-950/80 border-red-800 text-red-300' :
                          c.priority === 'HIGH' ? 'bg-amber-950/80 border-amber-800 text-amber-300' :
                          'bg-slate-800 border-slate-700 text-slate-300'
                        }`}>
                          {c.priority}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">{c.status}</span>
                      </div>

                      <h3 className="text-sm font-semibold text-slate-100">{c.title}</h3>
                      <p className="text-xs text-slate-400 line-clamp-2">{c.description || 'No description provided.'}</p>

                      <div className="pt-2 flex flex-wrap gap-1.5">
                        {c.tags.map((t) => (
                          <span key={t} className="text-[10px] font-mono text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                            #{t}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-2 shrink-0">
                      {isActiveTarget ? (
                        <span className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-xs font-mono">
                          Active Target
                        </span>
                      ) : (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveCase(c);
                            showNotification('info', `Active case set to ${c.case_number}`);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
                        >
                          Select as Active
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Selected Case Details & Scope Inspector */}
        <div className="space-y-4">
          {selectedCaseDetail ? (
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-4 text-xs">
              <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
                <div>
                  <span className="font-mono text-cyan-400 font-bold block">{selectedCaseDetail.case_number}</span>
                  <h3 className="font-semibold text-slate-200 text-sm mt-0.5">{selectedCaseDetail.title}</h3>
                </div>
                <div className="flex items-center gap-1">
                  {selectedCaseDetail.status === 'ACTIVE' && (
                    <button
                      onClick={() => handleUpdateStatus(selectedCaseDetail.id, 'ARCHIVED')}
                      className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                      title="Archive Case"
                    >
                      <Archive className="w-4 h-4" />
                    </button>
                  )}
                  {selectedCaseDetail.status === 'ARCHIVED' && (
                    <button
                      onClick={() => handleUpdateStatus(selectedCaseDetail.id, 'ACTIVE')}
                      className="p-1.5 rounded text-cyan-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
                      title="Reactivate Case"
                    >
                      <Check className="w-4 h-4" />
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteCase(selectedCaseDetail)}
                    className="p-1.5 rounded text-red-400 hover:text-red-300 hover:bg-slate-800 transition-colors"
                    title="Delete Case"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Objective */}
              <div className="space-y-1">
                <span className="text-[11px] font-mono text-slate-500 uppercase block">Investigation Objective</span>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/80">
                  {selectedCaseDetail.objective || 'No objective specified.'}
                </p>
              </div>

              {/* Authorized Scope Boundaries */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
                  <span>Server-Enforced Scope</span>
                  <span className="text-cyan-400 font-mono text-[10px]">Strict Boundary</span>
                </span>

                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Authorized Domains</span>
                    <ul className="list-disc list-inside text-slate-200 mt-0.5 space-y-0.5">
                      {selectedCaseDetail.scope.domains.map((d) => (
                        <li key={d} className="break-all">{d}</li>
                      ))}
                    </ul>
                  </div>

                  {selectedCaseDetail.scope.ipRanges.length > 0 && (
                    <div className="pt-1.5 border-t border-slate-800/60">
                      <span className="text-slate-500 block text-[10px] uppercase">Authorized IP / CIDR</span>
                      <ul className="list-disc list-inside text-slate-200 mt-0.5 space-y-0.5">
                        {selectedCaseDetail.scope.ipRanges.map((r) => (
                          <li key={r}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="pt-1.5 border-t border-slate-800/60">
                    <span className="text-slate-500 block text-[10px] uppercase">Allowed Collectors</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedCaseDetail.scope.allowedCollectorTypes.map((c) => (
                        <span key={c} className="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-300 text-[10px] border border-slate-700">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Case Metadata */}
              <div className="space-y-1 text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800">
                <div className="flex justify-between">
                  <span>Created By:</span>
                  <span className="text-slate-200">{selectedCaseDetail.created_by}</span>
                </div>
                <div className="flex justify-between">
                  <span>Created At:</span>
                  <span className="text-slate-200">{new Date(selectedCaseDetail.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 rounded-lg bg-slate-900 border border-slate-800 text-center text-slate-500 text-xs">
              Select a case to inspect scope parameters.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
