import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  ShieldCheck, 
  Layers, 
  FileCode, 
  Share2, 
  Archive,
  CheckCircle2,
  Sparkles,
  AlertTriangle,
  RefreshCw,
  Lightbulb,
  ShieldAlert
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';

export const ReportsView: React.FC = () => {
  const { activeCase, cases, showNotification } = useCase();
  const [selectedCaseId, setSelectedCaseId] = useState(activeCase?.id || cases[0]?.id || '');
  const [exporting, setExporting] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [assessment, setAssessment] = useState<any>(null);

  const targetCase = cases.find((c) => c.id === selectedCaseId) || activeCase;

  useEffect(() => {
    if (selectedCaseId) {
      api.fetchAiAssessment(selectedCaseId)
        .then((res) => setAssessment(res.assessment))
        .catch(() => setAssessment(null));
    }
  }, [selectedCaseId]);

  const handleGenerateAiAssessment = async () => {
    if (!selectedCaseId) return;
    setAnalyzing(true);
    try {
      const res = await api.generateAiAssessmentApi(selectedCaseId);
      setAssessment(res.assessment);
      showNotification('success', 'Intelligence Assessment generated successfully.');
    } catch (err: any) {
      showNotification('error', err.message || 'Failed to generate assessment');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'stix') => {
    setExporting(format);
    try {
      const url = `/api/export/${format}?case_id=${encodeURIComponent(selectedCaseId)}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);
      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `sentinel_${format}_${targetCase?.case_number || 'export'}.${format === 'csv' ? 'csv' : 'json'}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      console.error('Export download error', err);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Investigation Reports & Threat Intelligence Exports
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Export standardized intelligence packages with full provenance citations, SHA-256 integrity digests, and OASIS STIX 2.1 bundle formatting.
          </p>
        </div>

        {/* Case Selector for Report */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400 font-mono">Target Case:</span>
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.case_number} · {c.title.slice(0, 28)}…
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* AI Threat Intelligence Assessment Card */}
      <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-5 h-5 text-purple-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>AI Threat Intelligence & Hypothesis Synthesis</span>
                {assessment && (
                  <>
                    <span className="text-slate-600 font-mono text-xs">·</span>
                    <span className="text-purple-400 font-mono text-[11px]">
                      {assessment.generated_by === 'GEMINI_AI' ? 'Gemini 3.8 Flash' : 'Rule Engine Fallback'}
                    </span>
                  </>
                )}
              </h2>
              <p className="text-[11px] text-slate-400">
                Automated multi-source evidence correlation, threat scoring, and structured hypothesis assessment.
              </p>
            </div>
          </div>

          <button
            onClick={handleGenerateAiAssessment}
            disabled={analyzing}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs transition-colors disabled:opacity-50 font-mono shrink-0 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${analyzing ? 'animate-spin' : ''}`} />
            <span>{analyzing ? 'Synthesizing...' : 'Generate AI Briefing'}</span>
          </button>
        </div>

        {assessment ? (
          <div className="space-y-4 text-xs font-sans">
            {/* Score & Level Banner */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[11px]">Threat Level:</span>
                <span className="inline-flex items-center gap-1.5 font-mono font-bold text-xs text-slate-200">
                  <span className={`w-2 h-2 rounded-full ${
                    assessment.threat_level === 'CRITICAL' ? 'bg-red-400' :
                    assessment.threat_level === 'HIGH' ? 'bg-orange-400' :
                    assessment.threat_level === 'MEDIUM' ? 'bg-amber-400' :
                    'bg-emerald-400'
                  }`} />
                  {assessment.threat_level}
                </span>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[11px]">Threat Score:</span>
                <span className="text-cyan-400 font-mono font-bold text-sm">
                  {assessment.threat_score} / 100
                </span>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[11px]">Hypotheses:</span>
                <span className="text-purple-300 font-mono font-semibold">
                  {assessment.hypotheses?.length || 0} Formal Leads
                </span>
              </div>
            </div>

            {/* Executive Summary */}
            <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-mono text-purple-400 uppercase font-bold block">
                Executive Threat Summary
              </span>
              <p className="text-slate-200 leading-relaxed text-xs">
                {assessment.executive_summary}
              </p>
            </div>

            {/* Hypotheses */}
            {assessment.hypotheses && assessment.hypotheses.length > 0 && (
              <div className="space-y-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold">
                  Intelligence Hypotheses & Evidence Traceability
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {assessment.hypotheses.map((hyp: any) => (
                    <div key={hyp.id} className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-100 text-xs">{hyp.title}</span>
                        <span className="font-mono text-[10px] text-amber-400 uppercase">
                          {hyp.confidence} ({Math.round(hyp.confidence_score * 100)}%)
                        </span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{hyp.description}</p>
                      {hyp.evidentiary_basis?.length > 0 && (
                        <div className="font-mono text-[10px] text-slate-500 truncate">
                          Basis: {hyp.evidentiary_basis.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 font-mono text-xs bg-slate-950 rounded border border-slate-800">
            No active threat intelligence briefing generated yet for this case. Click "Generate AI Briefing" above.
          </div>
        )}
      </div>

      {/* Export Format Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* STIX 2.1 Card */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between shadow-lg">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400 font-bold text-xs uppercase">OASIS STIX 2.1</span>
              <span className="inline-flex items-center gap-1 font-mono text-[11px] text-cyan-300">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                INTEROPERABLE
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Structured Threat Information</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Standard JSON-based serialized bundle conforming to STIX 2.1 specifications. Maps domains, IPs, and certificates to standardized observable objects.
            </p>
          </div>

          <button
            onClick={() => handleExport('stix')}
            disabled={exporting === 'stix'}
            className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition-colors flex items-center justify-center gap-2 shadow-sm"
          >
            <Download className="w-4 h-4" />
            <span>{exporting === 'stix' ? 'Generating STIX...' : 'Download STIX 2.1 Bundle'}</span>
          </button>
        </div>

        {/* Raw JSON Card */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between shadow-lg">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-blue-400 font-bold text-xs uppercase">Full Dossier JSON</span>
              <span className="inline-flex items-center gap-1 font-mono text-[11px] text-blue-300">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                COMPLETE ARCHIVE
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Comprehensive Case Vault</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Complete machine-readable JSON object containing case metadata, scope definitions, raw evidence payloads, SHA-256 hashes, and temporal graph edges.
            </p>
          </div>

          <button
            onClick={() => handleExport('json')}
            disabled={exporting === 'json'}
            className="w-full py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition-colors flex items-center justify-center gap-2"
          >
            <Download className="w-4 h-4" />
            <span>{exporting === 'json' ? 'Exporting JSON...' : 'Download Complete JSON'}</span>
          </button>
        </div>

        {/* CSV Inventory Card */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between shadow-lg">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-emerald-400 font-bold text-xs uppercase">Spreadsheet CSV</span>
              <span className="inline-flex items-center gap-1 font-mono text-[11px] text-emerald-300">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                TABULAR
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100">Entity Inventory Table</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Tabular spreadsheet of discovered infrastructure entities, canonical values, confidence scores, observation timestamps, and demo markers.
            </p>
          </div>

          <button
            onClick={() => handleExport('csv')}
            disabled={exporting === 'csv'}
            className="w-full py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition-colors flex items-center justify-center gap-2"
          >
            <Download className="w-4 h-4" />
            <span>{exporting === 'csv' ? 'Exporting CSV...' : 'Download Entities CSV'}</span>
          </button>
        </div>
      </div>

      {/* Case Report Preview Section */}
      {targetCase && (
        <div className="p-6 rounded-lg bg-slate-900 border border-slate-800 space-y-4 text-xs">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <span className="font-mono text-cyan-400 font-bold text-sm">{targetCase.case_number}</span>
              <h2 className="text-base font-semibold text-slate-100 mt-0.5">{targetCase.title}</h2>
            </div>
            <span className="font-mono text-slate-400 text-[11px]">
              Last Updated: {new Date(targetCase.updated_at).toLocaleString()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1 bg-slate-950 p-3 rounded border border-slate-800/80">
              <span className="font-mono text-slate-500 uppercase text-[10px]">Executive Objective</span>
              <p className="text-slate-300 leading-relaxed">{targetCase.objective}</p>
            </div>

            <div className="space-y-1 bg-slate-950 p-3 rounded border border-slate-800/80 font-mono text-[11px]">
              <span className="text-slate-500 uppercase text-[10px]">Authorized Scope</span>
              <div className="text-cyan-300 truncate">Domains: {targetCase.scope.domains.join(', ')}</div>
              {targetCase.scope.ipRanges.length > 0 && (
                <div className="text-emerald-300">CIDRs: {targetCase.scope.ipRanges.join(', ')}</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
