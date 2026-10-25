import React, { useState } from 'react';
import { X, Briefcase, ShieldAlert, CheckCircle2, Sparkles } from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { CasePriority } from '../../types/osint.ts';

interface NewCaseModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NewCaseModal: React.FC<NewCaseModalProps> = ({ isOpen, onClose }) => {
  const { refreshCases, setActiveCase, showNotification } = useCase();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [objective, setObjective] = useState('');
  const [priority, setPriority] = useState<CasePriority>('HIGH');
  const [tags, setTags] = useState('PASSIVE-RECON, INFRASTRUCTURE');
  const [domainsInput, setDomainsInput] = useState('');
  const [ipRangesInput, setIpRangesInput] = useState('');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLoadSampleScope = () => {
    setTitle('Operation NorthStar — Autonomous Telemetry Mapping');
    setDescription('Passive surveillance and threat mapping for external cloud infrastructure and DNS delegation.');
    setObjective('Identify all publicly visible subdomains, ASN routes, certificate issuers, and registrar contacts.');
    setPriority('HIGH');
    setTags('PASSIVE-RECON, INFRASTRUCTURE, AUDIT');
    setDomainsInput('northstar-telemetry.io, *.northstar-telemetry.io');
    setIpRangesInput('198.51.100.0/24');
    setNotes('Restricted strictly to passive DNS and public CT log enumeration. No active scanning.');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const domains = domainsInput
      .split(/[\n,]/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);

    if (domains.length === 0) {
      setError('At least one authorized target domain or FQDN pattern is required.');
      return;
    }

    const ipRanges = ipRangesInput
      .split(/[\n,]/)
      .map((r) => r.trim())
      .filter(Boolean);

    const tagList = tags
      .split(',')
      .map((t) => t.trim().toUpperCase())
      .filter(Boolean);

    setSubmitting(true);
    try {
      const created = await api.createCase({
        title,
        description,
        objective,
        priority,
        tags: tagList,
        scope: {
          domains,
          ipRanges,
          allowedCollectorTypes: ['PASSIVE_DNS', 'CERT_TRANSPARENCY', 'RDAP_WHOIS', 'BGP_ROUTING'],
          notes,
        },
      });

      await refreshCases();
      setActiveCase(created);
      showNotification('success', `Investigation Case ${created.case_number} created with authorized scope.`);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create case');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-xl bg-[#0F172A] border border-slate-700 rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Create Investigation Case</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleLoadSampleScope}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] font-mono flex items-center gap-1 transition-colors"
              title="Pre-populate with sample case data"
            >
              <Sparkles className="w-3 h-3 text-cyan-400" />
              <span>Load Template</span>
            </button>
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-200 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="space-y-1">
            <label className="font-medium text-slate-300">Case Title *</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Operation NorthWind — Subdomain & ASN Correlation"
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="font-medium text-slate-300 block">Priority Level</label>
              <div className="grid grid-cols-4 gap-1 p-0.5 bg-slate-950 rounded border border-slate-800 font-mono text-[10px]">
                {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as CasePriority[]).map((p) => (
                  <button
                    type="button"
                    key={p}
                    onClick={() => setPriority(p)}
                    className={`py-1 rounded text-center transition-colors ${
                      priority === p
                        ? p === 'CRITICAL'
                          ? 'bg-red-950 text-red-300 border border-red-800 font-bold'
                          : 'bg-slate-800 text-cyan-300 border border-slate-700 font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1">
              <label className="font-medium text-slate-300">Tags (comma-separated)</label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="INFRA, THREAT-INTEL"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="font-medium text-slate-300">Investigation Objective</label>
            <textarea
              rows={2}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Define clear legal/investigative mission parameters and questions to answer..."
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 focus:outline-none focus:border-cyan-500 font-sans"
            />
          </div>

          {/* Scope Boundaries */}
          <div className="p-3.5 rounded bg-slate-950/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                Mandatory Authorized Scope
              </span>
              <span className="text-[10px] text-cyan-400 font-mono">Server Enforced</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Target identifiers will be validated against this boundary before any network query is made. Targets outside these domains or IP ranges will be strictly rejected.
            </p>

            <div className="space-y-1">
              <label className="font-medium text-slate-300">Authorized Domains / FQDNs * (comma or line separated)</label>
              <textarea
                rows={2}
                required
                value={domainsInput}
                onChange={(e) => setDomainsInput(e.target.value)}
                placeholder="example.org, *.example.org, telemetry.target.net"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="font-medium text-slate-300">Authorized IP CIDR Ranges (optional)</label>
              <input
                type="text"
                value={ipRangesInput}
                onChange={(e) => setIpRangesInput(e.target.value)}
                placeholder="198.51.100.0/24, 203.0.113.5"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors disabled:opacity-50"
            >
              {submitting ? 'Creating Case...' : 'Create & Authorize Case'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
