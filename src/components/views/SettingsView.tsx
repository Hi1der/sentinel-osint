import React from 'react';
import { 
  Sliders, 
  ShieldCheck, 
  Lock, 
  Database, 
  Key, 
  FileCheck2, 
  AlertTriangle,
  Cpu
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h1 className="text-lg font-bold text-slate-100 font-sans">
            Platform Configuration & Access Control
          </h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          System policies, scope enforcement parameters, security guardrails, and cryptographic logging configurations.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Session & Identity */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 shadow-md text-xs">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Analyst Identity & Authorization</h2>
          </div>

          <div className="space-y-2 font-mono text-[11px]">
            <div className="flex justify-between p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500">Authenticated User:</span>
              <span className="text-slate-200">s30408390@gmail.com</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500">Assigned Role:</span>
              <span className="text-cyan-400 font-bold">SENIOR_THREAT_ANALYST</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500">Execution Mode:</span>
              <span className="text-emerald-400">STRICT_PASSIVE_ONLY</span>
            </div>
          </div>
        </div>

        {/* Security & Scope Enforcement */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 shadow-md text-xs">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-100">Server-Side Scope Guardrails</h2>
          </div>

          <div className="space-y-2 text-slate-300 leading-relaxed font-sans text-xs">
            <p>
              Target scope boundaries are enforced on the backend before any outbound connection is established. Outbound requests outside authorized case boundaries are denied with a structured security violation.
            </p>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1">
              <div className="text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>SSRF Loopback / RFC1918 Blocking: ACTIVE</span>
              </div>
              <div className="text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Cloud Metadata (169.254.169.254) Blocking: ACTIVE</span>
              </div>
              <div className="text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Response Size Limit: 1MB Hard Cap</span>
              </div>
            </div>
          </div>
        </div>

        {/* Data Minimization & Retention */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 shadow-md text-xs">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Database className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold text-slate-100">Telemetry Retention Policy</h2>
          </div>

          <div className="space-y-2.5 text-slate-300">
            <p className="text-xs text-slate-400">
              Raw telemetry payloads are scheduled for automated 30-day data minimization purging, while cryptographic SHA-256 audit log blocks remain permanently append-only for verifiable non-repudiation.
            </p>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-500">Raw Telemetry Store:</span>
                <span className="text-slate-300">30 Days Auto-Purge</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Audit Log Chain:</span>
                <span className="text-purple-300 font-bold">PERMANENT / APPEND-ONLY</span>
              </div>
            </div>
          </div>
        </div>

        {/* AI Engine Status */}
        <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4 shadow-md text-xs">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Gemini AI Threat Intelligence Engine</h2>
          </div>

          <div className="space-y-2 text-slate-300">
            <p className="text-xs text-slate-400">
              AI analytical features operate strictly server-side using the <code className="text-cyan-300 font-mono">@google/genai</code> SDK. All model hypotheses require explicit evidence ID citations. No keys are exposed to client-side bundles.
            </p>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-500">Assigned Model:</span>
                <span className="text-cyan-300">gemini-3.8-flash</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Evidence Citation Guard:</span>
                <span className="text-emerald-400 font-bold">MANDATORY</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
