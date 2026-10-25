import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, 
  Hash, 
  RotateCw, 
  CheckCircle2, 
  AlertTriangle, 
  Copy, 
  Check, 
  Lock,
  Layers,
  Info
} from 'lucide-react';
import * as api from '../../services/api.ts';
import { AuditRecord, AuditVerificationResult } from '../../types/osint.ts';

export const AuditLogView: React.FC = () => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [verification, setVerification] = useState<AuditVerificationResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAuditData = async () => {
    try {
      const data = await api.fetchAuditLogs();
      setLogs(data);
    } catch (err) {
      console.error('Failed to load audit logs', err);
    } finally {
      setLoading(false);
    }
  };

  const runVerification = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAuditChain();
      setVerification(res);
    } catch (err: any) {
      console.error('Verification failed', err);
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, []);

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-purple-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Cryptographic Audit Log & SHA-256 Hash Chain
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Every investigation mutation, case update, and outbound scan is bound to an immutable SHA-256 hash chain with deterministic canonical serialization.
          </p>
        </div>

        <button
          onClick={runVerification}
          disabled={verifying}
          className="px-4 py-2 rounded bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium transition-colors shadow-sm flex items-center gap-1.5 self-start md:self-auto disabled:opacity-50"
        >
          <RotateCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
          <span>{verifying ? 'Verifying Chain...' : 'Verify Cryptographic Integrity'}</span>
        </button>
      </div>

      {/* Verification Result Banner */}
      {verification && (
        <div
          className={`p-4 rounded-lg border flex items-start gap-3 ${
            verification.valid
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
              : 'bg-red-950/40 border-red-800 text-red-200'
          }`}
        >
          {verification.valid ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-1 text-xs">
            <div className="font-semibold text-sm">
              {verification.valid ? 'Cryptographic Hash Chain Untampered' : 'Audit Chain Mismatch Detected'}
            </div>
            <p className="leading-relaxed opacity-90">{verification.message}</p>
            <div className="text-[11px] font-mono text-slate-400 pt-1">
              Verified: {verification.verified_records} / {verification.total_records} records · Checked at: {new Date(verification.checked_at).toLocaleTimeString()}
            </div>
          </div>
        </div>
      )}

      {/* Audit Notice Callout */}
      <div className="p-3.5 rounded bg-slate-900/60 border border-slate-800 flex items-start gap-2.5 text-xs text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong>Security Note on Non-Repudiation:</strong> An internal SHA-256 hash chain guarantees tamper-evident sequential logging. Modification of any record breaks subsequent digests. However, absolute non-repudiation requires anchoring periodic checkpoints to external distributed timestamping or trusted key management.
        </p>
      </div>

      {/* Hash Chain Log Table */}
      <div className="rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-lg">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60 font-mono text-xs">
          <span className="font-semibold text-slate-200 uppercase">
            Sequential Audit Ledger ({logs.length} Blocks)
          </span>
          <span className="text-slate-500 text-[11px]">Formula: SHA256(LogID || UserID || Action || Target || Timestamp || PrevHash)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Block #</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Previous Hash</th>
                <th className="px-4 py-3">Current Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-[11px]">
              {logs.map((record) => (
                <tr key={record.log_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-3 font-bold text-cyan-400 tabular-nums">
                    #{record.log_id}
                  </td>
                  <td className="px-4 py-3 text-slate-200 font-semibold">
                    {record.action}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {record.target}
                  </td>
                  <td className="px-4 py-3 text-slate-500">
                    {new Date(record.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-slate-500">
                    <span className="truncate max-w-[100px] block font-mono text-[10px]">
                      {record.previous_hash.slice(0, 12)}…
                    </span>
                  </td>
                  <td className="px-4 py-3 text-cyan-300">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[10px] truncate max-w-[120px]">
                        {record.current_hash.slice(0, 16)}…
                      </span>
                      <button
                        onClick={() => handleCopy(record.current_hash)}
                        className="text-slate-400 hover:text-cyan-300 p-0.5"
                        title="Copy Full Hash"
                      >
                        {copiedHash === record.current_hash ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
