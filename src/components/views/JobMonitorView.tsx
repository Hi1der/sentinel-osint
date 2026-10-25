import React, { useEffect, useState } from 'react';
import { 
  Terminal, 
  Activity, 
  Play, 
  XCircle, 
  RotateCw, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Search,
  FileText
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { ScanJob } from '../../types/osint.ts';

interface JobMonitorViewProps {
  onOpenQuickScanModal: () => void;
}

export const JobMonitorView: React.FC<JobMonitorViewProps> = ({ onOpenQuickScanModal }) => {
  const { activeCase, showNotification } = useCase();
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);

  const loadJobs = async () => {
    try {
      const data = await api.fetchJobs();
      setJobs(data);
      if (data.length > 0 && !selectedJob) {
        setSelectedJob(data[0]);
      }
    } catch (err) {
      console.error('Failed to load jobs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadJobs();
    const interval = setInterval(loadJobs, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleCancelJob = async (jobId: string) => {
    try {
      const updated = await api.cancelJob(jobId);
      showNotification('info', `Job #${jobId.slice(-6)} has been cancelled.`);
      setJobs((prev) => prev.map((j) => (j.job_id === jobId ? updated : j)));
      if (selectedJob?.job_id === jobId) setSelectedJob(updated);
    } catch (err: any) {
      showNotification('error', `Cancel failed: ${err.message}`);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h1 className="text-lg font-bold text-slate-100 font-sans">
              Reconnaissance Job Queue & Monitor
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time state machine lifecycle (PENDING → RUNNING → COMPLETED / FAILED / CANCELLED) with rate-limit and circuit breaker logging.
          </p>
        </div>

        <button
          onClick={onOpenQuickScanModal}
          className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors shadow-sm flex items-center gap-1.5 self-start md:self-auto"
        >
          <Play className="w-3.5 h-3.5" />
          <span>Dispatch New Recon Job</span>
        </button>
      </div>

      {/* Main Split: Jobs Table & Real-Time Log Console */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Jobs Table (2 Cols) */}
        <div className="lg:col-span-2 rounded-lg bg-slate-900 border border-slate-800 overflow-hidden shadow-lg">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
              Job Queue Register ({jobs.length})
            </span>
            <button
              onClick={loadJobs}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
            >
              <RotateCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Job ID</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Collectors</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {jobs.map((job) => {
                  const isSelected = selectedJob?.job_id === job.job_id;
                  return (
                    <tr
                      key={job.job_id}
                      onClick={() => setSelectedJob(job)}
                      className={`hover:bg-slate-800/40 transition-colors cursor-pointer ${
                        isSelected ? 'bg-cyan-950/30' : ''
                      }`}
                    >
                      <td className="px-4 py-3 font-semibold text-cyan-400">
                        {job.job_id.slice(-8)}
                        {job.is_demo && (
                          <span className="ml-2 inline-flex items-center gap-1 font-mono text-[10px] text-amber-400">
                            <span className="w-1 h-1 rounded-full bg-amber-400" />
                            DEMO
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-slate-100 font-medium">{job.target_identifier}</td>
                      <td className="px-4 py-3 text-slate-400">{job.collectors_selected.length} active</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            job.status === 'COMPLETED' ? 'bg-emerald-400' :
                            job.status === 'RUNNING' ? 'bg-cyan-400 animate-ping' :
                            job.status === 'FAILED' ? 'bg-red-400' :
                            job.status === 'CANCELLED' ? 'bg-slate-400' :
                            'bg-amber-400'
                          }`} />
                          {job.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-500">
                        {new Date(job.started_at).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {(job.status === 'RUNNING' || job.status === 'PENDING') && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCancelJob(job.job_id);
                            }}
                            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-red-950 text-red-300 border border-red-900 transition-colors text-[10px]"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Selected Job Telemetry Logs */}
        <div className="space-y-4">
          {selectedJob ? (
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3 text-xs">
              <div className="border-b border-slate-800 pb-2 flex items-center justify-between">
                <div>
                  <span className="font-mono text-cyan-400 font-bold block">{selectedJob.job_id}</span>
                  <span className="text-slate-300 font-medium mt-0.5 block">Target: {selectedJob.target_identifier}</span>
                </div>
                <span className="text-[10px] text-slate-400 font-mono">{selectedJob.status}</span>
              </div>

              {/* Collectors Applied */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Configured Collectors</span>
                <div className="flex flex-wrap gap-1">
                  {selectedJob.collectors_selected.map((col) => (
                    <span key={col} className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-[10px]">
                      {col}
                    </span>
                  ))}
                </div>
              </div>

              {/* Execution Console Logs */}
              <div className="space-y-1.5 pt-1">
                <span className="text-[10px] font-mono text-slate-500 uppercase flex items-center justify-between">
                  <span>Execution Output Stream</span>
                  <span className="text-cyan-400 text-[10px]">Buffered</span>
                </span>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1.5 text-slate-300 max-h-72 overflow-y-auto leading-relaxed">
                  {selectedJob.logs.map((log, i) => (
                    <div key={i} className="border-b border-slate-900 pb-1 last:border-0">
                      {log}
                    </div>
                  ))}
                </div>
              </div>

              {/* Results Summary if completed */}
              {selectedJob.results_summary && (
                <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 space-y-1 font-mono text-[11px]">
                  <span className="text-slate-500 uppercase text-[10px] block">Yield Summary</span>
                  <div className="flex justify-between text-slate-300">
                    <span>Discovered Entities:</span>
                    <span className="text-cyan-400 font-bold">{selectedJob.results_summary.entities_discovered}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Collected Evidence:</span>
                    <span className="text-emerald-400 font-bold">{selectedJob.results_summary.evidence_collected}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span>Formed Relationships:</span>
                    <span className="text-blue-400 font-bold">{selectedJob.results_summary.relations_formed}</span>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-6 rounded-lg bg-slate-900 border border-slate-800 text-center text-slate-500 text-xs font-mono">
              Select a job to view output stream.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
