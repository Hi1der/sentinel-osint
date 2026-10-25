import { 
  InvestigationCase, 
  EvidenceItem, 
  Entity, 
  Relationship, 
  ScanJob, 
  AuditRecord, 
  AuditVerificationResult,
  DataSourceStatus 
} from '../types/osint.ts';

export async function fetchHealth() {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Failed to fetch system health');
  return res.json();
}

export async function fetchStats() {
  const res = await fetch('/api/stats');
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchCases(): Promise<InvestigationCase[]> {
  const res = await fetch('/api/cases');
  if (!res.ok) throw new Error('Failed to fetch cases');
  return res.json();
}

export async function fetchCase(id: string): Promise<InvestigationCase> {
  const res = await fetch(`/api/cases/${id}`);
  if (!res.ok) throw new Error('Failed to fetch case');
  return res.json();
}

export async function createCase(data: Partial<InvestigationCase>): Promise<InvestigationCase> {
  const res = await fetch('/api/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to create case');
  }
  return res.json();
}

export async function updateCase(id: string, data: Partial<InvestigationCase>): Promise<InvestigationCase> {
  const res = await fetch(`/api/cases/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to update case');
  }
  return res.json();
}

export async function deleteCase(id: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`/api/cases/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to delete case');
  }
  return res.json();
}

export async function validateScope(caseId: string, target: string): Promise<{ in_scope: boolean; reason?: string }> {
  const res = await fetch('/api/scope/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_id: caseId, target }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to validate scope');
  }
  return res.json();
}

export async function fetchEvidence(caseId?: string): Promise<EvidenceItem[]> {
  const url = caseId ? `/api/evidence?case_id=${encodeURIComponent(caseId)}` : '/api/evidence';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch evidence');
  return res.json();
}

export async function fetchEntities(caseId?: string): Promise<Entity[]> {
  const url = caseId ? `/api/entities?case_id=${encodeURIComponent(caseId)}` : '/api/entities';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch entities');
  return res.json();
}

export async function fetchRelationships(caseId?: string): Promise<Relationship[]> {
  const url = caseId ? `/api/relationships?case_id=${encodeURIComponent(caseId)}` : '/api/relationships';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch relationships');
  return res.json();
}

export async function fetchJobs(caseId?: string): Promise<ScanJob[]> {
  const url = caseId ? `/api/jobs?case_id=${encodeURIComponent(caseId)}` : '/api/jobs';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch jobs');
  return res.json();
}

export async function dispatchJob(payload: {
  case_id: string;
  target_identifier: string;
  target_type: string;
  collectors_selected: string[];
}): Promise<ScanJob> {
  const res = await fetch('/api/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.details || err.error || 'Failed to dispatch job');
  }
  return res.json();
}

export async function cancelJob(id: string): Promise<ScanJob> {
  const res = await fetch(`/api/jobs/${id}/cancel`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to cancel job');
  }
  return res.json();
}

export async function fetchAuditLogs(): Promise<AuditRecord[]> {
  const res = await fetch('/api/audit');
  if (!res.ok) throw new Error('Failed to fetch audit records');
  return res.json();
}

export async function verifyAuditChain(): Promise<AuditVerificationResult> {
  const res = await fetch('/api/audit/verify');
  if (!res.ok) throw new Error('Failed to execute audit verification');
  return res.json();
}

export async function fetchDataSources(): Promise<DataSourceStatus[]> {
  const res = await fetch('/api/sources');
  if (!res.ok) throw new Error('Failed to fetch data sources');
  return res.json();
}

export async function executeDnsCollectionApi(payload: {
  case_id: string;
  target_domain: string;
  record_types?: string[];
  resolver?: string;
}) {
  const res = await fetch('/api/collectors/dns', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.details || err.message || err.error || 'DNS collection failed');
  }
  return res.json();
}

export async function triggerCorrelation(caseId: string): Promise<{
  success: boolean;
  case_id: string;
  case_number: string;
  entities_count: number;
  relationships_count: number;
  new_entities_count: number;
  new_relationships_count: number;
  updated_entities_count: number;
  updated_relationships_count: number;
}> {
  const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/correlate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || 'Failed to trigger correlation');
  }
  return res.json();
}

export async function executeRdapLookupApi(payload: { case_id: string; target: string }) {
  const res = await fetch('/api/collectors/rdap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'RDAP query failed');
  }
  return res.json();
}

export async function executeCrtLookupApi(payload: { case_id: string; target_domain: string }) {
  const res = await fetch('/api/collectors/crt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'Certificate Transparency query failed');
  }
  return res.json();
}

export async function executeBgpLookupApi(payload: { case_id: string; target_ip: string }) {
  const res = await fetch('/api/collectors/bgp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'BGP query failed');
  }
  return res.json();
}

export async function executePersonLookupApi(payload: { case_id: string; target: string; type?: 'GITHUB_DEVELOPER' | 'EMAIL' }) {
  const res = await fetch('/api/collectors/person', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'Person reconnaissance failed');
  }
  return res.json();
}

export async function fetchAiAssessment(caseId: string) {
  const res = await fetch(`/api/analysis/${encodeURIComponent(caseId)}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'Failed to fetch AI assessment');
  }
  return res.json();
}

export async function generateAiAssessmentApi(caseId: string) {
  const res = await fetch('/api/analysis/investigate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ case_id: caseId }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || 'Failed to generate AI analysis');
  }
  return res.json();
}

