/**
 * SENTINEL OSINT — Domain Data Types & Specification Contracts
 */

export type TargetType = 'DOMAIN' | 'IP' | 'ASN' | 'URL' | 'EMAIL_DOMAIN';

export type CaseStatus = 'ACTIVE' | 'ARCHIVED' | 'CLOSED';
export type CasePriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface InvestigationScope {
  domains: string[];
  ipRanges: string[];
  allowedCollectorTypes: string[];
  notes?: string;
}

export interface InvestigationCase {
  id: string;
  case_number: string;
  title: string;
  description: string;
  objective: string;
  status: CaseStatus;
  priority: CasePriority;
  tags: string[];
  scope: InvestigationScope;
  created_by: string;
  created_at: string;
  updated_at: string;
  is_demo?: boolean;
}

export type JobStatus = 
  | 'PENDING' 
  | 'RUNNING' 
  | 'PARTIAL_SUCCESS' 
  | 'FAILED' 
  | 'RETRYING' 
  | 'CANCELLED' 
  | 'COMPLETED';

export interface ScanJob {
  job_id: string;
  case_id: string;
  target_identifier: string;
  target_type: TargetType;
  collectors_selected: string[];
  status: JobStatus;
  progress: number; // 0-100
  logs: string[];
  error_log?: string;
  started_at: string;
  completed_at?: string;
  created_by: string;
  results_summary?: {
    entities_discovered: number;
    evidence_collected: number;
    relations_formed: number;
  };
  is_demo?: boolean;
}

export type EntityType = 
  | 'DOMAIN' 
  | 'SUBDOMAIN' 
  | 'IP_ADDRESS' 
  | 'ASN' 
  | 'SSL_CERTIFICATE' 
  | 'ORGANIZATION' 
  | 'EMAIL_DOMAIN'
  | 'URL'
  | 'PERSON'
  | 'EMAIL';

export interface Entity {
  id: string;
  case_id: string;
  entity_type: EntityType;
  canonical_value: string;
  display_value: string;
  first_seen: string;
  last_seen: string;
  source_ids: string[];
  confidence_score: number; // 0.0 - 1.0
  metadata: Record<string, any>;
  is_demo?: boolean;
}

export type RelationshipType = 
  | 'HAS_SUBDOMAIN' 
  | 'RESOLVES_TO' 
  | 'BELONGS_TO_ASN' 
  | 'PRESENTS_CERTIFICATE' 
  | 'ISSUED_CERT'
  | 'OPERATED_BY'
  | 'ASSOCIATED_WITH';

export interface Relationship {
  id: string;
  case_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship_type: RelationshipType;
  first_seen: string;
  last_seen: string;
  confidence_score: number; // 0.0 - 1.0
  evidence_ids: string[];
  is_hypothesis?: boolean;
  scoring_explanation?: string;
  metadata?: Record<string, any>;
  is_demo?: boolean;
}

export type VerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'DEMO';

export interface EvidenceItem {
  id: string;
  case_id: string;
  collector_id: string;
  source_provider: string;
  source_url?: string;
  target_identifier: string;
  retrieval_timestamp: string;
  observation_timestamp?: string;
  normalized_value: string;
  raw_payload: any;
  content_hash: string; // SHA-256
  confidence_score: number;
  verification_status: VerificationStatus;
  is_demo?: boolean;
}

export interface AuditRecord {
  log_id: number;
  user_id: string;
  action: string;
  target: string;
  timestamp: string;
  previous_hash: string;
  current_hash: string;
  details?: Record<string, any>;
}

export interface AuditVerificationResult {
  valid: boolean;
  total_records: number;
  verified_records: number;
  broken_index?: number;
  tampered_log_id?: number;
  message: string;
  checked_at: string;
}

export interface DataSourceStatus {
  id: string;
  name: string;
  type: 'PASSIVE_DNS' | 'RDAP_WHOIS' | 'CERT_TRANSPARENCY' | 'BGP_ROUTING' | 'REPUTATION';
  endpoint: string;
  status: 'OPERATIONAL' | 'RATE_LIMITED' | 'DEGRADED' | 'CONFIG_REQUIRED';
  rate_limit_per_min: number;
  requests_today: number;
  circuit_breaker_open: boolean;
  last_checked: string;
  requires_key: boolean;
  key_configured: boolean;
  compliance_note: string;
}

export type ActiveView = 
  | 'overview' 
  | 'investigations' 
  | 'search' 
  | 'domain' 
  | 'ip-asn' 
  | 'dns' 
  | 'certificates' 
  | 'graph' 
  | 'evidence' 
  | 'timeline' 
  | 'reports' 
  | 'sources' 
  | 'jobs' 
  | 'audit' 
  | 'settings';
