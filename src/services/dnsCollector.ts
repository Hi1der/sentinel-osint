/**
 * SENTINEL OSINT — Passive DNS-over-HTTPS Collector Service
 * Strictly passive DoH queries using allowlisted Cloudflare and Google JSON APIs
 */

import crypto from 'crypto';
import { 
  ALLOWED_DOH_RESOLVERS, 
  DnsRecordType, 
  ResolverId, 
  SUPPORTED_DNS_RECORD_TYPES 
} from '../utils/dnsValidation.ts';

export interface DnsAnswerRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface RawDnsResponse {
  Status: number;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  AD?: boolean;
  CD?: boolean;
  Question?: Array<{ name: string; type: number }>;
  Answer?: DnsAnswerRecord[];
  Authority?: any[];
  Comment?: string;
}

export type QueryOutcomeType = 
  | 'SUCCESS_WITH_RECORDS' 
  | 'SUCCESS_NXDOMAIN' 
  | 'SUCCESS_NO_ANSWERS' 
  | 'FAILED_HTTP' 
  | 'FAILED_TIMEOUT' 
  | 'FAILED_MALFORMED' 
  | 'FAILED_OVERSIZED' 
  | 'FAILED_REDIRECT' 
  | 'FAILED_RATE_LIMITED';

export interface SingleRecordResult {
  record_type: DnsRecordType;
  resolver_used: string;
  source_url: string;
  retrieval_timestamp: string;
  status_code?: number; // DNS RCODE
  outcome: QueryOutcomeType;
  is_successful: boolean;
  answers: DnsAnswerRecord[];
  normalized_summary: string;
  raw_payload?: RawDnsResponse;
  content_hash?: string;
  error?: string;
}

export interface DnsCollectorJobResult {
  target: string;
  resolver_requested: string;
  started_at: string;
  completed_at: string;
  overall_status: 'COMPLETED' | 'PARTIAL_SUCCESS' | 'FAILED';
  total_queries: number;
  successful_queries: number;
  failed_queries: number;
  records: SingleRecordResult[];
  discovered_ips: string[];
  discovered_cnames: string[];
  discovered_mx: string[];
  discovered_ns: string[];
}

// In-memory Rate Limiting (Token Bucket per resolver)
interface RateBucket {
  tokens: number;
  lastRefill: number;
}

const RATE_BUCKETS: Record<string, RateBucket> = {
  col_doh_cloudflare: { tokens: 60, lastRefill: Date.now() },
  col_doh_google: { tokens: 60, lastRefill: Date.now() },
};

function checkRateLimit(resolverId: string, limitPerMin = 60): boolean {
  const bucket = RATE_BUCKETS[resolverId];
  if (!bucket) return true;

  const now = Date.now();
  const elapsed = (now - bucket.lastRefill) / 1000;
  // Refill tokens
  bucket.tokens = Math.min(limitPerMin, bucket.tokens + elapsed * (limitPerMin / 60));
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return true;
  }
  return false;
}

export function computeCanonicalSha256(payload: unknown): string {
  // Deterministic JSON stringification
  const serialized = JSON.stringify(payload, Object.keys(payload as any).sort());
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Executes a single DoH query against an explicitly allowlisted provider.
 * Supports injected fetch client for hermetic automated testing.
 */
export async function querySingleRecord(
  domain: string,
  recordType: DnsRecordType,
  resolverId: 'col_doh_cloudflare' | 'col_doh_google',
  customFetch: typeof fetch = fetch
): Promise<SingleRecordResult> {
  const resolver = ALLOWED_DOH_RESOLVERS[resolverId];
  const retrievalTimestamp = new Date().toISOString();

  // 1. Fixed Resolver URL Construction
  const url = new URL(resolver.baseUrl);
  url.searchParams.set('name', domain);
  url.searchParams.set('type', recordType);
  const sourceUrl = url.toString();

  // Strict Host & Protocol Verification
  if (url.protocol !== 'https:' || !resolver.baseUrl.startsWith(url.origin)) {
    return {
      record_type: recordType,
      resolver_used: resolver.name,
      source_url: sourceUrl,
      retrieval_timestamp: retrievalTimestamp,
      outcome: 'FAILED_MALFORMED',
      is_successful: false,
      answers: [],
      normalized_summary: 'Target resolver URL failed strict origin allowlist validation.',
      error: 'SECURITY_VIOLATION: Resolver endpoint must match strict allowlist origin.'
    };
  }

  // 2. Rate Limit Enforcement
  if (!checkRateLimit(resolverId, 60)) {
    return {
      record_type: recordType,
      resolver_used: resolver.name,
      source_url: sourceUrl,
      retrieval_timestamp: retrievalTimestamp,
      outcome: 'FAILED_RATE_LIMITED',
      is_successful: false,
      answers: [],
      normalized_summary: `Rate limit threshold exceeded for ${resolver.name}.`,
      error: 'RATE_LIMIT_EXCEEDED: Maximum 60 queries/minute per provider.'
    };
  }

  // 3. Outbound Request with Strict Timeouts & Size Guardrails
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000); // 4000ms strict timeout

  try {
    const res = await customFetch(sourceUrl, {
      method: 'GET',
      headers: {
        'Accept': resolver.acceptHeader,
        'User-Agent': 'SENTINEL-OSINT/1.0 (Passive; Authorized-Scope)',
      },
      signal: controller.signal,
      redirect: 'manual', // Strictly reject redirects
    });

    clearTimeout(timeoutId);

    // 4. Reject Redirect Responses (SSRF / Redirection Guard)
    if (res.status >= 300 && res.status < 400) {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_REDIRECT',
        is_successful: false,
        answers: [],
        normalized_summary: `Resolver issued unexpected HTTP redirect (${res.status}). Aborted.`,
        error: `REDIRECT_REJECTED: Automatic redirects are prohibited on resolver endpoints.`
      };
    }

    // 5. Check Content-Length & Read Response with Bounded Size Cap (512KB)
    const MAX_SIZE = 512 * 1024;
    const contentLength = res.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_SIZE) {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_OVERSIZED',
        is_successful: false,
        answers: [],
        normalized_summary: `Resolver response size (${contentLength} bytes) exceeds 512KB limit.`,
        error: 'OVERSIZED_RESPONSE: Maximum allowable DoH response payload is 512KB.'
      };
    }

    if (!res.ok) {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_HTTP',
        is_successful: false,
        answers: [],
        normalized_summary: `Resolver returned HTTP error ${res.status} ${res.statusText}.`,
        error: `HTTP_ERROR_${res.status}: ${res.statusText}`
      };
    }

    const rawText = await res.text();
    if (rawText.length > MAX_SIZE) {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_OVERSIZED',
        is_successful: false,
        answers: [],
        normalized_summary: `Response payload stream exceeded 512KB limit.`,
        error: 'OVERSIZED_RESPONSE'
      };
    }

    let json: RawDnsResponse;
    try {
      json = JSON.parse(rawText);
    } catch (parseErr) {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_MALFORMED',
        is_successful: false,
        answers: [],
        normalized_summary: 'Resolver response body could not be parsed as valid JSON.',
        error: 'MALFORMED_JSON_PAYLOAD'
      };
    }

    // 6. Validate DNS Payload Structure
    if (typeof json.Status !== 'number') {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_MALFORMED',
        is_successful: false,
        answers: [],
        normalized_summary: 'DNS payload missing mandatory numeric "Status" RCODE field.',
        error: 'INVALID_DNS_SCHEMA'
      };
    }

    const contentHash = computeCanonicalSha256(json);
    const answers = Array.isArray(json.Answer) ? json.Answer : [];

    // Outcome Classification
    if (json.Status === 3) {
      // Valid NXDOMAIN (Name Error: domain does not exist)
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        status_code: 3,
        outcome: 'SUCCESS_NXDOMAIN',
        is_successful: true,
        answers: [],
        normalized_summary: `NXDOMAIN (Domain does not exist according to authoritative zone)`,
        raw_payload: json,
        content_hash: contentHash
      };
    }

    if (json.Status === 0) {
      // NOERROR
      if (answers.length > 0) {
        const summary = answers.map(a => `${a.data} (TTL: ${a.TTL}s)`).join(', ');
        return {
          record_type: recordType,
          resolver_used: resolver.name,
          source_url: sourceUrl,
          retrieval_timestamp: retrievalTimestamp,
          status_code: 0,
          outcome: 'SUCCESS_WITH_RECORDS',
          is_successful: true,
          answers,
          normalized_summary: `${recordType}: ${summary}`,
          raw_payload: json,
          content_hash: contentHash
        };
      } else {
        return {
          record_type: recordType,
          resolver_used: resolver.name,
          source_url: sourceUrl,
          retrieval_timestamp: retrievalTimestamp,
          status_code: 0,
          outcome: 'SUCCESS_NO_ANSWERS',
          is_successful: true,
          answers: [],
          normalized_summary: `NOERROR (Valid domain, but no ${recordType} records present in zone)`,
          raw_payload: json,
          content_hash: contentHash
        };
      }
    }

    // Other DNS RCODEs (e.g. 2: SERVFAIL, 5: REFUSED)
    return {
      record_type: recordType,
      resolver_used: resolver.name,
      source_url: sourceUrl,
      retrieval_timestamp: retrievalTimestamp,
      status_code: json.Status,
      outcome: 'FAILED_HTTP',
      is_successful: false,
      answers: [],
      normalized_summary: `DNS query failed with RCODE ${json.Status}${json.Comment ? ` (${json.Comment})` : ''}.`,
      raw_payload: json,
      content_hash: contentHash,
      error: `DNS_RCODE_${json.Status}`
    };

  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      return {
        record_type: recordType,
        resolver_used: resolver.name,
        source_url: sourceUrl,
        retrieval_timestamp: retrievalTimestamp,
        outcome: 'FAILED_TIMEOUT',
        is_successful: false,
        answers: [],
        normalized_summary: `Resolver query timed out after 4000ms.`,
        error: 'TIMEOUT'
      };
    }

    return {
      record_type: recordType,
      resolver_used: resolver.name,
      source_url: sourceUrl,
      retrieval_timestamp: retrievalTimestamp,
      outcome: 'FAILED_HTTP',
      is_successful: false,
      answers: [],
      normalized_summary: `Network request failed: ${err.message}`,
      error: err.message
    };
  }
}

/**
 * Orchestrates multi-record passive DNS collection with resolver fallback strategy.
 */
export async function executeDnsCollection(
  domain: string,
  recordTypes: DnsRecordType[],
  preferredResolver: ResolverId = 'col_doh_cloudflare',
  customFetch: typeof fetch = fetch
): Promise<DnsCollectorJobResult> {
  const startedAt = new Date().toISOString();
  const results: SingleRecordResult[] = [];

  const discoveredIps = new Set<string>();
  const discoveredCnames = new Set<string>();
  const discoveredMx = new Set<string>();
  const discoveredNs = new Set<string>();

  for (const rType of recordTypes) {
    let result: SingleRecordResult;

    if (preferredResolver === 'auto') {
      // Primary: Cloudflare, Fallback: Google
      result = await querySingleRecord(domain, rType, 'col_doh_cloudflare', customFetch);
      if (!result.is_successful && (result.outcome === 'FAILED_HTTP' || result.outcome === 'FAILED_TIMEOUT')) {
        const fallbackResult = await querySingleRecord(domain, rType, 'col_doh_google', customFetch);
        if (fallbackResult.is_successful) {
          result = fallbackResult;
        }
      }
    } else {
      const activeResolver = preferredResolver === 'col_doh_google' ? 'col_doh_google' : 'col_doh_cloudflare';
      result = await querySingleRecord(domain, rType, activeResolver, customFetch);
    }

    results.push(result);

    // Extract correlated indicators from successful answers
    if (result.is_successful && result.answers) {
      for (const ans of result.answers) {
        if (rType === 'A' || rType === 'AAAA') {
          discoveredIps.add(ans.data);
        } else if (rType === 'CNAME') {
          discoveredCnames.add(ans.data.replace(/\.$/, ''));
        } else if (rType === 'MX') {
          // MX data format: "10 mail.example.com."
          const parts = ans.data.trim().split(/\s+/);
          const host = parts.length > 1 ? parts[1].replace(/\.$/, '') : ans.data;
          discoveredMx.add(host);
        } else if (rType === 'NS') {
          discoveredNs.add(ans.data.replace(/\.$/, ''));
        }
      }
    }
  }

  const completedAt = new Date().toISOString();
  const successfulCount = results.filter(r => r.is_successful).length;
  const failedCount = results.length - successfulCount;

  let overallStatus: 'COMPLETED' | 'PARTIAL_SUCCESS' | 'FAILED';
  if (successfulCount === results.length) {
    overallStatus = 'COMPLETED';
  } else if (successfulCount > 0) {
    overallStatus = 'PARTIAL_SUCCESS';
  } else {
    overallStatus = 'FAILED';
  }

  return {
    target: domain,
    resolver_requested: preferredResolver,
    started_at: startedAt,
    completed_at: completedAt,
    overall_status: overallStatus,
    total_queries: results.length,
    successful_queries: successfulCount,
    failed_queries: failedCount,
    records: results,
    discovered_ips: Array.from(discoveredIps),
    discovered_cnames: Array.from(discoveredCnames),
    discovered_mx: Array.from(discoveredMx),
    discovered_ns: Array.from(discoveredNs),
  };
}
