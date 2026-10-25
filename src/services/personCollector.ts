/**
 * SENTINEL OSINT — Passive Person, Developer & Email Reconnaissance Collector
 * Strictly passive reconnaissance: public GitHub developer profiles and RFC 5322 email / MX routing verification
 */

import crypto from 'crypto';
import { executeDnsCollection } from './dnsCollector.ts';

export interface DeveloperProfile {
  username: string;
  name?: string;
  company?: string;
  blog?: string;
  location?: string;
  email?: string;
  bio?: string;
  public_repos: number;
  followers: number;
  created_at: string;
  updated_at: string;
  profile_url: string;
  avatar_url?: string;
}

export interface EmailVerificationResult {
  email: string;
  domain: string;
  syntax_valid: boolean;
  has_mx_records: boolean;
  mx_records: string[];
  deliverability_probability: 'HIGH' | 'MEDIUM' | 'LOW' | 'INVALID';
  notes: string;
}

export interface PersonReconResult {
  target: string;
  type: 'GITHUB_DEVELOPER' | 'EMAIL';
  source_url: string;
  retrieval_timestamp: string;
  is_successful: boolean;
  status_code?: number;
  developer_profile?: DeveloperProfile;
  email_verification?: EmailVerificationResult;
  raw_payload?: any;
  content_hash: string;
  error?: string;
}

export function computeCanonicalSha256(data: any): string {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Validates a GitHub username format
 */
export function validateGithubUsername(username: string): boolean {
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/.test(username.trim());
}

/**
 * Validates email syntax according to RFC 5322 standard
 */
export function validateEmailSyntax(email: string): boolean {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return emailRegex.test(email.trim());
}

/**
 * Queries GitHub public API for passive developer profile
 */
export async function executeGithubLookup(username: string, timeoutMs = 8000): Promise<PersonReconResult> {
  const trimmed = username.trim();
  const now = new Date().toISOString();

  if (!validateGithubUsername(trimmed)) {
    return {
      target: trimmed,
      type: 'GITHUB_DEVELOPER',
      source_url: '',
      retrieval_timestamp: now,
      is_successful: false,
      error: 'Invalid GitHub username format (must be 1-39 alphanumeric/hyphen characters)',
      content_hash: computeCanonicalSha256({ error: 'invalid_username', target: trimmed })
    };
  }

  const sourceUrl = `https://api.github.com/users/${encodeURIComponent(trimmed)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(sourceUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'SENTINEL-OSINT-Recon/1.0 (Passive OSINT Research)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const statusCode = res.status;

    if (statusCode === 404) {
      return {
        target: trimmed,
        type: 'GITHUB_DEVELOPER',
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: 404,
        error: `NOT_FOUND: GitHub profile "${trimmed}" does not exist`,
        content_hash: computeCanonicalSha256({ status: 404, username: trimmed })
      };
    }

    if (statusCode === 403) {
      return {
        target: trimmed,
        type: 'GITHUB_DEVELOPER',
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: 403,
        error: 'RATE_LIMITED: GitHub unauthenticated public rate limit exceeded. Retry later.',
        content_hash: computeCanonicalSha256({ status: 403, username: trimmed })
      };
    }

    if (!res.ok) {
      return {
        target: trimmed,
        type: 'GITHUB_DEVELOPER',
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: statusCode,
        error: `HTTP_${statusCode}: GitHub returned ${res.statusText}`,
        content_hash: computeCanonicalSha256({ status: statusCode, username: trimmed })
      };
    }

    const raw = await res.json();
    const profile: DeveloperProfile = {
      username: raw.login || trimmed,
      name: raw.name || undefined,
      company: raw.company || undefined,
      blog: raw.blog || undefined,
      location: raw.location || undefined,
      email: raw.email || undefined,
      bio: raw.bio || undefined,
      public_repos: typeof raw.public_repos === 'number' ? raw.public_repos : 0,
      followers: typeof raw.followers === 'number' ? raw.followers : 0,
      created_at: raw.created_at || now,
      updated_at: raw.updated_at || now,
      profile_url: raw.html_url || `https://github.com/${trimmed}`,
      avatar_url: raw.avatar_url
    };

    return {
      target: trimmed,
      type: 'GITHUB_DEVELOPER',
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: true,
      status_code: statusCode,
      developer_profile: profile,
      raw_payload: raw,
      content_hash: computeCanonicalSha256(raw)
    };
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');
    return {
      target: trimmed,
      type: 'GITHUB_DEVELOPER',
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: false,
      error: isTimeout ? `REQUEST_TIMEOUT: GitHub did not respond within ${timeoutMs}ms` : `NETWORK_ERROR: ${err.message}`,
      content_hash: computeCanonicalSha256({ error: err.message, target: trimmed })
    };
  }
}

/**
 * Validates an email address passively using RFC 5322 syntax validation and DoH MX lookup
 */
export async function executeEmailRecon(email: string): Promise<PersonReconResult> {
  const trimmed = email.trim().toLowerCase();
  const now = new Date().toISOString();
  const syntaxValid = validateEmailSyntax(trimmed);

  if (!syntaxValid) {
    return {
      target: trimmed,
      type: 'EMAIL',
      source_url: 'internal://syntax-check',
      retrieval_timestamp: now,
      is_successful: false,
      error: 'Invalid email address syntax (violates RFC 5322 standards)',
      email_verification: {
        email: trimmed,
        domain: trimmed.split('@')[1] || '',
        syntax_valid: false,
        has_mx_records: false,
        mx_records: [],
        deliverability_probability: 'INVALID',
        notes: 'Syntax error in email address format'
      },
      content_hash: computeCanonicalSha256({ email: trimmed, syntax_valid: false })
    };
  }

  const domain = trimmed.split('@')[1];
  let hasMx = false;
  const mxHosts: string[] = [];

  try {
    const dnsResult = await executeDnsCollection(domain, ['MX'], 'col_doh_cloudflare');
    const mxRecordResult = dnsResult.records.find(r => r.record_type === 'MX');

    if (mxRecordResult && mxRecordResult.is_successful && mxRecordResult.answers.length > 0) {
      hasMx = true;
      for (const ans of mxRecordResult.answers) {
        // MX record data usually has priority + host (e.g., "10 mail.example.com.")
        const parts = ans.data.trim().split(/\s+/);
        const host = parts.length > 1 ? parts[1].replace(/\.$/, '') : parts[0];
        mxHosts.push(host);
      }
    }
  } catch {
    // DNS resolution failure
  }

    const deliverability: 'HIGH' | 'MEDIUM' | 'LOW' | 'INVALID' = hasMx ? 'HIGH' : 'LOW';
    const notes = hasMx 
      ? `Domain ${domain} accepts inbound mail via ${mxHosts.length} MX server(s): ${mxHosts.join(', ')}. Evidentiary Notice: MX routing confirms zone mail exchangers only; it does NOT confirm mailbox existence or the legal identity of an individual.`
      : `Domain ${domain} has NO active MX mail exchangers reported via DNS. Mailbox delivery impossible.`;

    return {
      target: trimmed,
      type: 'EMAIL',
      source_url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      retrieval_timestamp: now,
      is_successful: true,
      email_verification: {
        email: trimmed,
        domain,
        syntax_valid: true,
        has_mx_records: hasMx,
        mx_records: mxHosts,
        deliverability_probability: deliverability,
        notes
      },
      raw_payload: { 
        email: trimmed, 
        domain, 
        syntaxValid, 
        hasMx, 
        mxHosts,
        evidentiary_notice: 'Passive MX resolution proves domain routing configuration only; does NOT prove mailbox existence or personal identity.'
      },
      content_hash: computeCanonicalSha256({ email: trimmed, domain, hasMx, mxHosts })
    };
}
