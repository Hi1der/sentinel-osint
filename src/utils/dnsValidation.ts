/**
 * SENTINEL OSINT — DNS Normalization & Hostname Validation
 * RFC 1035 / RFC 1123 compliant domain validation
 */

import { InvestigationScope } from '../types/osint.ts';
import { isPrivateOrLoopbackIP } from './security.ts';

export const SUPPORTED_DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'] as const;
export type DnsRecordType = typeof SUPPORTED_DNS_RECORD_TYPES[number];

export const ALLOWED_DOH_RESOLVERS = {
  col_doh_cloudflare: {
    id: 'col_doh_cloudflare',
    name: 'Cloudflare DNS over HTTPS',
    baseUrl: 'https://cloudflare-dns.com/dns-query',
    acceptHeader: 'application/dns-json',
  },
  col_doh_google: {
    id: 'col_doh_google',
    name: 'Google Public DNS over HTTPS',
    baseUrl: 'https://dns.google/resolve',
    acceptHeader: 'application/json',
  },
} as const;

export type ResolverId = keyof typeof ALLOWED_DOH_RESOLVERS | 'auto';

export interface DomainValidationResult {
  valid: boolean;
  normalized?: string;
  error?: string;
}

/**
 * Normalizes and validates a target hostname for DNS queries.
 * Rejects IP addresses, malformed characters, excessive length, or empty input.
 */
export function normalizeAndValidateDomain(input: unknown): DomainValidationResult {
  if (typeof input !== 'string') {
    return { valid: false, error: 'Target must be a non-empty string' };
  }

  let domain = input.trim().toLowerCase();

  if (!domain) {
    return { valid: false, error: 'Target domain cannot be empty' };
  }

  // Handle trailing root dot (e.g., "example.org." -> "example.org")
  if (domain.endsWith('.')) {
    domain = domain.slice(0, -1);
  }

  if (!domain) {
    return { valid: false, error: 'Target domain cannot be just a root dot' };
  }

  // Reject IPv4 addresses
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(domain)) {
    return { 
      valid: false, 
      error: 'UNSUPPORTED_TARGET_TYPE: Target is an IP address. Passive DNS collector requires a domain or FQDN.' 
    };
  }

  // Reject IPv6 addresses
  if (domain.includes(':')) {
    return { 
      valid: false, 
      error: 'UNSUPPORTED_TARGET_TYPE: Target is an IPv6 address. Passive DNS collector requires a domain or FQDN.' 
    };
  }

  // Reject path / protocol / userinfo injection
  if (domain.includes('/') || domain.includes('\\') || domain.includes('?') || domain.includes('#') || domain.includes('@')) {
    return { valid: false, error: 'Target contains unsafe URL or path characters' };
  }

  // Total length check: RFC 1035 max 253 characters
  if (domain.length > 253) {
    return { valid: false, error: `Domain length (${domain.length}) exceeds maximum allowable 253 characters` };
  }

  // Label validation
  const labels = domain.split('.');
  if (labels.length < 2) {
    return { valid: false, error: 'Target must have at least one top-level domain component (e.g. example.com)' };
  }

  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (label.length === 0) {
      return { valid: false, error: 'Domain contains empty label (consecutive dots)' };
    }
    if (label.length > 63) {
      return { valid: false, error: `Domain label "${label.slice(0, 10)}..." exceeds maximum 63 characters` };
    }
    if (!labelRegex.test(label)) {
      return { valid: false, error: `Domain label "${label}" contains invalid characters (must be alphanumeric or hyphen, not starting/ending with hyphen)` };
    }
  }

  // Check top-level domain (TLD must not be all-numeric)
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) {
    return { valid: false, error: 'Top-level domain cannot be purely numeric' };
  }

  return { valid: true, normalized: domain };
}

/**
 * Strict boundary-aware domain scope authorization check.
 * Prevents suffix-confusion attacks (e.g. example.org.attacker.com).
 */
export function isDomainAuthorizedInScope(
  normalizedDomain: string, 
  scope: InvestigationScope
): { authorized: boolean; reason?: string } {
  if (!scope || !Array.isArray(scope.domains) || scope.domains.length === 0) {
    return {
      authorized: false,
      reason: 'Investigation case has no authorized domain scope defined.'
    };
  }

  for (const raw of scope.domains) {
    let pattern = raw.trim().toLowerCase();
    if (pattern.endsWith('.')) pattern = pattern.slice(0, -1);

    if (pattern.startsWith('*.')) {
      const baseDomain = pattern.slice(2);
      // Wildcard permits exact base domain or exact subdomains of base domain
      if (normalizedDomain === baseDomain || normalizedDomain.endsWith('.' + baseDomain)) {
        return { authorized: true };
      }
    } else {
      // Direct domain pattern permits exact domain or subdomains under that domain
      if (normalizedDomain === pattern || normalizedDomain.endsWith('.' + pattern)) {
        return { authorized: true };
      }
    }
  }

  return {
    authorized: false,
    reason: `OUT_OF_SCOPE: Target domain "${normalizedDomain}" is not authorized by case scope domains (${scope.domains.join(', ')}). Query rejected before outbound connection.`
  };
}
