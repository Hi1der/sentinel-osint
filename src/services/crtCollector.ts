/**
 * SENTINEL OSINT — Passive Certificate Transparency (CT) Collector
 * Queries public CT logs via crt.sh API to enumerate SANs, subdomains, and certificate telemetry
 */

import crypto from 'crypto';
import { normalizeAndValidateDomain } from '../utils/dnsValidation.ts';

export interface RawCrtCertificate {
  issuer_ca_id?: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  id: number;
  entry_timestamp?: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

export interface NormalizedCertificate {
  cert_id: string;
  serial_number: string;
  issuer: string;
  common_name: string;
  sans: string[];
  not_before: string;
  not_after: string;
  is_expired: boolean;
  discovered_subdomains: string[];
}

export interface CrtCollectorResult {
  target_domain: string;
  source_url: string;
  retrieval_timestamp: string;
  is_successful: boolean;
  status_code?: number;
  total_certs_found: number;
  certificates: NormalizedCertificate[];
  all_discovered_subdomains: string[];
  raw_payload?: RawCrtCertificate[];
  content_hash: string;
  error?: string;
}

export function computeCanonicalSha256(data: any): string {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Extracts and canonicalizes subdomains matching base target domain from SAN / name_value string
 */
export function extractSubdomainsFromSans(baseDomain: string, nameValue: string): string[] {
  if (!nameValue) return [];
  const lines = nameValue.split(/[\r\n\s]+/).map(s => s.trim().toLowerCase());
  const discovered = new Set<string>();
  const base = baseDomain.toLowerCase();

  for (let item of lines) {
    if (!item) continue;
    // Strip wildcards
    if (item.startsWith('*.')) {
      item = item.slice(2);
    }
    // Check if within domain hierarchy
    if (item.endsWith('.' + base) && item !== base) {
      discovered.add(item);
    }
  }

  return Array.from(discovered);
}

/**
 * Executes a passive Certificate Transparency lookup against crt.sh
 */
export async function executeCrtLookup(targetDomain: string, timeoutMs = 12000): Promise<CrtCollectorResult> {
  const norm = normalizeAndValidateDomain(targetDomain);
  const now = new Date().toISOString();

  if (!norm.valid || !norm.normalized) {
    return {
      target_domain: targetDomain,
      source_url: '',
      retrieval_timestamp: now,
      is_successful: false,
      total_certs_found: 0,
      certificates: [],
      all_discovered_subdomains: [],
      error: norm.error || 'Invalid domain for Certificate Transparency collection',
      content_hash: computeCanonicalSha256({ error: norm.error, target: targetDomain })
    };
  }

  const domain = norm.normalized;
  const sourceUrl = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(sourceUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'SENTINEL-OSINT-CTCollector/1.0 (Passive Research)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const statusCode = res.status;

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      return {
        target_domain: domain,
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: statusCode,
        total_certs_found: 0,
        certificates: [],
        all_discovered_subdomains: [],
        error: `HTTP_${statusCode}: crt.sh returned ${res.statusText || 'error'} (${errText.slice(0, 100)})`,
        content_hash: computeCanonicalSha256({ status: statusCode, domain })
      };
    }

    const rawPayload: RawCrtCertificate[] = await res.json();
    if (!Array.isArray(rawPayload)) {
      return {
        target_domain: domain,
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: true,
        status_code: statusCode,
        total_certs_found: 0,
        certificates: [],
        all_discovered_subdomains: [],
        raw_payload: [],
        content_hash: computeCanonicalSha256([])
      };
    }

    // Deduplicate certificates and process SANs
    const seenCerts = new Map<string, NormalizedCertificate>();
    const allSubs = new Set<string>();
    const currentDate = new Date();

    for (const cert of rawPayload) {
      const serial = (cert.serial_number || String(cert.id || '')).toLowerCase();
      if (!serial) continue;

      const sansRaw = (cert.name_value || '').split(/[\r\n\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
      const uniqueSans = Array.from(new Set(sansRaw));
      const subs = extractSubdomainsFromSans(domain, cert.name_value || '');
      subs.forEach(s => allSubs.add(s));

      const notAfter = cert.not_after ? new Date(cert.not_after) : null;
      const isExpired = notAfter ? notAfter < currentDate : false;

      // Extract simplified issuer name
      let issuerSimple = cert.issuer_name || 'Unknown Issuer';
      const oMatch = issuerSimple.match(/O=([^,]+)/);
      const cnMatch = issuerSimple.match(/CN=([^,]+)/);
      if (cnMatch) {
        issuerSimple = cnMatch[1].trim();
      } else if (oMatch) {
        issuerSimple = oMatch[1].trim();
      }

      if (!seenCerts.has(serial)) {
        seenCerts.set(serial, {
          cert_id: String(cert.id || serial),
          serial_number: serial,
          issuer: issuerSimple,
          common_name: cert.common_name || domain,
          sans: uniqueSans,
          not_before: cert.not_before,
          not_after: cert.not_after,
          is_expired: isExpired,
          discovered_subdomains: subs
        });
      }
    }

    const certificates = Array.from(seenCerts.values()).slice(0, 50); // limit to top 50 recent

    return {
      target_domain: domain,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: true,
      status_code: statusCode,
      total_certs_found: seenCerts.size,
      certificates,
      all_discovered_subdomains: Array.from(allSubs),
      raw_payload: rawPayload.slice(0, 50),
      content_hash: computeCanonicalSha256(rawPayload)
    };
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');
    return {
      target_domain: domain,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: false,
      total_certs_found: 0,
      certificates: [],
      all_discovered_subdomains: [],
      error: isTimeout ? `REQUEST_TIMEOUT: crt.sh did not respond within ${timeoutMs}ms` : `NETWORK_ERROR: ${err.message}`,
      content_hash: computeCanonicalSha256({ error: err.message, target: domain })
    };
  }
}
