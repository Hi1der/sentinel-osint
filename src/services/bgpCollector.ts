/**
 * SENTINEL OSINT — Passive BGP & Autonomous System (ASN) Collector
 * Queries public RIPE NCC Stat API for BGP prefix announcements, ASN ownership, and routing paths
 */

import crypto from 'crypto';
import { isPrivateOrLoopbackIP } from '../utils/security.ts';

export interface BgpRoutingData {
  ip: string;
  prefix: string;
  asns: number[];
  primary_asn?: number;
  holder?: string;
  announced: boolean;
}

export interface BgpCollectorResult {
  target_ip: string;
  source_url: string;
  retrieval_timestamp: string;
  is_successful: boolean;
  status_code?: number;
  routing_data?: BgpRoutingData;
  raw_payload?: any;
  content_hash: string;
  error?: string;
}

export function computeCanonicalSha256(data: any): string {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Validates IP address target for BGP queries with SSRF protection
 */
export function validateBgpTarget(ip: string): { valid: boolean; normalized?: string; error?: string } {
  const trimmed = ip.trim().toLowerCase();
  if (!trimmed) {
    return { valid: false, error: 'Target IP cannot be empty' };
  }

  if (isPrivateOrLoopbackIP(trimmed)) {
    return { valid: false, error: 'SECURITY_VIOLATION: Private, loopback, or cloud metadata IP addresses cannot be queried via BGP routing' };
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(trimmed)) {
    return { valid: true, normalized: trimmed };
  }

  if (trimmed.includes(':')) {
    return { valid: true, normalized: trimmed };
  }

  return { valid: false, error: 'Target is not a valid IPv4 or IPv6 address' };
}

/**
 * Executes a passive BGP network info and ASN lookup via RIPE Stat
 */
export async function executeBgpLookup(targetIp: string, timeoutMs = 8000): Promise<BgpCollectorResult> {
  const check = validateBgpTarget(targetIp);
  const now = new Date().toISOString();

  if (!check.valid || !check.normalized) {
    return {
      target_ip: targetIp,
      source_url: '',
      retrieval_timestamp: now,
      is_successful: false,
      error: check.error || 'Invalid IP for BGP routing collection',
      content_hash: computeCanonicalSha256({ error: check.error, target: targetIp })
    };
  }

  const ip = check.normalized;
  const sourceUrl = `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(sourceUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'SENTINEL-OSINT-BGPCollector/1.0 (Passive Research)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const statusCode = res.status;

    if (!res.ok) {
      return {
        target_ip: ip,
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: statusCode,
        error: `HTTP_${statusCode}: RIPE Stat returned ${res.statusText}`,
        content_hash: computeCanonicalSha256({ status: statusCode, ip })
      };
    }

    const rawPayload = await res.json();
    const data = rawPayload.data || {};
    const rawAsns: any[] = Array.isArray(data.asns) ? data.asns : [];
    const asns = rawAsns.map(a => parseInt(String(a), 10)).filter(n => !isNaN(n) && n > 0);
    const prefix = data.prefix || `${ip}/32`;
    const primaryAsn = asns[0];

    // Optionally lookup ASN holder name if primary ASN found
    let holder: string | undefined;
    if (primaryAsn) {
      try {
        const asnUrl = `https://stat.ripe.net/data/as-overview/data.json?resource=AS${primaryAsn}`;
        const asnRes = await fetch(asnUrl, {
          headers: { 'Accept': 'application/json', 'User-Agent': 'SENTINEL-OSINT-BGPCollector/1.0' },
          signal: AbortSignal.timeout(4000)
        });
        if (asnRes.ok) {
          const asnData = await asnRes.json();
          holder = asnData?.data?.holder;
        }
      } catch {
        // non-blocking
      }
    }

    const routingData: BgpRoutingData = {
      ip,
      prefix,
      asns,
      primary_asn: primaryAsn,
      holder: holder || (primaryAsn ? `AS${primaryAsn}` : 'Unrouted / Unknown'),
      announced: asns.length > 0
    };

    return {
      target_ip: ip,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: true,
      status_code: statusCode,
      routing_data: routingData,
      raw_payload: rawPayload,
      content_hash: computeCanonicalSha256(rawPayload)
    };
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');
    return {
      target_ip: ip,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: false,
      error: isTimeout ? `REQUEST_TIMEOUT: RIPE Stat did not respond within ${timeoutMs}ms` : `NETWORK_ERROR: ${err.message}`,
      content_hash: computeCanonicalSha256({ error: err.message, target: ip })
    };
  }
}
