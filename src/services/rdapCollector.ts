/**
 * SENTINEL OSINT — Passive RDAP (Registration Data Access Protocol) Collector
 * RFC 7480, RFC 7481, RFC 7482, RFC 7483 compliant domain and IP registration intelligence
 */

import crypto from 'crypto';
import { isPrivateOrLoopbackIP } from '../utils/security.ts';
import { normalizeAndValidateDomain } from '../utils/dnsValidation.ts';

export interface RdapEntityInfo {
  handle?: string;
  roles?: string[];
  name?: string;
  kind?: string;
  email?: string;
  phone?: string;
}

export interface RdapEventInfo {
  action: string;
  date: string;
}

export interface NormalizedRdapData {
  target: string;
  type: 'DOMAIN' | 'IP';
  handle?: string;
  registrar?: string;
  registrant_name?: string;
  registrant_org?: string;
  registrant_country?: string;
  registration_date?: string;
  expiration_date?: string;
  last_updated_date?: string;
  status: string[];
  nameservers: string[];
  dnssec: boolean;
  network?: {
    cidr?: string;
    start_address?: string;
    end_address?: string;
    ip_version?: string;
    name?: string;
    country?: string;
  };
  entities: RdapEntityInfo[];
  raw_events: RdapEventInfo[];
}

export interface RdapQueryResult {
  target: string;
  type: 'DOMAIN' | 'IP';
  source_url: string;
  retrieval_timestamp: string;
  is_successful: boolean;
  status_code?: number;
  data?: NormalizedRdapData;
  raw_payload?: any;
  content_hash: string;
  error?: string;
}

export function computeCanonicalSha256(data: any): string {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

/**
 * Validates whether the target is an IP or domain and guards against SSRF
 */
export function validateRdapTarget(target: string): { valid: boolean; type: 'DOMAIN' | 'IP'; normalized?: string; error?: string } {
  const trimmed = target.trim().toLowerCase();
  if (!trimmed) {
    return { valid: false, type: 'DOMAIN', error: 'Target cannot be empty' };
  }

  // Check IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(trimmed)) {
    if (isPrivateOrLoopbackIP(trimmed)) {
      return { valid: false, type: 'IP', error: 'SECURITY_VIOLATION: Private or loopback IP rejected by SSRF guard' };
    }
    return { valid: true, type: 'IP', normalized: trimmed };
  }

  // Check IPv6
  if (trimmed.includes(':')) {
    if (isPrivateOrLoopbackIP(trimmed)) {
      return { valid: false, type: 'IP', error: 'SECURITY_VIOLATION: Loopback IPv6 rejected by SSRF guard' };
    }
    return { valid: true, type: 'IP', normalized: trimmed };
  }

  // Check domain
  const normDomain = normalizeAndValidateDomain(trimmed);
  if (!normDomain.valid || !normDomain.normalized) {
    return { valid: false, type: 'DOMAIN', error: normDomain.error || 'Invalid domain hostname syntax' };
  }

  return { valid: true, type: 'DOMAIN', normalized: normDomain.normalized };
}

/**
 * Executes a passive RDAP query against standard HTTPS RDAP services
 */
export async function executeRdapLookup(target: string, timeoutMs = 8000): Promise<RdapQueryResult> {
  const check = validateRdapTarget(target);
  const now = new Date().toISOString();

  if (!check.valid || !check.normalized) {
    return {
      target,
      type: check.type,
      source_url: '',
      retrieval_timestamp: now,
      is_successful: false,
      error: check.error || 'Invalid target for RDAP collection',
      content_hash: computeCanonicalSha256({ error: check.error, target })
    };
  }

  const normalizedTarget = check.normalized;
  const isIp = check.type === 'IP';
  
  // Authoritative RDAP endpoints avoiding third-party Cloudflare bot-challenge aggregators
  let sourceUrl = '';
  if (isIp) {
    sourceUrl = `https://rdap.arin.net/registry/ip/${encodeURIComponent(normalizedTarget)}`;
  } else {
    const parts = normalizedTarget.split('.');
    const tld = parts[parts.length - 1];
    if (tld === 'com') {
      sourceUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(normalizedTarget)}`;
    } else if (tld === 'net') {
      sourceUrl = `https://rdap.verisign.com/net/v1/domain/${encodeURIComponent(normalizedTarget)}`;
    } else if (tld === 'org') {
      sourceUrl = `https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(normalizedTarget)}`;
    } else {
      sourceUrl = `https://rdap.org/domain/${encodeURIComponent(normalizedTarget)}`;
    }
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(sourceUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'SENTINEL-OSINT-IntelligenceEngine/1.0 (Passive Research; Compliance RFC 7480)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const statusCode = res.status;

    if (!res.ok) {
      const errorText = await res.text().catch(() => '');
      return {
        target: normalizedTarget,
        type: check.type,
        source_url: sourceUrl,
        retrieval_timestamp: now,
        is_successful: false,
        status_code: statusCode,
        error: `HTTP_${statusCode}: RDAP registry returned ${res.statusText || 'error'} (${errorText.slice(0, 100)})`,
        content_hash: computeCanonicalSha256({ status: statusCode, errorText, target: normalizedTarget })
      };
    }

    const rawPayload = await res.json();
    const normalizedData = parseRdapPayload(normalizedTarget, check.type, rawPayload);

    return {
      target: normalizedTarget,
      type: check.type,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: true,
      status_code: statusCode,
      data: normalizedData,
      raw_payload: rawPayload,
      content_hash: computeCanonicalSha256(rawPayload)
    };
  } catch (err: any) {
    const isTimeout = err.name === 'AbortError' || err.message?.includes('aborted');
    return {
      target: normalizedTarget,
      type: check.type,
      source_url: sourceUrl,
      retrieval_timestamp: now,
      is_successful: false,
      error: isTimeout ? `REQUEST_TIMEOUT: RDAP server did not respond within ${timeoutMs}ms` : `NETWORK_ERROR: ${err.message}`,
      content_hash: computeCanonicalSha256({ error: err.message, target: normalizedTarget })
    };
  }
}

/**
 * Normalizes RDAP JSON payload into consistent, strongly-typed OSINT attributes
 */
export function parseRdapPayload(target: string, type: 'DOMAIN' | 'IP', raw: any): NormalizedRdapData {
  const result: NormalizedRdapData = {
    target,
    type,
    handle: raw.handle || undefined,
    status: Array.isArray(raw.status) ? raw.status : [],
    nameservers: [],
    dnssec: false,
    entities: [],
    raw_events: []
  };

  // Parse nameservers
  if (Array.isArray(raw.nameservers)) {
    result.nameservers = raw.nameservers
      .map((ns: any) => (ns.ldhName || ns.handle || '').toLowerCase().trim())
      .filter((ns: string) => ns.length > 0);
  }

  // Parse events (registration, expiration, last changed)
  if (Array.isArray(raw.events)) {
    for (const ev of raw.events) {
      if (ev.eventAction && ev.eventDate) {
        result.raw_events.push({
          action: ev.eventAction,
          date: ev.eventDate
        });
        if (ev.eventAction === 'registration') result.registration_date = ev.eventDate;
        if (ev.eventAction === 'expiration') result.expiration_date = ev.eventDate;
        if (ev.eventAction === 'last changed' || ev.eventAction === 'last update') result.last_updated_date = ev.eventDate;
      }
    }
  }

  // Parse secureDNS
  if (raw.secureDNS && typeof raw.secureDNS.delegationSigned === 'boolean') {
    result.dnssec = raw.secureDNS.delegationSigned;
  }

  // Parse entities (registrar, registrant, contacts)
  if (Array.isArray(raw.entities)) {
    for (const ent of raw.entities) {
      const roles = Array.isArray(ent.roles) ? ent.roles : [];
      const handle = ent.handle;
      let name: string | undefined;
      let email: string | undefined;
      let phone: string | undefined;

      // Extract vcardArray if present
      if (Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1])) {
        const vcardProps = ent.vcardArray[1];
        for (const prop of vcardProps) {
          if (Array.isArray(prop)) {
            const [propName, , , propVal] = prop;
            if (propName === 'fn' && typeof propVal === 'string') name = propVal;
            if (propName === 'email' && typeof propVal === 'string') email = propVal;
            if (propName === 'tel' && typeof propVal === 'string') phone = propVal;
          }
        }
      }

      result.entities.push({
        handle,
        roles,
        name,
        email,
        phone
      });

      if (roles.includes('registrar')) {
        result.registrar = name || handle || 'Unknown Registrar';
      }
      if (roles.includes('registrant')) {
        result.registrant_name = name;
      }
    }
  }

  // IP specific fields (CIDR / startAddress)
  if (type === 'IP') {
    result.network = {
      start_address: raw.startAddress,
      end_address: raw.endAddress,
      ip_version: raw.ipVersion,
      name: raw.name,
      country: raw.country
    };
    if (raw.cidr0_cidrs && Array.isArray(raw.cidr0_cidrs) && raw.cidr0_cidrs[0]) {
      const c = raw.cidr0_cidrs[0];
      result.network.cidr = `${c.v4prefix || c.v6prefix}/${c.length}`;
    }
  }

  return result;
}
