/**
 * SENTINEL OSINT — Evidence-Backed Entity Correlation & Graph Engine
 * Transforms raw and normalized evidence items into a deterministic,
 * provenance-backed entity relationship graph.
 *
 * Rules:
 * - Every relationship MUST trace directly to stored evidence IDs or be flagged as a hypothesis.
 * - Entities and relationships maintain temporal first_seen / last_seen timestamps.
 * - No scope expansion: discovered entities do NOT modify case authorization scopes.
 * - Strict normalization: lowercase, trimmed, no trailing dots, canonical IP representations.
 */

import { 
  Entity, 
  Relationship, 
  EvidenceItem, 
  EntityType, 
  RelationshipType 
} from '../types/osint.ts';

export interface CorrelationResult {
  entities: Entity[];
  relationships: Relationship[];
  new_entities_count: number;
  new_relationships_count: number;
  updated_entities_count: number;
  updated_relationships_count: number;
}

/**
 * Normalizes a domain or hostname:
 * - lowercase
 * - trimmed
 * - removes trailing dots
 */
export function normalizeHostname(host: string): string {
  if (!host) return '';
  let cleaned = host.trim().toLowerCase();
  while (cleaned.endsWith('.')) {
    cleaned = cleaned.slice(0, -1);
  }
  return cleaned;
}

/**
 * Determines whether childDomain is a subdomain of parentDomain.
 */
export function isSubdomainOf(childDomain: string, parentDomain: string): boolean {
  const child = normalizeHostname(childDomain);
  const parent = normalizeHostname(parentDomain);
  if (!child || !parent || child === parent) return false;
  return child.endsWith('.' + parent);
}

/**
 * Classifies whether a domain string should be categorized as DOMAIN or SUBDOMAIN
 * relative to known apex/root domains in scope or within the active case.
 */
export function classifyDomainType(domain: string, knownBaseDomains: string[] = []): EntityType {
  const norm = normalizeHostname(domain);
  for (const base of knownBaseDomains) {
    if (isSubdomainOf(norm, base)) {
      return 'SUBDOMAIN';
    }
  }
  const parts = norm.split('.');
  // Rough heuristic: if more than 2 labels, usually a subdomain (e.g. api.defense-corp.org)
  // unless 2-part ccTLD like example.co.uk
  if (parts.length > 2) {
    const isCcTld = parts.length === 3 && ['co.uk', 'com.au', 'co.nz', 'co.jp'].includes(`${parts[1]}.${parts[2]}`);
    return isCcTld ? 'DOMAIN' : 'SUBDOMAIN';
  }
  return 'DOMAIN';
}

/**
 * Parses DNS payload answers and extracts structured indicators.
 */
export interface ExtractedDnsIndicators {
  ips: { ip: string; version: 'IPv4' | 'IPv6'; ttl?: number }[];
  cnames: { target: string; ttl?: number }[];
  mxHosts: { host: string; priority: number; ttl?: number }[];
  nsHosts: { host: string; ttl?: number }[];
  txtRecords: { value: string; isSpf: boolean; ttl?: number }[];
  soaRecord?: { primaryNs: string; adminEmail: string; serial: number; ttl?: number };
}

export function extractIndicatorsFromDnsEvidence(evidence: EvidenceItem): ExtractedDnsIndicators {
  const result: ExtractedDnsIndicators = {
    ips: [],
    cnames: [],
    mxHosts: [],
    nsHosts: [],
    txtRecords: []
  };

  const payload = evidence.raw_payload;
  if (!payload || !Array.isArray(payload.Answer)) {
    return result;
  }

  for (const ans of payload.Answer) {
    if (!ans || !ans.data) continue;
    const type = ans.type;
    const dataStr = String(ans.data).trim();

    // Type 1 = A, Type 28 = AAAA
    if (type === 1) {
      result.ips.push({ ip: dataStr, version: 'IPv4', ttl: ans.TTL });
    } else if (type === 28) {
      result.ips.push({ ip: dataStr.toLowerCase(), version: 'IPv6', ttl: ans.TTL });
    } else if (type === 5) {
      // CNAME
      result.cnames.push({ target: normalizeHostname(dataStr), ttl: ans.TTL });
    } else if (type === 15) {
      // MX: e.g. "10 mail.example.com."
      const parts = dataStr.split(/\s+/);
      const priority = parts.length > 1 ? parseInt(parts[0], 10) : 10;
      const host = parts.length > 1 ? normalizeHostname(parts[1]) : normalizeHostname(dataStr);
      result.mxHosts.push({ host, priority: isNaN(priority) ? 10 : priority, ttl: ans.TTL });
    } else if (type === 2) {
      // NS
      result.nsHosts.push({ host: normalizeHostname(dataStr), ttl: ans.TTL });
    } else if (type === 16) {
      // TXT
      const cleanedTxt = dataStr.replace(/^"(.*)"$/, '$1');
      result.txtRecords.push({
        value: cleanedTxt,
        isSpf: cleanedTxt.toLowerCase().startsWith('v=spf1'),
        ttl: ans.TTL
      });
    } else if (type === 6) {
      // SOA: e.g. "ns1.example.org. hostmaster.example.org. 2026101501 7200 3600 1209600 3600"
      const parts = dataStr.split(/\s+/);
      if (parts.length >= 3) {
        result.soaRecord = {
          primaryNs: normalizeHostname(parts[0]),
          adminEmail: normalizeHostname(parts[1]).replace(/\./, '@'), // SOA convention first dot is @
          serial: parseInt(parts[2], 10) || 0,
          ttl: ans.TTL
        };
      }
    }
  }

  return result;
}

/**
 * Deterministic 64-bit hash generator for stable entity and relationship IDs
 */
export function hashString(str: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const part1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const part2 = (h2 >>> 0).toString(16).padStart(8, '0');
  return `${part1}${part2}`;
}

/**
 * Deterministic ID generator for entities and relationships
 */
export function buildEntityId(caseId: string, type: EntityType, canonicalValue: string): string {
  const normVal = canonicalValue.trim().toLowerCase();
  return `ent_${type.toLowerCase()}_${hashString(`${caseId}:${type}:${normVal}`)}`;
}

export function buildRelationshipId(
  caseId: string, 
  sourceId: string, 
  targetId: string, 
  relType: RelationshipType,
  subtype?: string
): string {
  const key = `${caseId}:${sourceId}:${relType}:${subtype || ''}:${targetId}`;
  return `rel_${hashString(key)}`;
}

/**
 * Main correlation execution routine:
 * Takes incoming or stored evidence, correlates entities, resolves deduplications,
 * computes timestamps, and generates evidence-backed relationships.
 */
export function correlateEvidenceForCase(
  caseId: string,
  evidenceItems: EvidenceItem[],
  existingEntities: Entity[] = [],
  existingRelationships: Relationship[] = [],
  knownBaseDomains: string[] = []
): CorrelationResult {
  const entityMap = new Map<string, Entity>();
  const relationshipMap = new Map<string, Relationship>();

  let newEntitiesCount = 0;
  let newRelationshipsCount = 0;
  let updatedEntitiesCount = 0;
  let updatedRelationshipsCount = 0;

  // 1. Seed existing entities and relationships
  for (const ent of existingEntities) {
    if (ent.case_id === caseId) {
      entityMap.set(ent.id, { ...ent });
    }
  }

  for (const rel of existingRelationships) {
    if (rel.case_id === caseId) {
      relationshipMap.set(rel.id, { ...rel, evidence_ids: [...rel.evidence_ids] });
    }
  }

  // Helper to get or create entity
  function upsertEntity(
    type: EntityType,
    canonicalVal: string,
    observationTime: string,
    sourceId: string,
    confidence: number,
    metadata: Record<string, any> = {},
    isDemo: boolean = false
  ): Entity {
    const id = buildEntityId(caseId, type, canonicalVal);
    let ent = entityMap.get(id);

    if (!ent) {
      ent = {
        id,
        case_id: caseId,
        entity_type: type,
        canonical_value: canonicalVal,
        display_value: canonicalVal,
        first_seen: observationTime,
        last_seen: observationTime,
        source_ids: [sourceId],
        confidence_score: confidence,
        metadata: { ...metadata },
        is_demo: isDemo
      };
      entityMap.set(id, ent);
      newEntitiesCount++;
    } else {
      // Update temporal bounds
      if (new Date(observationTime) < new Date(ent.first_seen)) {
        ent.first_seen = observationTime;
      }
      if (new Date(observationTime) > new Date(ent.last_seen)) {
        ent.last_seen = observationTime;
      }
      if (!ent.source_ids.includes(sourceId)) {
        ent.source_ids.push(sourceId);
      }
      ent.metadata = { ...ent.metadata, ...metadata };
      // If any observation is real, clear demo flag
      if (!isDemo && ent.is_demo) {
        ent.is_demo = false;
      }
      updatedEntitiesCount++;
    }

    return ent;
  }

  // Helper to get or create relationship
  function upsertRelationship(
    sourceEntityId: string,
    targetEntityId: string,
    relType: RelationshipType,
    observationTime: string,
    evidenceId: string,
    confidence: number,
    explanation: string,
    isHypothesis: boolean = false,
    isDemo: boolean = false,
    metadata: Record<string, any> = {}
  ): Relationship {
    const id = buildRelationshipId(caseId, sourceEntityId, targetEntityId, relType, metadata?.relation_subtype);
    let rel = relationshipMap.get(id);

    if (!rel) {
      rel = {
        id,
        case_id: caseId,
        source_entity_id: sourceEntityId,
        target_entity_id: targetEntityId,
        relationship_type: relType,
        first_seen: observationTime,
        last_seen: observationTime,
        confidence_score: confidence,
        evidence_ids: [evidenceId],
        is_hypothesis: isHypothesis,
        scoring_explanation: explanation,
        metadata,
        is_demo: isDemo
      };
      relationshipMap.set(id, rel);
      newRelationshipsCount++;
    } else {
      if (new Date(observationTime) < new Date(rel.first_seen)) {
        rel.first_seen = observationTime;
      }
      if (new Date(observationTime) > new Date(rel.last_seen)) {
        rel.last_seen = observationTime;
      }
      if (!rel.evidence_ids.includes(evidenceId)) {
        rel.evidence_ids.push(evidenceId);
      }
      if (!isDemo && rel.is_demo) {
        rel.is_demo = false;
      }
      rel.metadata = { ...rel.metadata, ...metadata };
      updatedRelationshipsCount++;
    }

    return rel;
  }

  // 2. Iterate through evidence records for this case
  const caseEvidence = evidenceItems.filter(e => e.case_id === caseId);

  for (const ev of caseEvidence) {
    const obsTime = ev.observation_timestamp || ev.retrieval_timestamp || new Date().toISOString();
    const isDemo = Boolean(ev.is_demo);
    const sourceProvider = ev.source_provider || ev.collector_id;
    const targetDomain = normalizeHostname(ev.target_identifier);

    if (!targetDomain) continue;

    // A. Upsert Target Entity (Domain or IP)
    const isIpTarget = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetDomain) || targetDomain.includes(':');
    const domainType = isIpTarget ? 'IP_ADDRESS' : classifyDomainType(targetDomain, knownBaseDomains);
    const domainEntity = upsertEntity(
      domainType,
      targetDomain,
      obsTime,
      ev.collector_id,
      ev.confidence_score,
      { collector: ev.collector_id, provider: sourceProvider },
      isDemo
    );

    // If it is a subdomain, connect to known parent if in scope
    for (const base of knownBaseDomains) {
      if (isSubdomainOf(targetDomain, base)) {
        const parentEntity = upsertEntity(
          'DOMAIN',
          base,
          obsTime,
          ev.collector_id,
          0.95,
          { role: 'APEX_DOMAIN' },
          isDemo
        );
        upsertRelationship(
          parentEntity.id,
          domainEntity.id,
          'HAS_SUBDOMAIN',
          obsTime,
          ev.id,
          0.99,
          `Subdomain relationship observed for ${targetDomain} under parent domain ${base}. Evidence ID: ${ev.id}`,
          false,
          isDemo
        );
      }
    }

    // B. Parse indicators from DNS payload
    const indicators = extractIndicatorsFromDnsEvidence(ev);

    // B.1 IP Resolutions (A, AAAA) -> RESOLVES_TO
    for (const ipItem of indicators.ips) {
      const ipEntity = upsertEntity(
        'IP_ADDRESS',
        ipItem.ip,
        obsTime,
        ev.collector_id,
        ev.confidence_score,
        { version: ipItem.version, origin_domain: targetDomain, ttl: ipItem.ttl },
        isDemo
      );

      upsertRelationship(
        domainEntity.id,
        ipEntity.id,
        'RESOLVES_TO',
        obsTime,
        ev.id,
        ev.confidence_score,
        `Authoritative DNS resolution from ${targetDomain} to ${ipItem.ip} via ${sourceProvider}. Evidence ID: ${ev.id}`,
        false,
        isDemo,
        { ttl: ipItem.ttl, ip_version: ipItem.version }
      );
    }

    // B.2 CNAME Aliases -> ASSOCIATED_WITH (or ALIAS)
    for (const cnameItem of indicators.cnames) {
      const cnameEntity = upsertEntity(
        'DOMAIN',
        cnameItem.target,
        obsTime,
        ev.collector_id,
        ev.confidence_score,
        { role: 'CNAME_TARGET', cname_of: targetDomain, ttl: cnameItem.ttl },
        isDemo
      );

      upsertRelationship(
        domainEntity.id,
        cnameEntity.id,
        'ASSOCIATED_WITH',
        obsTime,
        ev.id,
        ev.confidence_score,
        `Canonical name alias: ${targetDomain} CNAME points to ${cnameItem.target}. Evidence ID: ${ev.id}`,
        false,
        isDemo,
        { relation_subtype: 'CNAME_ALIAS', ttl: cnameItem.ttl }
      );
    }

    // B.3 Mail Servers (MX) -> ASSOCIATED_WITH
    for (const mxItem of indicators.mxHosts) {
      const mxEntity = upsertEntity(
        'DOMAIN',
        mxItem.host,
        obsTime,
        ev.collector_id,
        ev.confidence_score,
        { role: 'MAIL_EXCHANGE', priority: mxItem.priority, mx_for: targetDomain, ttl: mxItem.ttl },
        isDemo
      );

      upsertRelationship(
        domainEntity.id,
        mxEntity.id,
        'ASSOCIATED_WITH',
        obsTime,
        ev.id,
        ev.confidence_score,
        `Designated Mail Exchange (MX) record for ${targetDomain} with priority ${mxItem.priority}. Evidence ID: ${ev.id}`,
        false,
        isDemo,
        { relation_subtype: 'MAIL_EXCHANGE', priority: mxItem.priority, ttl: mxItem.ttl }
      );
    }

    // B.4 Nameservers (NS) -> ASSOCIATED_WITH
    for (const nsItem of indicators.nsHosts) {
      const nsEntity = upsertEntity(
        'DOMAIN',
        nsItem.host,
        obsTime,
        ev.collector_id,
        ev.confidence_score,
        { role: 'NAMESERVER', ns_for: targetDomain, ttl: nsItem.ttl },
        isDemo
      );

      upsertRelationship(
        domainEntity.id,
        nsEntity.id,
        'ASSOCIATED_WITH',
        obsTime,
        ev.id,
        ev.confidence_score,
        `Authoritative Name Server (NS) for zone ${targetDomain}: ${nsItem.host}. Evidence ID: ${ev.id}`,
        false,
        isDemo,
        { relation_subtype: 'NAMESERVER', ttl: nsItem.ttl }
      );
    }

    // B.5 SOA Records -> ASSOCIATED_WITH
    if (indicators.soaRecord) {
      const soaNsEntity = upsertEntity(
        'DOMAIN',
        indicators.soaRecord.primaryNs,
        obsTime,
        ev.collector_id,
        ev.confidence_score,
        { role: 'PRIMARY_SOA_NAMESERVER', zone: targetDomain },
        isDemo
      );

      upsertRelationship(
        domainEntity.id,
        soaNsEntity.id,
        'ASSOCIATED_WITH',
        obsTime,
        ev.id,
        ev.confidence_score,
        `Primary Master Name Server specified in Start of Authority (SOA) for ${targetDomain}. Evidence ID: ${ev.id}`,
        false,
        isDemo,
        { relation_subtype: 'SOA_PRIMARY_NS', serial: indicators.soaRecord.serial }
      );
    }

    // C. BGP Routing & Autonomous System Intelligence
    if (ev.collector_id.includes('ripe') || ev.collector_id.includes('bgp')) {
      const payload = ev.raw_payload;
      const data = payload?.data || payload?.routing_data || payload;
      const rawAsns: any[] = Array.isArray(data?.asns) ? data.asns : (data?.primary_asn ? [data.primary_asn] : []);
      const asns = rawAsns.map(a => parseInt(String(a), 10)).filter(n => !isNaN(n) && n > 0);

      for (const asn of asns) {
        const asnStr = `AS${asn}`;
        const holder = data?.holder || (asn === 13335 ? 'CLOUDFLARENET' : undefined);
        const asnEntity = upsertEntity(
          'ASN',
          asnStr,
          obsTime,
          ev.collector_id,
          ev.confidence_score,
          { asn, holder, prefix: data?.prefix },
          isDemo
        );

        upsertRelationship(
          domainEntity.id,
          asnEntity.id,
          'BELONGS_TO_ASN',
          obsTime,
          ev.id,
          ev.confidence_score,
          `IP ${targetDomain} announced under ${asnStr}${holder ? ` (${holder})` : ''}. Evidence ID: ${ev.id}`,
          false,
          isDemo,
          { prefix: data?.prefix, relation_subtype: 'BGP_ROUTING' }
        );
      }
    }

    // D. Certificate Transparency (crt.sh) Intelligence
    if (ev.collector_id.includes('crt')) {
      const payload = ev.raw_payload;
      const certList: any[] = Array.isArray(payload) 
        ? payload 
        : (Array.isArray(payload?.certificates) ? payload.certificates : []);

      for (const cert of certList.slice(0, 30)) {
        const serial = (cert.serial_number || String(cert.id || '')).toLowerCase();
        if (!serial) continue;

        const certEntity = upsertEntity(
          'SSL_CERTIFICATE',
          serial,
          obsTime,
          ev.collector_id,
          ev.confidence_score,
          {
            serial_number: serial,
            issuer: cert.issuer || cert.issuer_name,
            common_name: cert.common_name,
            not_before: cert.not_before,
            not_after: cert.not_after,
            is_expired: cert.is_expired
          },
          isDemo
        );

        upsertRelationship(
          domainEntity.id,
          certEntity.id,
          'PRESENTS_CERTIFICATE',
          obsTime,
          ev.id,
          ev.confidence_score,
          `Host ${targetDomain} observed presenting TLS certificate ${serial}. Evidence ID: ${ev.id}`,
          false,
          isDemo,
          { relation_subtype: 'TLS_PRESENTATION' }
        );

        // Certificate Authority Organization
        const issuerName = cert.issuer || cert.issuer_name;
        if (issuerName && typeof issuerName === 'string') {
          const caEntity = upsertEntity(
            'ORGANIZATION',
            issuerName,
            obsTime,
            ev.collector_id,
            ev.confidence_score,
            { role: 'CERTIFICATE_AUTHORITY' },
            isDemo
          );

          upsertRelationship(
            caEntity.id,
            certEntity.id,
            'ISSUED_CERT',
            obsTime,
            ev.id,
            ev.confidence_score,
            `CA ${issuerName} issued certificate ${serial}. Evidence ID: ${ev.id}`,
            false,
            isDemo,
            { relation_subtype: 'CA_ISSUANCE' }
          );
        }

        // Subdomains discovered from Certificate SANs
        const rawSans = cert.name_value || (Array.isArray(cert.sans) ? cert.sans.join('\n') : '');
        if (rawSans && !isIpTarget) {
          const lines = String(rawSans).split(/[\r\n\s]+/).map(s => s.trim().toLowerCase());
          for (let s of lines) {
            if (s.startsWith('*.')) s = s.slice(2);
            if (s.endsWith('.' + targetDomain) && s !== targetDomain) {
              const subEnt = upsertEntity(
                'SUBDOMAIN',
                s,
                obsTime,
                ev.collector_id,
                ev.confidence_score,
                { role: 'SUBDOMAIN', discovered_via: 'CERTIFICATE_TRANSPARENCY' },
                isDemo
              );

              upsertRelationship(
                domainEntity.id,
                subEnt.id,
                'HAS_SUBDOMAIN',
                obsTime,
                ev.id,
                ev.confidence_score,
                `Subdomain ${s} enumerated in CT SAN extension for ${targetDomain}. Evidence ID: ${ev.id}`,
                false,
                isDemo,
                { relation_subtype: 'CT_SAN_DISCOVERY' }
              );
            }
          }
        }
      }
    }

    // E. RDAP Domain & IP Registration Intelligence
    if (ev.collector_id.includes('rdap')) {
      const payload = ev.raw_payload;
      const data = payload?.data || payload;
      const registrar = data?.registrar || (Array.isArray(data?.entities) ? data.entities.find((e: any) => e.roles?.includes('registrar'))?.name : undefined);

      if (registrar && typeof registrar === 'string') {
        const regEntity = upsertEntity(
          'ORGANIZATION',
          registrar,
          obsTime,
          ev.collector_id,
          ev.confidence_score,
          { role: 'REGISTRAR' },
          isDemo
        );

        upsertRelationship(
          domainEntity.id,
          regEntity.id,
          'ASSOCIATED_WITH',
          obsTime,
          ev.id,
          ev.confidence_score,
          `Entity ${targetDomain} registered with accredited registrar ${registrar}. Evidence ID: ${ev.id}`,
          false,
          isDemo,
          { relation_subtype: 'REGISTRAR' }
        );
      }

      // RDAP nameservers
      if (Array.isArray(data?.nameservers)) {
        for (const ns of data.nameservers) {
          const nsHost = normalizeHostname(typeof ns === 'string' ? ns : (ns.ldhName || ns.handle || ''));
          if (nsHost) {
            const nsEntity = upsertEntity(
              'DOMAIN',
              nsHost,
              obsTime,
              ev.collector_id,
              ev.confidence_score,
              { role: 'NAMESERVER', source: 'RDAP' },
              isDemo
            );

            upsertRelationship(
              domainEntity.id,
              nsEntity.id,
              'ASSOCIATED_WITH',
              obsTime,
              ev.id,
              ev.confidence_score,
              `RDAP registered nameserver ${nsHost} for ${targetDomain}. Evidence ID: ${ev.id}`,
              false,
              isDemo,
              { relation_subtype: 'NAMESERVER' }
            );
          }
        }
      }
    }

    // F. Developer & Person Reconnaissance Intelligence
    if (ev.collector_id.includes('github') || ev.collector_id.includes('person')) {
      const profile = ev.raw_payload?.developer_profile || ev.raw_payload;
      const username = profile?.username || profile?.login;

      if (username) {
        const personEntity = upsertEntity(
          'ORGANIZATION',
          username,
          obsTime,
          ev.collector_id,
          ev.confidence_score,
          {
            role: 'DEVELOPER_PROFILE',
            name: profile.name,
            company: profile.company,
            public_repos: profile.public_repos,
            profile_url: profile.profile_url || `https://github.com/${username}`
          },
          isDemo
        );

        upsertRelationship(
          domainEntity.id,
          personEntity.id,
          'ASSOCIATED_WITH',
          obsTime,
          ev.id,
          ev.confidence_score,
          `Developer ${username} associated with target investigation ${targetDomain}. Evidence ID: ${ev.id}`,
          false,
          isDemo,
          { relation_subtype: 'DEVELOPER_PROFILE' }
        );
      }
    }
  }

  return {
    entities: Array.from(entityMap.values()),
    relationships: Array.from(relationshipMap.values()),
    new_entities_count: newEntitiesCount,
    new_relationships_count: newRelationshipsCount,
    updated_entities_count: updatedEntitiesCount,
    updated_relationships_count: updatedRelationshipsCount
  };
}
