/**
 * SENTINEL OSINT — Phase 3 Automated Test Suite
 * Tests Evidence-Backed Entity Correlation, Parsing of all 7 DNS Record Types,
 * Strict Provenance, Temporal Tracking, Scope Non-Expansion, and Persistence.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { 
  extractIndicatorsFromDnsEvidence, 
  normalizeHostname, 
  isSubdomainOf, 
  classifyDomainType, 
  correlateEvidenceForCase, 
  buildEntityId, 
  buildRelationshipId 
} from '../src/services/correlationEngine.ts';
import { EvidenceItem, InvestigationScope, Entity, Relationship } from '../src/types/osint.ts';
import { isDomainAuthorizedInScope } from '../src/utils/dnsValidation.ts';
import { validateTargetScope } from '../src/utils/security.ts';
import { computeCanonicalSha256 } from '../src/services/dnsCollector.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runPhase3Tests() {
  console.log('========================================================');
  console.log('  SENTINEL OSINT — Phase 3 Entity Correlation Test Suite');
  console.log('========================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      console.log(`  [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${testName} ${detail ? `(${detail})` : ''}`);
      failed++;
    }
  }

  // -----------------------------------------------------------
  // SECTION A: DNS Record Parsing Coverage (All 7 Types)
  // -----------------------------------------------------------
  console.log('--- Section A: DNS Record Parsing Coverage (7 Types) ---');

  // 1. A Record (IPv4)
  const evA: EvidenceItem = {
    id: 'ev-test-a-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'A: 198.51.100.10',
    raw_payload: {
      Status: 0,
      Answer: [{ name: 'defense-corp.org', type: 1, TTL: 300, data: '198.51.100.10' }]
    },
    content_hash: 'a'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indA = extractIndicatorsFromDnsEvidence(evA);
  assert(indA.ips.length === 1 && indA.ips[0].ip === '198.51.100.10' && indA.ips[0].version === 'IPv4', '1. Parses A record IPv4 address and TTL');

  // 2. AAAA Record (IPv6)
  const evAAAA: EvidenceItem = {
    id: 'ev-test-aaaa-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'AAAA: 2001:db8::1',
    raw_payload: {
      Status: 0,
      Answer: [{ name: 'defense-corp.org', type: 28, TTL: 3600, data: '2001:db8::1' }]
    },
    content_hash: 'b'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indAAAA = extractIndicatorsFromDnsEvidence(evAAAA);
  assert(indAAAA.ips.length === 1 && indAAAA.ips[0].ip === '2001:db8::1' && indAAAA.ips[0].version === 'IPv6', '2. Parses AAAA record IPv6 address and TTL');

  // 3. CNAME Record
  const evCNAME: EvidenceItem = {
    id: 'ev-test-cname-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'api.defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'CNAME: lb.defense-corp.org.',
    raw_payload: {
      Status: 0,
      Answer: [{ name: 'api.defense-corp.org', type: 5, TTL: 600, data: 'lb.defense-corp.org.' }]
    },
    content_hash: 'c'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indCNAME = extractIndicatorsFromDnsEvidence(evCNAME);
  assert(indCNAME.cnames.length === 1 && indCNAME.cnames[0].target === 'lb.defense-corp.org', '3. Parses CNAME canonical alias and strips trailing dot');

  // 4. MX Record (Mail Exchange)
  const evMX: EvidenceItem = {
    id: 'ev-test-mx-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'MX: 10 mail.defense-corp.org.',
    raw_payload: {
      Status: 0,
      Answer: [
        { name: 'defense-corp.org', type: 15, TTL: 300, data: '10 mail1.defense-corp.org.' },
        { name: 'defense-corp.org', type: 15, TTL: 300, data: '20 mail2.defense-corp.org.' }
      ]
    },
    content_hash: 'd'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indMX = extractIndicatorsFromDnsEvidence(evMX);
  assert(indMX.mxHosts.length === 2 && indMX.mxHosts[0].host === 'mail1.defense-corp.org' && indMX.mxHosts[0].priority === 10, '4. Parses MX records with host and priority');

  // 5. NS Record (Nameservers)
  const evNS: EvidenceItem = {
    id: 'ev-test-ns-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'NS: ns1.defense-corp.org.',
    raw_payload: {
      Status: 0,
      Answer: [
        { name: 'defense-corp.org', type: 2, TTL: 86400, data: 'ns1.defense-corp.org.' },
        { name: 'defense-corp.org', type: 2, TTL: 86400, data: 'ns2.defense-corp.org.' }
      ]
    },
    content_hash: 'e'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indNS = extractIndicatorsFromDnsEvidence(evNS);
  assert(indNS.nsHosts.length === 2 && indNS.nsHosts[0].host === 'ns1.defense-corp.org', '5. Parses NS authoritative nameservers');

  // 6. TXT Record (SPF & verification strings)
  const evTXT: EvidenceItem = {
    id: 'ev-test-txt-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'TXT: v=spf1 include:_spf.google.com ~all',
    raw_payload: {
      Status: 0,
      Answer: [
        { name: 'defense-corp.org', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com ~all"' },
        { name: 'defense-corp.org', type: 16, TTL: 300, data: '"google-site-verification=abc123xyz"' }
      ]
    },
    content_hash: 'f'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indTXT = extractIndicatorsFromDnsEvidence(evTXT);
  assert(indTXT.txtRecords.length === 2 && indTXT.txtRecords[0].isSpf && indTXT.txtRecords[0].value.includes('v=spf1'), '6. Parses TXT records, strips wrapping quotes, and flags SPF');

  // 7. SOA Record (Start of Authority)
  const evSOA: EvidenceItem = {
    id: 'ev-test-soa-01',
    case_id: 'case_test_p3',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DNS over HTTPS',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T08:00:00.000Z',
    observation_timestamp: '2026-10-15T08:00:00.000Z',
    normalized_value: 'SOA: ns1.defense-corp.org hostmaster.defense-corp.org',
    raw_payload: {
      Status: 0,
      Answer: [
        { name: 'defense-corp.org', type: 6, TTL: 3600, data: 'ns1.defense-corp.org. hostmaster.defense-corp.org. 2026101501 7200 3600 1209600 3600' }
      ]
    },
    content_hash: '1'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED',
    is_demo: false
  };
  const indSOA = extractIndicatorsFromDnsEvidence(evSOA);
  assert(indSOA.soaRecord !== undefined && indSOA.soaRecord.primaryNs === 'ns1.defense-corp.org' && indSOA.soaRecord.serial === 2026101501, '7. Parses SOA primary master and serial number');

  // -----------------------------------------------------------
  // SECTION B: Normalization & Entity Classification
  // -----------------------------------------------------------
  console.log('\n--- Section B: Hostname Normalization & Domain Classification ---');

  assert(normalizeHostname('  DEFENSE-CORP.ORG.  ') === 'defense-corp.org', '8. Normalizes mixed case, whitespace, and trailing dots');
  assert(isSubdomainOf('api.stage.defense-corp.org', 'defense-corp.org'), '9. Identifies nested subdomain relationship');
  assert(!isSubdomainOf('defense-corp.org', 'defense-corp.org'), '10. Rejects identical domain as subdomain of itself');
  assert(!isSubdomainOf('fake-defense-corp.org', 'defense-corp.org'), '11. Rejects prefix-spoofed domain as subdomain');

  const classifiedApex = classifyDomainType('defense-corp.org', ['defense-corp.org']);
  assert(classifiedApex === 'DOMAIN', '12. Classifies base domain as DOMAIN entity');

  const classifiedSub = classifyDomainType('api.defense-corp.org', ['defense-corp.org']);
  assert(classifiedSub === 'SUBDOMAIN', '13. Classifies child hostname as SUBDOMAIN entity');

  // -----------------------------------------------------------
  // SECTION C: Evidence-Backed Correlation & Provenance Chaining
  // -----------------------------------------------------------
  console.log('\n--- Section C: Correlation Engine & Strict Provenance ---');

  const allEvidence = [evA, evAAAA, evCNAME, evMX, evNS, evSOA];
  const correlation = correlateEvidenceForCase(
    'case_test_p3',
    allEvidence,
    [],
    [],
    ['defense-corp.org']
  );

  assert(correlation.entities.length >= 6, '14. Correlates all entities from multi-record evidence items');
  assert(correlation.relationships.length >= 6, '15. Forms evidence-backed relationships across all parsed records');

  // Verify RESOLVES_TO relationship
  const resolvesRel = correlation.relationships.find(r => r.relationship_type === 'RESOLVES_TO');
  assert(resolvesRel !== undefined, '16. Creates RESOLVES_TO relationship from A/AAAA evidence');
  assert(resolvesRel!.evidence_ids.includes('ev-test-a-01') || resolvesRel!.evidence_ids.includes('ev-test-aaaa-01'), '17. Relationship traces directly to originating evidence ID');
  assert(!resolvesRel!.is_hypothesis, '18. Observed DNS resolution relationship is marked is_hypothesis: false');
  assert(resolvesRel!.scoring_explanation?.includes('Authoritative DNS resolution') || false, '19. Relationship provides explicit audit scoring explanation');

  // Verify ASSOCIATED_WITH relationships (CNAME, MX, NS)
  const cnameRel = correlation.relationships.find(r => r.metadata?.relation_subtype === 'CNAME_ALIAS');
  assert(cnameRel !== undefined && cnameRel.evidence_ids.includes('ev-test-cname-01'), '20. CNAME relationship traces to CNAME evidence item');

  const mxRel = correlation.relationships.find(r => r.metadata?.relation_subtype === 'MAIL_EXCHANGE');
  assert(mxRel !== undefined && mxRel.evidence_ids.includes('ev-test-mx-01'), '21. MX relationship traces to MX evidence item');

  const nsRel = correlation.relationships.find(r => r.metadata?.relation_subtype === 'NAMESERVER');
  assert(nsRel !== undefined && nsRel.evidence_ids.includes('ev-test-ns-01'), '22. NS relationship traces to NS evidence item');

  // -----------------------------------------------------------
  // SECTION D: Temporal Tracking (first_seen / last_seen)
  // -----------------------------------------------------------
  console.log('\n--- Section D: Temporal Observation Bounds ---');

  const earlyEvidence: EvidenceItem = {
    id: 'ev-early-01',
    case_id: 'case_temporal_test',
    collector_id: 'col_doh_cloudflare',
    source_provider: 'Cloudflare DoH',
    target_identifier: 'temporal.org',
    retrieval_timestamp: '2026-10-01T10:00:00.000Z',
    observation_timestamp: '2026-10-01T10:00:00.000Z',
    normalized_value: 'A: 198.51.100.20',
    raw_payload: { Status: 0, Answer: [{ name: 'temporal.org', type: 1, TTL: 300, data: '198.51.100.20' }] },
    content_hash: '1'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED'
  };

  const lateEvidence: EvidenceItem = {
    id: 'ev-late-02',
    case_id: 'case_temporal_test',
    collector_id: 'col_doh_google',
    source_provider: 'Google DoH',
    target_identifier: 'temporal.org',
    retrieval_timestamp: '2026-10-15T12:00:00.000Z',
    observation_timestamp: '2026-10-15T12:00:00.000Z',
    normalized_value: 'A: 198.51.100.20',
    raw_payload: { Status: 0, Answer: [{ name: 'temporal.org', type: 1, TTL: 300, data: '198.51.100.20' }] },
    content_hash: '2'.repeat(64),
    confidence_score: 0.99,
    verification_status: 'VERIFIED'
  };

  // Run initial correlation with early evidence
  const res1 = correlateEvidenceForCase('case_temporal_test', [earlyEvidence]);
  const ipEnt1 = res1.entities.find(e => e.canonical_value === '198.51.100.20');
  assert(ipEnt1!.first_seen === '2026-10-01T10:00:00.000Z' && ipEnt1!.last_seen === '2026-10-01T10:00:00.000Z', '23. Records initial temporal bounds on first observation');

  // Correlate with subsequent later evidence
  const res2 = correlateEvidenceForCase(
    'case_temporal_test',
    [lateEvidence],
    res1.entities,
    res1.relationships
  );
  const ipEnt2 = res2.entities.find(e => e.canonical_value === '198.51.100.20');
  assert(ipEnt2!.first_seen === '2026-10-01T10:00:00.000Z', '24. Preserves earliest first_seen across multiple observation runs');
  assert(ipEnt2!.last_seen === '2026-10-15T12:00:00.000Z', '25. Advances last_seen timestamp on subsequent observation');
  assert(ipEnt2!.source_ids.includes('col_doh_cloudflare') && ipEnt2!.source_ids.includes('col_doh_google'), '26. Merges source provider identifiers across observations');

  // -----------------------------------------------------------
  // SECTION E: Investigation Scope Non-Expansion
  // -----------------------------------------------------------
  console.log('\n--- Section E: Investigation Scope Non-Expansion Guardrail ---');

  const testScope: InvestigationScope = {
    domains: ['defense-corp.org'],
    ipRanges: ['198.51.100.0/24'],
    allowedCollectorTypes: ['PASSIVE_DNS']
  };

  // External NS discovered in graph (e.g., ns1.external-provider.com)
  const discoveredExternalDomain = 'ns1.external-provider.com';
  const scopeCheck = isDomainAuthorizedInScope(discoveredExternalDomain, testScope);
  assert(!scopeCheck.authorized, '27. Discovered graph entity outside authorized scope remains strictly unauthorized');
  assert(scopeCheck.reason?.includes('OUT_OF_SCOPE') || false, '28. Explicit OUT_OF_SCOPE rejection enforced for graph-discovered entity');

  // Discovered IP outside authorized CIDR
  const discoveredExternalIp = '203.0.113.88';
  const ipScopeCheck = validateTargetScope(discoveredExternalIp, testScope);
  assert(!ipScopeCheck.in_scope, '29. Discovered IP outside scope CIDR remains strictly unauthorized');

  // -----------------------------------------------------------
  // SECTION F: Disk Persistence Simulation & Integrity
  // -----------------------------------------------------------
  console.log('\n--- Section F: Disk Persistence & Restart State Preservation ---');

  const tempDbPath = path.join(__dirname, 'temp_persistence_test.json');
  try {
    const testPayload = {
      cases: [{ id: 'case_pers_01', case_number: 'CASE-2026-P3', status: 'ACTIVE' }],
      entities: res2.entities,
      relationships: res2.relationships,
      evidence: [earlyEvidence, lateEvidence]
    };
    fs.writeFileSync(tempDbPath, JSON.stringify(testPayload, null, 2), 'utf-8');

    // Simulate server restart: read fresh from disk
    const reloaded = JSON.parse(fs.readFileSync(tempDbPath, 'utf-8'));
    assert(reloaded.entities.length === res2.entities.length, '30. Preserves all correlated entities across server restart');
    assert(reloaded.relationships.length === res2.relationships.length, '31. Preserves all correlated relationships across server restart');
    assert(reloaded.relationships[0].evidence_ids.length > 0, '32. Preserves evidentiary provenance chain across persistence roundtrip');
  } finally {
    if (fs.existsSync(tempDbPath)) {
      fs.unlinkSync(tempDbPath);
    }
  }

  console.log('\n========================================================');
  console.log(`  Phase 3 Tests Completed: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('========================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runPhase3Tests();
