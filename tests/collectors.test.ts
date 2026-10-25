/**
 * SENTINEL OSINT — Multi-Source Intelligence Collectors & AI Analyst Test Suite
 * Tests for RDAP, crt.sh Certificate Transparency, BGP Routing, Person OSINT, and AI Synthesis
 */

import { validateRdapTarget, parseRdapPayload } from '../src/services/rdapCollector.ts';
import { extractSubdomainsFromSans } from '../src/services/crtCollector.ts';
import { validateBgpTarget } from '../src/services/bgpCollector.ts';
import { validateGithubUsername, validateEmailSyntax } from '../src/services/personCollector.ts';
import { generateHeuristicAssessment } from '../src/services/aiAnalyst.ts';
import { correlateEvidenceForCase } from '../src/services/correlationEngine.ts';
import { EvidenceItem, InvestigationCase, Entity, Relationship } from '../src/types/osint.ts';

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    console.log(`  [PASS] ${msg}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${msg}`);
    failed++;
  }
}

console.log('========================================================');
console.log('  SENTINEL OSINT — Collectors & Intelligence Test Suite');
console.log('========================================================');

// --- Section A: RDAP Validation & Parsing ---
console.log('\n--- Section A: RDAP Validation & Parsing ---');

const rdapDomCheck = validateRdapTarget('defense-corp.org');
assert(rdapDomCheck.valid === true && rdapDomCheck.type === 'DOMAIN', '1. Validates standard domain target for RDAP');

const rdapIpCheck = validateRdapTarget('198.51.100.42');
assert(rdapIpCheck.valid === true && rdapIpCheck.type === 'IP', '2. Validates routable public IP target for RDAP');

const rdapSsrfLoopback = validateRdapTarget('127.0.0.1');
assert(rdapSsrfLoopback.valid === false && Boolean(rdapSsrfLoopback.error?.includes('SECURITY_VIOLATION')), '3. Strictly blocks 127.0.0.1 SSRF in RDAP');

const rdapSsrfMetadata = validateRdapTarget('169.254.169.254');
assert(rdapSsrfMetadata.valid === false && Boolean(rdapSsrfMetadata.error?.includes('SECURITY_VIOLATION')), '4. Strictly blocks cloud metadata SSRF in RDAP');

const mockRdapPayload = {
  handle: 'DOM-DEFENSE-1',
  ldhName: 'defense-corp.org',
  status: ['clientTransferProhibited', 'active'],
  nameservers: [{ ldhName: 'ns1.defense-corp.org' }, { ldhName: 'ns2.defense-corp.org' }],
  events: [
    { eventAction: 'registration', eventDate: '2020-01-15T00:00:00Z' },
    { eventAction: 'expiration', eventDate: '2030-01-15T00:00:00Z' }
  ],
  entities: [
    {
      roles: ['registrar'],
      vcardArray: ['vcard', [['fn', {}, 'text', 'MarkMonitor Inc.']]]
    }
  ]
};

const parsedRdap = parseRdapPayload('defense-corp.org', 'DOMAIN', mockRdapPayload);
assert(parsedRdap.registrar === 'MarkMonitor Inc.', '5. Extracts accredited registrar from RDAP vcardArray');
assert(parsedRdap.registration_date === '2020-01-15T00:00:00Z', '6. Extracts authoritative registration date');
assert(parsedRdap.nameservers.length === 2 && parsedRdap.nameservers[0] === 'ns1.defense-corp.org', '7. Normalizes RDAP registered nameservers');

// --- Section B: Certificate Transparency & SAN Extraction ---
console.log('\n--- Section B: Certificate Transparency (crt.sh) ---');

const sansRaw = 'defense-corp.org\n*.defense-corp.org\napi.defense-corp.org\nvpn.defense-corp.org\nattacker.com';
const subs = extractSubdomainsFromSans('defense-corp.org', sansRaw);

assert(subs.includes('api.defense-corp.org'), '8. Extracts in-scope subdomain "api.defense-corp.org" from SANs');
assert(subs.includes('vpn.defense-corp.org'), '9. Extracts in-scope subdomain "vpn.defense-corp.org" from SANs');
assert(!subs.includes('defense-corp.org'), '10. Excludes apex domain itself from discovered subdomains list');
assert(!subs.includes('attacker.com'), '11. Strictly ignores out-of-scope external domains in SANs');

// --- Section C: BGP Routing & ASN Validation ---
console.log('\n--- Section C: BGP Routing & ASN Validation ---');

const bgpValid = validateBgpTarget('198.51.100.1');
assert(bgpValid.valid === true && bgpValid.normalized === '198.51.100.1', '12. Validates public IP for BGP lookups');

const bgpPrivate = validateBgpTarget('10.200.1.5');
assert(bgpPrivate.valid === false && Boolean(bgpPrivate.error?.includes('SECURITY_VIOLATION')), '13. Strictly blocks private RFC 1918 Class A in BGP');

const bgpLoopback = validateBgpTarget('127.0.0.1');
assert(bgpLoopback.valid === false && Boolean(bgpLoopback.error?.includes('SECURITY_VIOLATION')), '14. Strictly blocks loopback address in BGP');

// --- Section D: Person OSINT & Email Validation ---
console.log('\n--- Section D: Person OSINT & Email Validation ---');

assert(validateGithubUsername('torvalds') === true, '15. Accepts valid standard GitHub username');
assert(validateGithubUsername('sec-analyst-01') === true, '16. Accepts valid hyphenated GitHub username');
assert(validateGithubUsername('-invalid') === false, '17. Rejects invalid leading-hyphen GitHub username');
assert(validateGithubUsername('a'.repeat(45)) === false, '18. Rejects overlong (>39 chars) GitHub username');

assert(validateEmailSyntax('analyst@defense-corp.org') === true, '19. Validates standard RFC 5322 email syntax');
assert(validateEmailSyntax('invalid-email-no-at') === false, '20. Rejects invalid email without @');
assert(validateEmailSyntax('@no-user.com') === false, '21. Rejects invalid email without local part');

// --- Section E: Multi-Source Correlation Engine ---
console.log('\n--- Section E: Multi-Source Correlation Engine ---');

const testCase: InvestigationCase = {
  id: 'case_multi_test',
  case_number: 'CASE-TEST-MULTI',
  title: 'Multi-Source Correlation Test',
  description: 'Integration test',
  objective: 'Verify correlation across DoH, RDAP, CT, and BGP',
  status: 'ACTIVE',
  priority: 'HIGH',
  tags: ['TEST'],
  scope: {
    domains: ['defense-corp.org'],
    ipRanges: ['198.51.100.0/24'],
    allowedCollectorTypes: ['ALL']
  },
  created_by: 'tester',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString()
};

const evidenceItems: EvidenceItem[] = [
  // 1. RDAP Evidence
  {
    id: 'ev-test-rdap',
    case_id: 'case_multi_test',
    collector_id: 'col_rdap_domain',
    source_provider: 'ICANN / RIR RDAP Registration',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T10:00:00Z',
    normalized_value: 'RDAP: MarkMonitor Inc.',
    raw_payload: {
      registrar: 'MarkMonitor Inc.',
      nameservers: ['ns1.defense-corp.org', 'ns2.defense-corp.org']
    },
    content_hash: 'hash-rdap-1',
    confidence_score: 0.98,
    verification_status: 'VERIFIED'
  },
  // 2. CT Evidence
  {
    id: 'ev-test-ct',
    case_id: 'case_multi_test',
    collector_id: 'col_crt_sh',
    source_provider: 'Sectigo crt.sh',
    target_identifier: 'defense-corp.org',
    retrieval_timestamp: '2026-10-15T10:05:00Z',
    normalized_value: 'CT: 1 cert found',
    raw_payload: [
      {
        id: 998877,
        serial_number: '04a1b2c3d4e5',
        issuer: "Let's Encrypt Authority R3",
        common_name: 'defense-corp.org',
        name_value: 'defense-corp.org\nportal.defense-corp.org',
        not_before: '2026-01-01',
        not_after: '2026-04-01'
      }
    ],
    content_hash: 'hash-ct-1',
    confidence_score: 0.99,
    verification_status: 'VERIFIED'
  },
  // 3. BGP Routing Evidence on resolved IP
  {
    id: 'ev-test-bgp',
    case_id: 'case_multi_test',
    collector_id: 'col_ripe_stat',
    source_provider: 'RIPE NCC Stat',
    target_identifier: '198.51.100.42',
    retrieval_timestamp: '2026-10-15T10:10:00Z',
    normalized_value: 'BGP: AS13335 (CLOUDFLARENET)',
    raw_payload: {
      data: {
        asns: [13335],
        prefix: '198.51.100.0/24',
        holder: 'CLOUDFLARENET'
      }
    },
    content_hash: 'hash-bgp-1',
    confidence_score: 0.99,
    verification_status: 'VERIFIED'
  }
];

const correlation = correlateEvidenceForCase(
  'case_multi_test',
  evidenceItems,
  [],
  [],
  ['defense-corp.org']
);

const registrarEntity = correlation.entities.find(e => e.entity_type === 'ORGANIZATION' && e.canonical_value === 'MarkMonitor Inc.');
assert(Boolean(registrarEntity), '22. Correlates RDAP Registrar as an ORGANIZATION entity');

const certEntity = correlation.entities.find(e => e.entity_type === 'SSL_CERTIFICATE' && e.canonical_value === '04a1b2c3d4e5');
assert(Boolean(certEntity), '23. Correlates crt.sh CT log as an SSL_CERTIFICATE entity');

const subEntity = correlation.entities.find(e => e.entity_type === 'SUBDOMAIN' && e.canonical_value === 'portal.defense-corp.org');
assert(Boolean(subEntity), '24. Correlates SAN from CT log into a SUBDOMAIN entity');

const asnEntity = correlation.entities.find(e => e.entity_type === 'ASN' && e.canonical_value === 'AS13335');
assert(Boolean(asnEntity), '25. Correlates BGP route announcement into an ASN entity (AS13335)');

const bgpRel = correlation.relationships.find(r => r.relationship_type === 'BELONGS_TO_ASN');
assert(Boolean(bgpRel), '26. Creates BELONGS_TO_ASN relationship between IP and ASN entity');
assert(bgpRel?.evidence_ids.includes('ev-test-bgp') === true, '27. Traces BELONGS_TO_ASN relationship directly to BGP evidence');

const certRel = correlation.relationships.find(r => r.relationship_type === 'PRESENTS_CERTIFICATE');
assert(Boolean(certRel), '28. Creates PRESENTS_CERTIFICATE relationship between domain and certificate');

// --- Section F: AI Intelligence Analyst Engine ---
console.log('\n--- Section F: AI Intelligence Analyst Engine ---');

const assessment = generateHeuristicAssessment(testCase, evidenceItems, correlation.entities, correlation.relationships);
assert(typeof assessment.threat_score === 'number' && assessment.threat_score >= 0 && assessment.threat_score <= 100, '29. Computes normalized threat score between 0 and 100');
assert(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(assessment.threat_level), '30. Categorizes threat level appropriately');
assert(assessment.hypotheses.length > 0, '31. Generates structured hypotheses with evidentiary basis');
assert(assessment.recommended_actions.length > 0, '32. Recommends passive reconnaissance actions');

console.log('========================================================');
console.log(`  Tests Completed: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log('========================================================');

if (failed > 0) {
  process.exit(1);
}
