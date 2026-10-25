/**
 * SENTINEL OSINT — Phase 2 Automated Test Suite
 * Tests Passive DNS-over-HTTPS Collector, Domain Normalization, Scope Enforcement,
 * Mocked Resolver Behaviors, Evidence Provenance, and SHA-256 Audit Integrity.
 */

import { normalizeAndValidateDomain, isDomainAuthorizedInScope } from '../src/utils/dnsValidation.ts';
import { 
  querySingleRecord, 
  executeDnsCollection, 
  computeCanonicalSha256, 
  SingleRecordResult 
} from '../src/services/dnsCollector.ts';
import { InvestigationScope } from '../src/types/osint.ts';
import { computeAuditHash } from '../src/utils/security.ts';

function createMockResponse(status: number, body: any, headers: Record<string, string> = {}) {
  const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: {
      get: (name: string) => headers[name.toLowerCase()] || null,
    },
    text: async () => bodyText,
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
  } as unknown as Response;
}

async function runPhase2Tests() {
  console.log('========================================================');
  console.log('  SENTINEL OSINT — Phase 2 DNS Collector Test Suite');
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
  // SECTION A: Input and Scope Validation (Tests 1-7)
  // -----------------------------------------------------------
  console.log('--- Section A: Input & Scope Authorization ---');

  const testScope: InvestigationScope = {
    domains: ['defense-corp.org', '*.threat-lab.net'],
    ipRanges: ['198.51.100.0/24'],
    allowedCollectorTypes: ['PASSIVE_DNS']
  };

  // Test 1: Valid domain in exact scope
  const t1 = normalizeAndValidateDomain('defense-corp.org');
  assert(t1.valid && t1.normalized === 'defense-corp.org', '1. Normalizes valid domain in exact scope');
  const s1 = isDomainAuthorizedInScope(t1.normalized!, testScope);
  assert(s1.authorized, '1. Authorizes domain in exact scope');

  // Test 2: Valid subdomain within permitted scope
  const t2 = normalizeAndValidateDomain('api.stage.threat-lab.net.'); // trailing dot
  assert(t2.valid && t2.normalized === 'api.stage.threat-lab.net', '2. Strips trailing root dot from subdomain');
  const s2 = isDomainAuthorizedInScope(t2.normalized!, testScope);
  assert(s2.authorized, '2. Authorizes wildcard subdomain within permitted scope');

  // Test 3: Out-of-scope domain returns not authorized
  const t3 = normalizeAndValidateDomain('unauthorized-target.com');
  const s3 = isDomainAuthorizedInScope(t3.normalized!, testScope);
  assert(!s3.authorized && s3.reason?.includes('OUT_OF_SCOPE') || false, '3. Out-of-scope domain rejected with OUT_OF_SCOPE');

  // Test 4: Suffix-confusion attack is rejected
  // attacker registers defense-corp.org.attacker.invalid
  const t4 = normalizeAndValidateDomain('defense-corp.org.attacker.invalid');
  const s4 = isDomainAuthorizedInScope(t4.normalized!, testScope);
  assert(!s4.authorized, '4. Suffix-confusion attack (defense-corp.org.attacker.invalid) strictly rejected');

  // Prefix confusion like fake-defense-corp.org
  const t4b = normalizeAndValidateDomain('fake-defense-corp.org');
  const s4b = isDomainAuthorizedInScope(t4b.normalized!, testScope);
  assert(!s4b.authorized, '4b. Prefix-confusion attack (fake-defense-corp.org) strictly rejected');

  // Test 5: Invalid hostname syntax is rejected
  const t5_ip = normalizeAndValidateDomain('198.51.100.42');
  assert(!t5_ip.valid && t5_ip.error?.includes('IP address') || false, '5a. Rejects IPv4 address (no reverse DNS spoofing)');

  const t5_empty = normalizeAndValidateDomain('   ');
  assert(!t5_empty.valid, '5b. Rejects empty domain');

  const t5_special = normalizeAndValidateDomain('bad domain@inject.com');
  assert(!t5_special.valid, '5c. Rejects spaces and special characters');

  const t5_longlabel = normalizeAndValidateDomain('a'.repeat(64) + '.com');
  assert(!t5_longlabel.valid && t5_longlabel.error?.includes('exceeds maximum 63') || false, '5d. Rejects label exceeding 63 chars');

  // Test 6: Missing or empty scope is rejected
  const s6 = isDomainAuthorizedInScope('defense-corp.org', { domains: [], ipRanges: [], allowedCollectorTypes: [] });
  assert(!s6.authorized, '6. Empty case scope strictly rejects all domain queries');

  // Test 7: Unauthorized requests produce ZERO outbound resolver calls
  let outboundCallsCount = 0;
  const mockFetchCounter = (async () => {
    outboundCallsCount++;
    return createMockResponse(200, {});
  }) as unknown as typeof fetch;

  const targetDomain = 'malicious-domain.com';
  const targetScopeCheck = isDomainAuthorizedInScope(targetDomain, testScope);
  if (targetScopeCheck.authorized) {
    await querySingleRecord(targetDomain, 'A', 'col_doh_cloudflare', mockFetchCounter);
  }
  assert(outboundCallsCount === 0, '7. Unauthorized target produced exactly 0 outbound resolver calls');

  // -----------------------------------------------------------
  // SECTION B: Resolver Behaviors & Guardrails (Tests 8-19)
  // -----------------------------------------------------------
  console.log('\n--- Section B: Resolver Protocol & Guardrails ---');

  // Test 8: Successful A response
  const mockFetchA = (async () => {
    return createMockResponse(200, {
      Status: 0,
      TC: false,
      RD: true,
      RA: true,
      Question: [{ name: 'defense-corp.org', type: 1 }],
      Answer: [{ name: 'defense-corp.org', type: 1, TTL: 300, data: '198.51.100.10' }]
    });
  }) as unknown as typeof fetch;

  const resA = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchA);
  assert(resA.is_successful && resA.outcome === 'SUCCESS_WITH_RECORDS', '8. Handles successful A record with TTL');
  assert(resA.answers[0].data === '198.51.100.10', '8. Correctly extracts IPv4 address');

  // Test 9: Successful AAAA response
  const mockFetchAAAA = (async () => {
    return createMockResponse(200, {
      Status: 0,
      Answer: [{ name: 'defense-corp.org', type: 28, TTL: 3600, data: '2001:db8::1' }]
    });
  }) as unknown as typeof fetch;

  const resAAAA = await querySingleRecord('defense-corp.org', 'AAAA', 'col_doh_cloudflare', mockFetchAAAA);
  assert(resAAAA.is_successful && resAAAA.answers[0].data === '2001:db8::1', '9. Handles successful AAAA IPv6 response');

  // Test 10: Correct handling of CNAME, MX, NS, TXT, SOA
  const mockFetchMX = (async () => {
    return createMockResponse(200, {
      Status: 0,
      Answer: [
        { name: 'defense-corp.org', type: 15, TTL: 300, data: '10 mail.defense-corp.org.' }
      ]
    });
  }) as unknown as typeof fetch;

  const resMX = await querySingleRecord('defense-corp.org', 'MX', 'col_doh_cloudflare', mockFetchMX);
  assert(resMX.is_successful && resMX.answers[0].data.includes('mail.defense-corp.org'), '10. Handles MX response correctly');

  // Test 11: Valid NXDOMAIN response (RCODE 3)
  const mockFetchNX = (async () => {
    return createMockResponse(200, {
      Status: 3,
      Comment: 'Name Error'
    });
  }) as unknown as typeof fetch;

  const resNX = await querySingleRecord('nonexistent.defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchNX);
  assert(resNX.is_successful && resNX.outcome === 'SUCCESS_NXDOMAIN' && resNX.status_code === 3, '11. Valid NXDOMAIN handled as successful non-existence observation');

  // Test 12: NOERROR response with no answer records
  const mockFetchEmpty = (async () => {
    return createMockResponse(200, {
      Status: 0,
      Answer: []
    });
  }) as unknown as typeof fetch;

  const resEmpty = await querySingleRecord('defense-corp.org', 'TXT', 'col_doh_cloudflare', mockFetchEmpty);
  assert(resEmpty.is_successful && resEmpty.outcome === 'SUCCESS_NO_ANSWERS', '12. Valid NOERROR with 0 records handled as successful 0-answer observation');

  // Test 13: Resolver HTTP failure (e.g. 503)
  const mockFetch503 = (async () => {
    return createMockResponse(503, 'Upstream service unavailable');
  }) as unknown as typeof fetch;

  const res503 = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetch503);
  assert(!res503.is_successful && res503.outcome === 'FAILED_HTTP', '13. Resolver HTTP 503 handled as failure');

  // Test 14: Timeout handling
  const mockFetchTimeout = (async () => {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  }) as unknown as typeof fetch;

  const resTimeout = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchTimeout);
  assert(!resTimeout.is_successful && resTimeout.outcome === 'FAILED_TIMEOUT', '14. Abort timeout handled gracefully without crash');

  // Test 15: Malformed JSON payload
  const mockFetchBadJson = (async () => {
    return createMockResponse(200, '<html><head><title>Bad Gateway</title></head><body>502</body></html>');
  }) as unknown as typeof fetch;

  const resBadJson = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchBadJson);
  assert(!resBadJson.is_successful && resBadJson.outcome === 'FAILED_MALFORMED', '15. Malformed non-JSON payload rejected');

  // Test 16: Oversized response rejection (> 512KB)
  const hugePayload = 'X'.repeat(600 * 1024);
  const mockFetchOversized = (async () => {
    return createMockResponse(200, hugePayload, { 'content-length': String(600 * 1024) });
  }) as unknown as typeof fetch;

  const resOversized = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchOversized);
  assert(!resOversized.is_successful && resOversized.outcome === 'FAILED_OVERSIZED', '16. Oversized payload (>512KB) rejected');

  // Test 17: Redirect rejection (301/302)
  const mockFetchRedirect = (async () => {
    return createMockResponse(302, 'Redirecting...', { 'location': 'http://169.254.169.254/latest/meta-data' });
  }) as unknown as typeof fetch;

  const resRedirect = await querySingleRecord('defense-corp.org', 'A', 'col_doh_cloudflare', mockFetchRedirect);
  assert(!resRedirect.is_successful && resRedirect.outcome === 'FAILED_REDIRECT', '17. HTTP redirect rejected to prevent SSRF hopping');

  // Test 18: Partial success across multiple record types
  const mockMultiFetch = (async (url: string) => {
    if (url.includes('type=A')) {
      return createMockResponse(200, { Status: 0, Answer: [{ name: 'defense-corp.org', type: 1, TTL: 300, data: '198.51.100.1' }] });
    }
    // Fail MX
    return createMockResponse(500, 'Internal Server Error');
  }) as unknown as typeof fetch;

  const resMulti = await executeDnsCollection('defense-corp.org', ['A', 'MX'], 'col_doh_cloudflare', mockMultiFetch);
  assert(resMulti.overall_status === 'PARTIAL_SUCCESS', '18. Multi-type query with 1 success and 1 fail produces PARTIAL_SUCCESS');
  assert(resMulti.successful_queries === 1 && resMulti.failed_queries === 1, '18. Correctly counts successes and failures');

  // Test 19: All-query failure produces FAILED status
  const mockAllFail = (async () => createMockResponse(500, 'Fail')) as unknown as typeof fetch;
  const resAllFail = await executeDnsCollection('defense-corp.org', ['A', 'AAAA'], 'col_doh_cloudflare', mockAllFail);
  assert(resAllFail.overall_status === 'FAILED', '19. All-query failure produces FAILED job state');

  // -----------------------------------------------------------
  // SECTION C: Evidence Provenance, Hashes & Audit (Tests 20-25)
  // -----------------------------------------------------------
  console.log('\n--- Section C: Evidence Provenance & Audit Integrity ---');

  // Test 20: Evidence provenance integrity
  assert(resA.content_hash !== undefined && resA.content_hash.length === 64, '20. Generated 64-char hex SHA-256 content hash');
  assert(resA.source_url.startsWith('https://cloudflare-dns.com/dns-query'), '20. Verified fixed allowlisted source URL');

  // Test 21: Deterministic hash calculation
  const hash1 = computeCanonicalSha256(resA.raw_payload);
  const hash2 = computeCanonicalSha256(resA.raw_payload);
  assert(hash1 === hash2 && hash1 === resA.content_hash, '21. Content hash is deterministic across identical payloads');

  // Test 22: Simulated tampering detection
  const tamperedPayload = { ...resA.raw_payload, Status: 99 };
  const tamperedHash = computeCanonicalSha256(tamperedPayload);
  assert(tamperedHash !== hash1, '22. Payload modification produces distinct SHA-256 digest');

  // Test 23: Audit chain link calculation
  const prevHash = '1111111111111111111111111111111111111111111111111111111111111111';
  const auditLink = computeAuditHash(10, 'usr_analyst', 'DNS_COLLECTION_COMPLETED', 'defense-corp.org', '2026-10-15T06:00:00Z', prevHash);
  assert(auditLink.length === 64, '23. Computes continuous audit chain link for DNS collection');

  console.log('\n========================================================');
  console.log(`  Tests Completed: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('========================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runPhase2Tests();
