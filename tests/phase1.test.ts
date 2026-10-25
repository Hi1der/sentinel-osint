/**
 * SENTINEL OSINT — Phase 1 Automated Test Suite
 * Tests core case operations, server-side scope enforcement, SSRF protections, and cryptographic SHA-256 hash chaining.
 */

import { isPrivateOrLoopbackIP, validateTargetScope, computeAuditHash } from '../src/utils/security.ts';
import { InvestigationScope } from '../src/types/osint.ts';

function runTests() {
  console.log('========================================================');
  console.log('  SENTINEL OSINT — Phase 1 Test Execution Suite');
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

  // TEST SUITE 1: SSRF & Private Network Guards
  console.log('--- Suite 1: SSRF & Network Protections ---');
  assert(isPrivateOrLoopbackIP('127.0.0.1'), 'Blocks IPv4 loopback (127.0.0.1)');
  assert(isPrivateOrLoopbackIP('localhost'), 'Blocks localhost hostname');
  assert(isPrivateOrLoopbackIP('169.254.169.254'), 'Blocks AWS/GCP cloud metadata IP (169.254.169.254)');
  assert(isPrivateOrLoopbackIP('10.0.0.1'), 'Blocks RFC1918 Class A (10.0.0.1)');
  assert(isPrivateOrLoopbackIP('192.168.1.1'), 'Blocks RFC1918 Class C (192.168.1.1)');
  assert(isPrivateOrLoopbackIP('172.16.0.5'), 'Blocks RFC1918 Class B (172.16.0.5)');
  assert(!isPrivateOrLoopbackIP('198.51.100.42'), 'Allows public routable documentation IP (198.51.100.42)');
  assert(!isPrivateOrLoopbackIP('cloudflare.com'), 'Allows public domain name');

  // TEST SUITE 2: Server-Side Investigation Scope Enforcement
  console.log('\n--- Suite 2: Server-Side Scope Enforcement ---');
  const testScope: InvestigationScope = {
    domains: ['target-defense.org', '*.target-defense.org'],
    ipRanges: ['198.51.100.0/24'],
    allowedCollectorTypes: ['PASSIVE_DNS', 'CERT_TRANSPARENCY']
  };

  const exactDomain = validateTargetScope('target-defense.org', testScope);
  assert(exactDomain.in_scope, 'Allows exact authorized domain match');

  const wildcardSubdomain = validateTargetScope('api.target-defense.org', testScope);
  assert(wildcardSubdomain.in_scope, 'Allows wildcard authorized subdomain match');

  const nestedSubdomain = validateTargetScope('c2.stage.target-defense.org', testScope);
  assert(nestedSubdomain.in_scope, 'Allows deeply nested authorized subdomain match');

  const outOfScopeDomain = validateTargetScope('malicious-actor.com', testScope);
  assert(!outOfScopeDomain.in_scope, 'Rejects unauthorized domain target');
  assert(outOfScopeDomain.reason?.includes('SCOPE VIOLATION') || false, 'Provides explicit SCOPE VIOLATION reason');

  const inScopeIp = validateTargetScope('198.51.100.42', testScope);
  assert(inScopeIp.in_scope, 'Allows IP address within authorized CIDR prefix');

  const outOfScopeIp = validateTargetScope('203.0.113.15', testScope);
  assert(!outOfScopeIp.in_scope, 'Rejects IP address outside authorized CIDR prefix');

  const ssrfTarget = validateTargetScope('169.254.169.254', testScope);
  assert(!ssrfTarget.in_scope, 'Rejects SSRF cloud metadata even if requested');
  assert(ssrfTarget.reason?.includes('SECURITY POLICY VIOLATION') || false, 'Provides security policy violation notice on SSRF');

  // TEST SUITE 3: Cryptographic SHA-256 Hash Chain Integrity
  console.log('\n--- Suite 3: SHA-256 Tamper-Evident Audit Chain ---');
  const genesisPrev = '0000000000000000000000000000000000000000000000000000000000000000';
  const t0 = '2026-10-15T00:00:00.000Z';
  const hash1 = computeAuditHash(1, 'usr_admin', 'BOOTSTRAP', 'SYSTEM', t0, genesisPrev);
  assert(hash1.length === 64, 'Computes valid 64-char hex SHA-256 hash');

  const t1 = '2026-10-15T00:01:00.000Z';
  const hash2 = computeAuditHash(2, 'usr_admin', 'CASE_CREATED', 'CASE-001', t1, hash1);
  assert(hash2 !== hash1, 'Generates unique next link in chain');

  // Verify unbroken chain
  const recomputedHash2 = computeAuditHash(2, 'usr_admin', 'CASE_CREATED', 'CASE-001', t1, hash1);
  assert(recomputedHash2 === hash2, 'Verifies hash chain link deterministically');

  // Simulate tampering
  const tamperedActionHash = computeAuditHash(2, 'usr_admin', 'CASE_ALTERED', 'CASE-001', t1, hash1);
  assert(tamperedActionHash !== hash2, 'Detects simulated modification of action field');

  console.log('\n========================================================');
  console.log(`  Tests Completed: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('========================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
