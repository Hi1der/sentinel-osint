import crypto from 'crypto';
import { InvestigationScope } from '../types/osint.ts';

// -------------------------------------------------------------
// SCOPE VALIDATION & SSRF GUARDS
// -------------------------------------------------------------
export function isPrivateOrLoopbackIP(ip: string): boolean {
  // SSRF guard: Check loopback, private RFC1918, link-local, AWS/GCP metadata
  if (ip === 'localhost' || ip === '127.0.0.1' || ip.startsWith('127.') || ip === '::1') return true;
  if (ip === '169.254.169.254') return true; // Cloud metadata
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  // 172.16.0.0 to 172.31.255.255
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}

export function validateTargetScope(target: string, scope: InvestigationScope): { in_scope: boolean; reason?: string } {
  const cleaned = target.trim().toLowerCase();

  // 1. SSRF Guard
  if (isPrivateOrLoopbackIP(cleaned)) {
    return {
      in_scope: false,
      reason: `SECURITY POLICY VIOLATION: Target "${target}" is a private/loopback/cloud-metadata address. Outbound requests are blocked.`
    };
  }

  // 2. Check Domain Scope
  const domainTargets = scope.domains.map(d => d.trim().toLowerCase());
  for (const d of domainTargets) {
    if (d.startsWith('*.')) {
      const baseDomain = d.slice(2);
      if (cleaned === baseDomain || cleaned.endsWith('.' + baseDomain)) {
        return { in_scope: true };
      }
    } else if (cleaned === d) {
      return { in_scope: true };
    }
  }

  // 3. Check IP Scope
  const ipTargets = scope.ipRanges.map(r => r.trim());
  for (const range of ipTargets) {
    if (range.includes('/')) {
      // Basic CIDR prefix check (e.g. 198.51.100.0/24)
      const [prefix, bits] = range.split('/');
      if (bits === '24') {
        const prefix3 = prefix.split('.').slice(0, 3).join('.');
        const target3 = cleaned.split('.').slice(0, 3).join('.');
        if (prefix3 === target3) return { in_scope: true };
      }
    } else if (cleaned === range) {
      return { in_scope: true };
    }
  }

  return {
    in_scope: false,
    reason: `SCOPE VIOLATION: Target "${target}" is not covered by the authorized domains (${scope.domains.join(', ')}) or IP ranges (${scope.ipRanges.join(', ')}). Outbound collection is rejected.`
  };
}

// SHA-256 Canonical Audit Hash Function
export function computeAuditHash(
  logId: number, 
  userId: string, 
  action: string, 
  target: string, 
  timestamp: string, 
  previousHash: string
): string {
  const canonicalString = `${logId}|${userId}|${action}|${target}|${timestamp}|${previousHash}`;
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}
