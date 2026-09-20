/**
 * False-positive / suppression management test (§VII.17, §52). Verifies scoped/auditable suppression,
 * validation (no global ignore-all), expiry, and the honesty guard: a suppression can NEVER hide a Critical.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';
import { applySuppressions, validateSuppression, type Suppression } from '@qa/core';
import type { Finding } from '@qa/core';

const rubyFixture = fileURLToPath(new URL('../fixtures/insecure-ruby', import.meta.url)); // High, no Critical
const vulnFixture = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url)); // Critical secret
const tmps: string[] = [];
afterAll(async () => {
  await Promise.all(tmps.map((t) => fs.rm(t, { recursive: true, force: true })));
});
async function scan(dir: string, id: string, suppressions?: Suppression[]) {
  const t = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-supp-'));
  tmps.push(t);
  return runScan({ projectDir: dir, scanId: id, evidenceDir: path.join(t, 'ev'), suppressions });
}

function fakeFinding(ruleId: string, severity: Finding['severity'], file: string): Finding {
  return {
    id: `${ruleId}-x`, ruleId, category: 'Security', title: 't', description: 'd', status: 'FAIL',
    evidenceClass: 'AUTOMATICALLY_DETECTED', severity, risk: severity, confidence: 'Likely', reproducibility: 'Always',
    cwe: [], cve: [], affectedComponent: file, location: { file }, detectionMethod: 'static', toolUsed: 'x',
    evidence: [], remediation: { summary: 's', effort: 'M', riskReduction: 'Medium' }, verificationMethod: 'v',
    standards: [], traceability: { requirements: [], tests: [] },
  } as Finding;
}

describe('suppression management (§VII.17)', () => {
  it('validateSuppression rejects a global ignore-all and unscoped/unattributed entries', () => {
    expect(validateSuppression({ id: 's1', reason: 'r', createdBy: 'me', createdAt: '2026-01-01' })).not.toEqual([]); // no scope
    expect(validateSuppression({ id: 's2', pathPattern: '**', reason: 'r', createdBy: 'me', createdAt: '2026-01-01' })).not.toEqual([]); // global glob
    expect(validateSuppression({ id: 's3', ruleId: 'RB-EVAL-001', reason: '', createdBy: 'me', createdAt: '2026-01-01' })).not.toEqual([]); // no reason
    expect(validateSuppression({ id: 's4', ruleId: 'RB-EVAL-001', reason: 'false positive', createdBy: 'me', createdAt: '2026-01-01' })).toEqual([]); // valid
  });

  it('applySuppressions suppresses a matched non-Critical, honors expiry, and NEVER suppresses a Critical', () => {
    const findings = [fakeFinding('X-MED', 'Medium', 'src/a.ts'), fakeFinding('X-CRIT', 'Critical', 'src/a.ts')];
    const now = '2026-06-01T00:00:00.000Z';

    const active1 = applySuppressions(findings, [{ id: 's', ruleId: 'X-MED', reason: 'fp', createdBy: 'me', createdAt: '2026-01-01' }], now);
    expect(active1.suppressed.map((s) => s.finding.ruleId)).toEqual(['X-MED']);
    expect(active1.active.map((f) => f.ruleId)).toEqual(['X-CRIT']);

    // Expired suppression does not apply.
    const expired = applySuppressions(findings, [{ id: 's', ruleId: 'X-MED', reason: 'fp', createdBy: 'me', createdAt: '2026-01-01', expiresAt: '2026-03-01T00:00:00.000Z' }], now);
    expect(expired.suppressed).toHaveLength(0);

    // A suppression targeting the Critical is refused (finding stays active).
    const critAttempt = applySuppressions(findings, [{ id: 's', ruleId: 'X-CRIT', reason: 'accept', createdBy: 'me', createdAt: '2026-01-01' }], now);
    expect(critAttempt.suppressed).toHaveLength(0);
    expect(critAttempt.refusedCritical).toBe(1);
    expect(critAttempt.active.map((f) => f.ruleId)).toContain('X-CRIT');
  });

  it('runScan excludes a suppressed rule from findings/scores and records it (auditable)', async () => {
    const base = await scan(rubyFixture, 'supp_base');
    expect(base.findings.some((f) => f.ruleId === 'RB-WEAK-HASH-001')).toBe(true);

    const supp: Suppression = { id: 'sup-hash', ruleId: 'RB-WEAK-HASH-001', reason: 'accepted risk: legacy checksum', createdBy: 'qa@example.com', createdAt: '2026-01-01' };
    const withSupp = await scan(rubyFixture, 'supp_applied', [supp]);
    expect(() => validateScanResult(withSupp)).not.toThrow();
    expect(withSupp.findings.some((f) => f.ruleId === 'RB-WEAK-HASH-001')).toBe(false);
    expect(withSupp.suppressedFindings?.some((s) => s.finding.ruleId === 'RB-WEAK-HASH-001')).toBe(true);
    expect(withSupp.suppressedFindings?.[0]?.suppression.createdBy).toBe('qa@example.com');
  });

  it('a suppression can NEVER un-block a Critical via runScan (§VII.8)', async () => {
    const supp: Suppression = { id: 'sup-secret', ruleId: 'SEC-SECRET-001', reason: 'trying to hide it', createdBy: 'x', createdAt: '2026-01-01' };
    const r = await scan(vulnFixture, 'supp_crit', [supp]);
    // The Critical secret stays active and still blocks; it is NOT moved to suppressedFindings.
    expect(r.findings.some((f) => f.ruleId === 'SEC-SECRET-001' && f.severity === 'Critical')).toBe(true);
    expect(r.releaseDecision.decision).toBe('NO_GO');
  });
});
