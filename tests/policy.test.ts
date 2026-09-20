/**
 * Configurable policy engine test (§VII.11, §86). Verifies that a scan policy changes dimension weights and
 * the High-findings gate, that omitting a policy reproduces platform defaults, and — critically (§VII.8,
 * Rule 22/23) — that NO policy can un-block a Critical finding.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { resolvePolicy, DEFAULT_WEIGHTS } from '@qa/core';

const rubyFixture = fileURLToPath(new URL('../fixtures/insecure-ruby', import.meta.url)); // High findings, no Critical
const vulnFixture = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url)); // seeded Critical

async function scan(dir: string, id: string, policy?: Parameters<typeof runScan>[0]['policy']) {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-policy-'));
  try {
    return await runScan({ projectDir: dir, scanId: id, evidenceDir: path.join(tmp, 'ev'), policy });
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

describe('configurable policy engine (§VII.11)', () => {
  it('resolvePolicy clamps and defaults correctly', () => {
    const def = resolvePolicy();
    expect(def.maxHigh).toBe(0);
    expect(def.minEvidenceCoverage).toBe(0.4);
    expect(def.weights.Security).toBe(DEFAULT_WEIGHTS.Security);

    const custom = resolvePolicy({ weights: { Security: 0.5, Maintainability: -3 }, gates: { maxHigh: 10, minEvidenceCoverage: 2 } });
    expect(custom.weights.Security).toBe(0.5);
    // A negative weight is ignored (kept at default), and an out-of-range coverage is clamped to 1.
    expect(custom.weights.Maintainability).toBe(DEFAULT_WEIGHTS.Maintainability);
    expect(custom.maxHigh).toBe(10);
    expect(custom.minEvidenceCoverage).toBe(1);
  });

  it('a custom weight changes the dimension weight in the result', async () => {
    const def = await scan(rubyFixture, 'pol_def');
    const custom = await scan(rubyFixture, 'pol_wt', { weights: { Security: 0.9 } });
    const defSec = def.scores.find((s) => s.dimension === 'Security')!;
    const cusSec = custom.scores.find((s) => s.dimension === 'Security')!;
    expect(defSec.weight).toBe(DEFAULT_WEIGHTS.Security);
    expect(cusSec.weight).toBe(0.9);
  });

  it('raising the High budget flips GO_WITH_CONDITIONS → GO (no Critical present)', async () => {
    const def = await scan(rubyFixture, 'pol_gate_def');
    // insecure-ruby has High findings but no Critical → default maxHigh 0 → GO_WITH_CONDITIONS.
    expect(def.releaseDecision.decision).toBe('GO_WITH_CONDITIONS');

    const relaxed = await scan(rubyFixture, 'pol_gate_relaxed', { gates: { maxHigh: 20 } });
    expect(relaxed.releaseDecision.decision).toBe('GO');
  });

  it('NO policy can un-block a Critical finding (§VII.8, Rule 22/23)', async () => {
    // Even with an absurdly permissive gate and Security de-emphasized, a Critical still forces NO_GO.
    const permissive = await scan(vulnFixture, 'pol_crit', { weights: { Security: 0 }, gates: { maxHigh: 9999 } });
    expect(permissive.overall.criticalBlockers).toBeGreaterThan(0);
    expect(permissive.releaseDecision.decision).toBe('NO_GO');
  });
});
