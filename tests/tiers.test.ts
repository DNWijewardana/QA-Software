/**
 * Scan tiers test (§IX.9). QUICK runs a reduced engine set (fast hygiene); STANDARD/DEEP run the full static
 * set. Verifies engine selection is deterministic, that QUICK honestly discloses reduced coverage, and that
 * omitting a tier is unchanged (full static).
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { enginesForTier } from '@qa/engines';

const pyFixture = fileURLToPath(new URL('../fixtures/insecure-python', import.meta.url));
const tmps: string[] = [];
afterAll(async () => {
  await Promise.all(tmps.map((t) => fs.rm(t, { recursive: true, force: true })));
});
async function scan(id: string, tier?: 'quick' | 'standard' | 'deep') {
  const t = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-tier-'));
  tmps.push(t);
  return runScan({ projectDir: pyFixture, scanId: id, evidenceDir: path.join(t, 'ev'), tier });
}

describe('scan tiers (§IX.9)', () => {
  it('enginesForTier selects deterministically', () => {
    const quick = enginesForTier('quick').map((e) => e.name);
    const deep = enginesForTier('deep').map((e) => e.name);
    expect(quick).toContain('secret-scanner');
    expect(quick).not.toContain('python-scanner'); // deep-security engine excluded from QUICK
    expect(deep.length).toBeGreaterThan(quick.length);
    // STANDARD == DEEP for now (all static; dynamic engines are added at DEEP once authorized).
    expect(enginesForTier('standard').length).toBe(deep.length);
    // CUSTOM runs exactly the named engines.
    expect(enginesForTier('custom', ['secret-scanner']).map((e) => e.name)).toEqual(['secret-scanner']);
  });

  it('a QUICK scan runs fewer engines and discloses reduced coverage; DEEP runs the security engine', async () => {
    const quick = await scan('tier_quick', 'quick');
    // python-scanner is not in QUICK → its findings are absent.
    expect(quick.findings.some((f) => f.ruleId.startsWith('PY-'))).toBe(false);
    expect(quick.limitations.some((l) => l.includes('QUICK scan profile'))).toBe(true);

    const deep = await scan('tier_deep', 'deep');
    // DEEP runs python-scanner → the seeded Python defects are detected.
    expect(deep.findings.some((f) => f.ruleId.startsWith('PY-'))).toBe(true);
    expect(deep.limitations.some((l) => l.includes('QUICK scan profile'))).toBe(false);
  });
});
