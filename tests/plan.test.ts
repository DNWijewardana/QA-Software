/**
 * Scan-plan preview test (§IX.9/§126). planScan reports which engines WILL run for a project + tier without
 * executing anything, and never invents finding/check counts.
 */

import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { planScan } from '@qa/orchestrator';

const pyFixture = fileURLToPath(new URL('../fixtures/insecure-python', import.meta.url));

describe('scan plan preview (§IX.9/§126)', () => {
  it('lists the applicable engines for the default (full) profile without running them', async () => {
    const plan = await planScan({ projectDir: pyFixture });
    expect(plan.tier).toBe('default');
    expect(plan.fileCount).toBeGreaterThan(0);
    // python-scanner applies to the Python fixture and will run.
    const py = plan.engines.find((e) => e.name === 'python-scanner');
    expect(py?.applicable).toBe(true);
    expect(plan.applicableEngines).toBeGreaterThan(0);
    expect(plan.applicableEngines).toBeLessThanOrEqual(plan.engines.length);
    // No invented counts — the note is explicit about that, and there is no findings/check count field.
    expect(plan.note).toMatch(/never invented/i);
    expect(plan).not.toHaveProperty('findingCount');
  });

  it('a QUICK plan omits the deep security engines entirely', async () => {
    const plan = await planScan({ projectDir: pyFixture, tier: 'quick' });
    expect(plan.tier).toBe('quick');
    // python-scanner is not part of the QUICK tier → it is not even in the plan's engine list.
    expect(plan.engines.some((e) => e.name === 'python-scanner')).toBe(false);
    expect(plan.engines.some((e) => e.name === 'secret-scanner')).toBe(true);
  });
});
