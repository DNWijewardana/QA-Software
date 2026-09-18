/**
 * Detection-quality benchmark test (§X.1 dogfooding, §X.4). Runs the platform against the whole golden
 * corpus and asserts 100% recall of the seeded defects. A drop in recall (a real detection regression) fails
 * the build — the spec's "regression on detection quality is itself a quality gate".
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runBenchmark, GOLDEN_CORPUS } from '@qa/benchmark';

const fixturesRoot = fileURLToPath(new URL('../fixtures', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('detection-quality benchmark (§X.4)', () => {
  it('detects every seeded defect across the golden corpus (100% recall)', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-bench-'));
    const report = await runBenchmark({ fixturesRoot, evidenceRoot: tmp });

    // A readable failure message listing any undetected seeded defects.
    expect(report.totals.missingRules, `undetected seeded defects: ${JSON.stringify(report.totals.missingRules)}`).toEqual([]);
    expect(report.totals.recall).toBe(1);
    // Sanity: the corpus is non-trivial.
    expect(report.totals.fixtures).toBe(GOLDEN_CORPUS.length);
    expect(report.totals.expectedDefects).toBeGreaterThan(80);
  });
});
