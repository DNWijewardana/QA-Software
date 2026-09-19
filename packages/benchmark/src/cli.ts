#!/usr/bin/env -S npx tsx
/**
 * Detection-quality benchmark runner (§X.1/§X.4). Runs the platform against the golden corpus and prints a
 * recall table. Exits non-zero if any seeded defect is undetected (a detection-quality gate).
 *
 * Usage: npm run benchmark
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderBenchmark, runBenchmark } from './index.js';

const repoRoot = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));

async function main(): Promise<void> {
  const fixturesRoot = path.join(repoRoot, 'fixtures');
  const evidenceRoot = path.join(repoRoot, 'data', 'benchmark');
  await fs.mkdir(evidenceRoot, { recursive: true });

  const report = await runBenchmark({ fixturesRoot, evidenceRoot });
  console.log(renderBenchmark(report));

  const outPath = path.join(evidenceRoot, 'benchmark.json');
  await fs.writeFile(outPath, JSON.stringify(report, null, 2), 'utf8');
  console.error(`\n[benchmark] JSON: ${outPath}`);

  // Detection-quality gate: fail on any recall regression (undetected seeded defect) OR precision
  // regression (an unaccounted detection). Both are quality gates (§X.4).
  const pass = report.totals.recall >= 1 && report.totals.falsePositives.length === 0;
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error('[benchmark] FATAL:', err instanceof Error ? err.stack : err);
  process.exit(1);
});
