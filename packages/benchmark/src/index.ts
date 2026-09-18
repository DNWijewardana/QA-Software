/**
 * @qa/benchmark — detection-quality benchmark (§X.1 dogfooding, §X.4). Runs the platform against the golden
 * corpus and measures RECALL of the seeded defects. Regression on recall is a quality gate (§X.4).
 */

import { runScan } from '@qa/orchestrator';
import { GOLDEN_CORPUS, type CorpusEntry } from './corpus.js';

export * from './corpus.js';

export interface FixtureResult {
  fixture: string;
  expected: number;
  found: number;
  missing: string[];
  recall: number;
}

export interface BenchmarkReport {
  fixtures: FixtureResult[];
  totals: {
    fixtures: number;
    expectedDefects: number;
    foundDefects: number;
    recall: number;
    missingRules: Array<{ fixture: string; rule: string }>;
  };
}

export interface BenchmarkOptions {
  /** absolute path to the fixtures directory. */
  fixturesRoot: string;
  /** base directory for per-fixture evidence output. */
  evidenceRoot: string;
  corpus?: CorpusEntry[];
}

/** Scan every corpus fixture and compute per-fixture and overall recall of the seeded defects. */
export async function runBenchmark(opts: BenchmarkOptions): Promise<BenchmarkReport> {
  const corpus = opts.corpus ?? GOLDEN_CORPUS;
  const fixtures: FixtureResult[] = [];
  const missingRules: Array<{ fixture: string; rule: string }> = [];
  let expectedTotal = 0;
  let foundTotal = 0;

  for (const entry of corpus) {
    const result = await runScan({
      scanId: `bench_${entry.fixture}`,
      projectDir: `${opts.fixturesRoot}/${entry.fixture}`,
      evidenceDir: `${opts.evidenceRoot}/${entry.fixture}`,
      environment: 'benchmark',
    });
    // SEO findings are reported separately (§V.24) but are still "detections" for corpus purposes.
    const detected = new Set<string>([
      ...result.findings.map((f) => f.ruleId),
      ...(result.seo?.findings ?? []).map((f) => f.ruleId),
    ]);
    const missing = entry.expected.filter((r) => !detected.has(r));
    const found = entry.expected.length - missing.length;
    expectedTotal += entry.expected.length;
    foundTotal += found;
    for (const rule of missing) missingRules.push({ fixture: entry.fixture, rule });
    fixtures.push({
      fixture: entry.fixture,
      expected: entry.expected.length,
      found,
      missing,
      recall: entry.expected.length === 0 ? 1 : found / entry.expected.length,
    });
  }

  return {
    fixtures,
    totals: {
      fixtures: corpus.length,
      expectedDefects: expectedTotal,
      foundDefects: foundTotal,
      recall: expectedTotal === 0 ? 1 : foundTotal / expectedTotal,
      missingRules,
    },
  };
}

/** Render a human-readable benchmark table. */
export function renderBenchmark(report: BenchmarkReport): string {
  const L: string[] = [];
  L.push('# Detection-Quality Benchmark (§X.4)');
  L.push('');
  L.push('Measures RECALL of seeded defects across the golden corpus. (Precision is not measured — the');
  L.push('corpus is single-purpose, so unrelated legitimate findings are expected, not false positives.)');
  L.push('');
  L.push('| Fixture | Found / Expected | Recall | Missing |');
  L.push('|---|---|---|---|');
  for (const f of report.fixtures) {
    L.push(`| ${f.fixture} | ${f.found}/${f.expected} | ${(f.recall * 100).toFixed(0)}% | ${f.missing.join(', ') || '—'} |`);
  }
  const t = report.totals;
  L.push('');
  L.push(`**Overall recall: ${(t.recall * 100).toFixed(1)}%** — ${t.foundDefects}/${t.expectedDefects} seeded defects detected across ${t.fixtures} fixtures.`);
  if (t.missingRules.length) {
    L.push('');
    L.push('Undetected seeded defects (a detection-quality regression):');
    for (const m of t.missingRules) L.push(`- ${m.fixture}: ${m.rule}`);
  }
  return L.join('\n');
}
