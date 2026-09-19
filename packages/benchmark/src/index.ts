/**
 * @qa/benchmark — detection-quality benchmark (§X.1 dogfooding, §X.4). Runs the platform against the golden
 * corpus and measures RECALL of the seeded defects. Regression on recall is a quality gate (§X.4).
 */

import { runScan } from '@qa/orchestrator';
import { GOLDEN_CORPUS, GLOBAL_ALLOWED, type CorpusEntry } from './corpus.js';

export * from './corpus.js';

export interface FixtureResult {
  fixture: string;
  expected: number;
  found: number;
  missing: string[];
  recall: number;
  /** Total distinct rule IDs detected on this fixture. */
  detected: number;
  /** Detected rule IDs that are neither seeded nor accounted-for → candidate false positives. */
  falsePositives: string[];
  /** correctlyDetected / detected (1 when nothing was detected). */
  precision: number;
}

export interface BenchmarkReport {
  fixtures: FixtureResult[];
  totals: {
    fixtures: number;
    expectedDefects: number;
    foundDefects: number;
    recall: number;
    missingRules: Array<{ fixture: string; rule: string }>;
    /** Total distinct rule IDs detected across the corpus. */
    detected: number;
    /** Correct detections (seeded + accounted-for incidental) across the corpus. */
    correct: number;
    /** Micro-averaged precision = correct / detected. */
    precision: number;
    /** Unaccounted detections across the corpus (a precision regression → gate fails). */
    falsePositives: Array<{ fixture: string; rule: string }>;
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
  const falsePositiveList: Array<{ fixture: string; rule: string }> = [];
  let expectedTotal = 0;
  let foundTotal = 0;
  let detectedTotal = 0;
  let correctTotal = 0;

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
    // Every rule that is CORRECT to fire on this fixture: seeded ∪ documented-incidental ∪ global hygiene.
    const accounted = new Set<string>([...entry.expected, ...(entry.allowedExtra ?? []), ...GLOBAL_ALLOWED]);

    const missing = entry.expected.filter((r) => !detected.has(r));
    const found = entry.expected.length - missing.length;
    // A detection that is not accounted for anywhere is a candidate false positive.
    const falsePositives = [...detected].filter((r) => !accounted.has(r)).sort();
    const correct = detected.size - falsePositives.length;

    expectedTotal += entry.expected.length;
    foundTotal += found;
    detectedTotal += detected.size;
    correctTotal += correct;
    for (const rule of missing) missingRules.push({ fixture: entry.fixture, rule });
    for (const rule of falsePositives) falsePositiveList.push({ fixture: entry.fixture, rule });

    fixtures.push({
      fixture: entry.fixture,
      expected: entry.expected.length,
      found,
      missing,
      recall: entry.expected.length === 0 ? 1 : found / entry.expected.length,
      detected: detected.size,
      falsePositives,
      precision: detected.size === 0 ? 1 : correct / detected.size,
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
      detected: detectedTotal,
      correct: correctTotal,
      precision: detectedTotal === 0 ? 1 : correctTotal / detectedTotal,
      falsePositives: falsePositiveList,
    },
  };
}

/** Render a human-readable benchmark table. */
export function renderBenchmark(report: BenchmarkReport): string {
  const L: string[] = [];
  L.push('# Detection-Quality Benchmark (§X.4)');
  L.push('');
  L.push('Measures RECALL (seeded defects detected) and PRECISION (share of detections that are correct)');
  L.push('across the fully-labelled golden corpus. A detection that is neither a seeded defect nor a');
  L.push('documented legitimate incidental finding is a candidate FALSE POSITIVE and fails the gate.');
  L.push('');
  L.push('| Fixture | Found / Expected | Recall | Detected | Precision | False positives |');
  L.push('|---|---|---|---|---|---|');
  for (const f of report.fixtures) {
    L.push(`| ${f.fixture} | ${f.found}/${f.expected} | ${(f.recall * 100).toFixed(0)}% | ${f.detected} | ${(f.precision * 100).toFixed(0)}% | ${f.falsePositives.join(', ') || '—'} |`);
  }
  const t = report.totals;
  L.push('');
  L.push(`**Overall recall: ${(t.recall * 100).toFixed(1)}%** — ${t.foundDefects}/${t.expectedDefects} seeded defects detected across ${t.fixtures} fixtures.`);
  L.push(`**Overall precision: ${(t.precision * 100).toFixed(1)}%** — ${t.correct}/${t.detected} detections accounted for (seeded or documented-legitimate).`);
  if (t.missingRules.length) {
    L.push('');
    L.push('Undetected seeded defects (a recall regression):');
    for (const m of t.missingRules) L.push(`- ${m.fixture}: ${m.rule}`);
  }
  if (t.falsePositives.length) {
    L.push('');
    L.push('Unaccounted detections (a precision regression — classify as seeded, legitimate-incidental, or fix the rule):');
    for (const fp of t.falsePositives) L.push(`- ${fp.fixture}: ${fp.rule}`);
  }
  return L.join('\n');
}
