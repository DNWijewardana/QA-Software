#!/usr/bin/env -S npx tsx
/**
 * qa-scan — CLI driver for the SAFE_STATIC vertical slice.
 *
 * Usage:
 *   npm run scan -- <projectDir | https-git-url> [--out <dir>] [--json-only]
 *                   [--baseline <result.json>] [--fail-on-regression]
 *
 * The target may be a local directory OR a public https git URL (shallow-cloned to a temp dir, scanned,
 * then removed). Emits BOTH the canonical JSON contract (§IX.4) and a human report (§IX.1) — dual output
 * (Rule 36). Runs ONLY in SAFE_STATIC mode: reads files, executes nothing (§VIII.1).
 *
 * `--baseline` compares this scan to a previously-saved result.json (differential analysis, §VII.10) and
 * writes diff.json + diff.md; `--fail-on-regression` makes the CLI exit non-zero when the diff detects a
 * regression (new Critical/High, worsened release decision, or a dimension score drop) — a CI gate (§V.19).
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { diffScans, renderScanDiff, type ScanResult } from '@qa/core';
import { validateScanResult } from '@qa/contracts';
import { toCsv, toCycloneDx, toHtml, toJUnit, toSarif } from '@qa/reporters';
import { isRemoteTarget, newScanId, prepareSource, renderHumanReport, runScan } from '@qa/orchestrator';

interface Args {
  /** Raw target: a local path OR an https git URL (resolved later by prepareSource). */
  target: string;
  outDir: string;
  jsonOnly: boolean;
  /** Optional path to a previous result.json to diff against (§VII.10). */
  baseline: string;
  /** Exit non-zero when the diff detects a regression. */
  failOnRegression: boolean;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  let outDir = '';
  let jsonOnly = false;
  let baseline = '';
  let failOnRegression = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--out') outDir = argv[++i] ?? '';
    else if (a === '--json-only') jsonOnly = true;
    else if (a === '--baseline') baseline = argv[++i] ?? '';
    else if (a === '--fail-on-regression') failOnRegression = true;
    else positional.push(a);
  }
  const target = positional[0];
  if (!target) {
    console.error('Usage: npm run scan -- <projectDir | https-git-url> [--out <dir>] [--json-only] [--baseline <result.json>] [--fail-on-regression]');
    process.exit(2);
  }
  return {
    target: isRemoteTarget(target) ? target : path.resolve(target),
    outDir: outDir ? path.resolve(outDir) : path.resolve('data', 'scans'),
    jsonOnly,
    baseline: baseline ? path.resolve(baseline) : '',
    failOnRegression,
  };
}

/** Load and validate a baseline scan result from disk (§VII.10). Exits(2) on read/parse/validation failure. */
async function loadBaseline(baselinePath: string): Promise<ScanResult> {
  let raw: string;
  try {
    raw = await fs.readFile(baselinePath, 'utf8');
  } catch (err) {
    console.error(`[qa-scan] Cannot read baseline: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }
  try {
    validateScanResult(JSON.parse(raw));
    return JSON.parse(raw) as ScanResult;
  } catch (err) {
    console.error(`[qa-scan] Baseline is not a valid scan result: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // Resolve the target into a readable directory — cloning a remote repo to a temp dir if needed.
  let source;
  try {
    if (isRemoteTarget(args.target)) console.error(`[qa-scan] Cloning ${args.target} …`);
    source = await prepareSource(args.target);
  } catch (err) {
    console.error(`[qa-scan] Cannot read target: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }

  const scanId = newScanId();
  const scanOut = path.join(args.outDir, scanId);
  const evidenceDir = path.join(scanOut, 'evidence');

  console.error(`[qa-scan] Mode: SAFE_STATIC  Target: ${source.origin.type}:${source.origin.ref}`);
  let result;
  try {
    result = await runScan({
      projectDir: source.dir,
      scanId,
      evidenceDir,
      environment: 'local-cli',
      onStage: (s) => console.error(`[qa-scan] stage: ${s}`),
    });
  } finally {
    await source.cleanup(); // always remove any temp clone
  }

  await fs.mkdir(scanOut, { recursive: true });
  const jsonPath = path.join(scanOut, 'result.json');
  await fs.writeFile(jsonPath, JSON.stringify(result, null, 2), 'utf8');

  // Always emit the interchange exports (§IX.3) alongside JSON — CI/tooling consumes these.
  await fs.writeFile(path.join(scanOut, 'result.sarif'), toSarif(result), 'utf8');
  await fs.writeFile(path.join(scanOut, 'result.junit.xml'), toJUnit(result), 'utf8');
  await fs.writeFile(path.join(scanOut, 'findings.csv'), toCsv(result), 'utf8');
  await fs.writeFile(path.join(scanOut, 'report.html'), toHtml(result), 'utf8');
  if (result.sbom) {
    await fs.writeFile(path.join(scanOut, 'sbom.cdx.json'), toCycloneDx(result.sbom, scanId), 'utf8');
  }

  // Differential analysis against a baseline (§VII.10), when requested.
  let regressed = false;
  if (args.baseline) {
    const baseline = await loadBaseline(args.baseline);
    const diff = diffScans(baseline, result);
    regressed = diff.regressionDetected;
    await fs.writeFile(path.join(scanOut, 'diff.json'), JSON.stringify(diff, null, 2), 'utf8');
    const diffText = renderScanDiff(diff);
    await fs.writeFile(path.join(scanOut, 'diff.md'), diffText, 'utf8');
    if (!args.jsonOnly) console.log(`\n${diffText}`);
  }

  if (!args.jsonOnly) {
    const human = renderHumanReport(result);
    const humanPath = path.join(scanOut, 'report.md');
    await fs.writeFile(humanPath, human, 'utf8');
    console.log(human);
    console.error(`\n[qa-scan] JSON contract: ${jsonPath}`);
    console.error(`[qa-scan] Human report:  ${humanPath}`);
    console.error(`[qa-scan] SARIF:         ${path.join(scanOut, 'result.sarif')}`);
    console.error(`[qa-scan] JUnit XML:     ${path.join(scanOut, 'result.junit.xml')}`);
    console.error(`[qa-scan] CSV:           ${path.join(scanOut, 'findings.csv')}`);
    console.error(`[qa-scan] HTML report:   ${path.join(scanOut, 'report.html')}`);
    if (result.sbom) console.error(`[qa-scan] SBOM (CycloneDX): ${path.join(scanOut, 'sbom.cdx.json')}`);
    if (args.baseline) console.error(`[qa-scan] Diff report:   ${path.join(scanOut, 'diff.md')}`);
    console.error(`[qa-scan] Evidence dir:  ${evidenceDir}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }

  // Non-zero exit if release is blocked (§V.19), or — with --fail-on-regression — if the diff regressed (§VII.10).
  const blocked = result.releaseDecision.decision === 'NO_GO';
  if (args.failOnRegression && regressed) console.error('[qa-scan] Regression detected vs baseline — failing (--fail-on-regression).');
  process.exit(blocked || (args.failOnRegression && regressed) ? 1 : 0);
}

main().catch((err) => {
  console.error('[qa-scan] FATAL:', err instanceof Error ? err.stack : err);
  process.exit(1);
});
