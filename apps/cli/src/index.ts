#!/usr/bin/env -S npx tsx
/**
 * qa-scan — CLI driver for the SAFE_STATIC vertical slice.
 *
 * Usage:
 *   npm run scan -- <projectDir> [--out <dir>] [--json-only]
 *
 * Emits BOTH the canonical JSON contract (§IX.4) and a human report (§IX.1) — dual output (Rule 36).
 * Runs ONLY in SAFE_STATIC mode: reads files, executes nothing (§VIII.1).
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { toCsv, toCycloneDx, toJUnit, toSarif } from '@qa/reporters';
import { newScanId, renderHumanReport, runScan } from '@qa/orchestrator';

interface Args {
  projectDir: string;
  outDir: string;
  jsonOnly: boolean;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  let outDir = '';
  let jsonOnly = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--out') outDir = argv[++i] ?? '';
    else if (a === '--json-only') jsonOnly = true;
    else positional.push(a);
  }
  const projectDir = positional[0];
  if (!projectDir) {
    console.error('Usage: npm run scan -- <projectDir> [--out <dir>] [--json-only]');
    process.exit(2);
  }
  return {
    projectDir: path.resolve(projectDir),
    outDir: outDir ? path.resolve(outDir) : path.resolve('data', 'scans'),
    jsonOnly,
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  const stat = await fs.stat(args.projectDir).catch(() => null);
  if (!stat?.isDirectory()) {
    console.error(`Not a directory: ${args.projectDir}`);
    process.exit(2);
  }

  const scanId = newScanId();
  const scanOut = path.join(args.outDir, scanId);
  const evidenceDir = path.join(scanOut, 'evidence');

  console.error(`[qa-scan] Mode: SAFE_STATIC  Target: ${args.projectDir}`);
  const result = await runScan({
    projectDir: args.projectDir,
    scanId,
    evidenceDir,
    environment: 'local-cli',
    onStage: (s) => console.error(`[qa-scan] stage: ${s}`),
  });

  await fs.mkdir(scanOut, { recursive: true });
  const jsonPath = path.join(scanOut, 'result.json');
  await fs.writeFile(jsonPath, JSON.stringify(result, null, 2), 'utf8');

  // Always emit the interchange exports (§IX.3) alongside JSON — CI/tooling consumes these.
  await fs.writeFile(path.join(scanOut, 'result.sarif'), toSarif(result), 'utf8');
  await fs.writeFile(path.join(scanOut, 'result.junit.xml'), toJUnit(result), 'utf8');
  await fs.writeFile(path.join(scanOut, 'findings.csv'), toCsv(result), 'utf8');
  if (result.sbom) {
    await fs.writeFile(path.join(scanOut, 'sbom.cdx.json'), toCycloneDx(result.sbom, scanId), 'utf8');
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
    if (result.sbom) console.error(`[qa-scan] SBOM (CycloneDX): ${path.join(scanOut, 'sbom.cdx.json')}`);
    console.error(`[qa-scan] Evidence dir:  ${evidenceDir}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }

  // Non-zero exit if release is blocked — useful as a CI quality gate (§V.19).
  process.exit(result.releaseDecision.decision === 'NO_GO' ? 1 : 0);
}

main().catch((err) => {
  console.error('[qa-scan] FATAL:', err instanceof Error ? err.stack : err);
  process.exit(1);
});
