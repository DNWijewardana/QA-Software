/**
 * Differential / baseline analysis test (§VII.10). Scans two different fixtures and diffs them, asserting the
 * diff correctly reports new/resolved findings, dimension movement, decision change, and regression detection.
 * Also checks that diffing a scan against ITSELF yields an empty (no-change, no-regression) diff.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { diffScans, renderScanDiff } from '@qa/core';

const cleanFixture = fileURLToPath(new URL('../fixtures/bad-architecture', import.meta.url)); // no Critical
const vulnFixture = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url)); // seeded Critical secret
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('differential analysis (§VII.10)', () => {
  it('reports new/resolved findings, movement, and a regression when baseline→current worsens', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-diff-'));
    const baseline = await runScan({ projectDir: cleanFixture, scanId: 'scan_base', evidenceDir: path.join(tmp, 'b') });
    const current = await runScan({ projectDir: vulnFixture, scanId: 'scan_cur', evidenceDir: path.join(tmp, 'c') });

    const diff = diffScans(baseline, current);
    expect(diff.baselineScanId).toBe('scan_base');
    expect(diff.currentScanId).toBe('scan_cur');

    // The vulnerable sample introduces a Critical secret that the architecture fixture did not have.
    expect(diff.bySeverity.added.Critical).toBeGreaterThan(0);
    expect(diff.findings.added.some((f) => f.ruleId === 'SEC-SECRET-001')).toBe(true);
    // The architecture fixture's cycle finding is not present in the vulnerable sample → resolved.
    expect(diff.findings.resolved.some((f) => f.ruleId === 'ARCH-CIRCULAR-DEP-001')).toBe(true);

    // A new Critical ⇒ regression, and the decision worsens to NO_GO.
    expect(diff.regressionDetected).toBe(true);
    expect(diff.decision.current).toBe('NO_GO');
    expect(diff.decision.worsened || diff.decision.changed).toBe(true);

    // Human render is non-empty and mentions the regression.
    const text = renderScanDiff(diff);
    expect(text).toContain('Differential Analysis');
    expect(text).toContain('Regression detected');
  });

  it('a scan diffed against itself shows no changes and no regression', async () => {
    const s = await runScan({ projectDir: vulnFixture, scanId: 'scan_self', evidenceDir: path.join(tmp, 's') });
    const diff = diffScans(s, s);
    expect(diff.findings.added).toHaveLength(0);
    expect(diff.findings.resolved).toHaveLength(0);
    expect(diff.findings.unchanged).toBeGreaterThan(0);
    expect(diff.overall.scoreDelta).toBe(0);
    expect(diff.decision.changed).toBe(false);
    expect(diff.regressionDetected).toBe(false);
    expect(diff.dimensions.every((d) => d.direction === 'stable')).toBe(true);
  });
});
