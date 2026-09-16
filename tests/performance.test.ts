/**
 * PerformanceScanner test (§V.12). Builds a temp project with oversized assets, a render-blocking script,
 * and a committed source map (large files are generated at runtime, never committed), and asserts the
 * static performance budget findings. Also verifies a lean project yields no findings.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const KB = 1024;
let dir: string;
afterEach(async () => {
  if (dir) await fs.rm(dir, { recursive: true, force: true });
});

describe('PerformanceScanner (static budgets)', () => {
  it('flags oversized assets, render-blocking scripts, and source maps', async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-perf-'));
    await fs.mkdir(path.join(dir, 'assets'), { recursive: true });
    await fs.writeFile(path.join(dir, 'assets', 'hero.png'), Buffer.alloc(600 * KB)); // > 500KB image budget
    await fs.writeFile(path.join(dir, 'assets', 'app.min.js'), Buffer.alloc(320 * KB)); // > 300KB JS budget
    await fs.writeFile(path.join(dir, 'assets', 'styles.css'), Buffer.alloc(160 * KB)); // > 150KB CSS budget
    await fs.writeFile(path.join(dir, 'app.js.map'), '{"version":3}'); // committed source map
    await fs.writeFile(
      path.join(dir, 'index.html'),
      '<html><head><script src="/assets/app.min.js"></script></head><body></body></html>',
      'utf8',
    );

    const result = await runScan({ projectDir: dir, scanId: 'scan_perf', evidenceDir: path.join(dir, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'PERF-ASSET-IMG-001',
      'PERF-JS-SIZE-001',
      'PERF-CSS-SIZE-001',
      'PERF-SOURCEMAP-001',
      'PERF-RENDER-BLOCK-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    expect(result.scores.some((s) => s.dimension === 'Performance')).toBe(true);
  });

  it('produces no performance findings for a lean project', async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-perf-ok-'));
    await fs.mkdir(path.join(dir, 'assets'), { recursive: true });
    await fs.writeFile(path.join(dir, 'assets', 'icon.png'), Buffer.alloc(4 * KB)); // small
    await fs.writeFile(
      path.join(dir, 'index.html'),
      '<html><head><script src="/assets/app.js" defer></script></head><body></body></html>', // deferred → not blocking
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_perf_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('PERF-'))).toBe(false);
  });
});
