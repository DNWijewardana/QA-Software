/**
 * SEO analyzer test (§V.24). Scans the SEO-poor fixture and confirms each seeded issue is detected AND —
 * critically — that SEO findings are kept SEPARATE from software quality: they must not appear in the
 * scored findings, and must not affect the quality dimensions or the release decision.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/seo-issues', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('SEO analyzer (§V.24)', () => {
  it('detects seeded SEO issues in a separate report', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-seo-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_seo', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    expect(result.seo).toBeDefined();
    expect(result.seo!.note.toLowerCase()).toContain('separately');

    const rules = new Set(result.seo!.findings.map((f) => f.ruleId));
    for (const expected of [
      'SEO-TITLE-001',
      'SEO-META-DESC-001',
      'SEO-CANONICAL-001',
      'SEO-ROBOTS-NOINDEX-001',
      'SEO-H1-001',
      'SEO-OG-001',
      'SEO-VIEWPORT-001',
      'SEO-ROBOTSTXT-001',
      'SEO-SITEMAP-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
  });

  it('keeps SEO out of software quality (§V.24 separation)', async () => {
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_seo2', evidenceDir: path.join(tmp, 'ev2') });

    // SEO findings never appear in the scored findings list...
    expect(result.findings.every((f) => f.category !== 'SEO')).toBe(true);
    // ...and there is no SEO quality dimension.
    expect(result.scores.every((s) => (s.dimension as string) !== 'SEO')).toBe(true);
    // The SEO findings live only in the separate report.
    expect(result.seo!.findings.every((f) => f.category === 'SEO')).toBe(true);
  });
});
