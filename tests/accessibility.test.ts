/**
 * HtmlAccessibilityScanner test (§V.5, WCAG 2.2). Scans the intentionally-inaccessible HTML fixture,
 * confirms each seeded issue is detected, the Accessibility dimension is scored, and a manual WCAG audit
 * item is queued (automation cannot prove conformance). Also verifies a clean page yields no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/inaccessible-html', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('HtmlAccessibilityScanner (WCAG 2.2)', () => {
  it('detects every seeded accessibility issue and queues a manual audit', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-a11y-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_a11y', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'A11Y-HTML-LANG-001',
      'A11Y-TITLE-001',
      'A11Y-IMG-ALT-001',
      'A11Y-INPUT-LABEL-001',
      'A11Y-BUTTON-NAME-001',
      'A11Y-LINK-NAME-001',
      'A11Y-TABINDEX-001',
      'A11Y-IFRAME-TITLE-001',
      'A11Y-VIEWPORT-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    // Findings carry the WCAG criterion + level.
    const imgAlt = result.findings.find((f) => f.ruleId === 'A11Y-IMG-ALT-001');
    expect(imgAlt?.standards.some((s) => s.framework === 'WCAG 2.2' && s.id.includes('1.1.1'))).toBe(true);

    // Accessibility dimension is scored.
    expect(result.scores.some((s) => s.dimension === 'Accessibility')).toBe(true);

    // Honesty: a manual WCAG audit is queued because automation cannot prove conformance.
    expect(result.manualReviewQueue.some((m) => /WCAG 2.2 manual/i.test(m.item))).toBe(true);
  });

  it('produces no accessibility findings on a clean page (no false positives)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-a11y-ok-'));
    await fs.writeFile(
      path.join(dir, 'good.html'),
      `<!DOCTYPE html><html lang="en"><head><title>Good</title>
       <meta name="viewport" content="width=device-width, initial-scale=1"></head>
       <body><img src="a.png" alt="A logo">
       <label for="e">Email</label><input id="e" type="text">
       <button>Save</button><a href="/x">Home</a></body></html>`,
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_a11y_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('A11Y-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
