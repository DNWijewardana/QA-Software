/**
 * HTML report exporter tests (§IX.3). Runs one real scan of the fixture, then asserts the HTML report is a
 * complete document carrying the key sections — and, critically, that untrusted finding content is
 * HTML-escaped (no stored-XSS when the report is opened in a browser).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanResult } from '@qa/core';
import { runScan } from '@qa/orchestrator';
import { toHtml } from '@qa/reporters';

const fixtureDir = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url));
let tmp: string;
let result: ScanResult;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-html-'));
  result = await runScan({ projectDir: fixtureDir, scanId: 'scan_html', evidenceDir: path.join(tmp, 'ev') });
});
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('HTML report (§IX.3)', () => {
  it('renders a complete, self-contained HTML document with the key sections', () => {
    const html = toHtml(result);
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html.trimEnd().endsWith('</html>')).toBe(true);
    // Self-contained: styles inlined, no external script/stylesheet references.
    expect(html).toContain('<style>');
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<link[^>]+stylesheet/i);
    // Core sections present.
    expect(html).toContain('Release Decision');
    expect(html).toContain(result.releaseDecision.decision.replace(/_/g, ' '));
    expect(html).toContain('Quality dimensions');
    expect(html).toContain('Findings');
    expect(html).toContain('Limitations');
    expect(html).toContain('scan_html');
    // At least one real finding surfaces.
    expect(html).toContain(result.findings[0]!.title);
  });

  it('escapes untrusted finding content (no stored-XSS)', () => {
    // A malicious value could arrive via a filename, string literal, or dependency name in scanned code.
    const poisoned: ScanResult = {
      ...result,
      findings: result.findings.map((f, i) =>
        i === 0 ? { ...f, title: '<script>alert(1)</script>', description: '"><img src=x onerror=alert(2)>' } : f,
      ),
    };
    const html = toHtml(poisoned);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('<img src=x onerror=alert(2)>');
  });
});
