/**
 * CicdScanner test (§V.19). Scans the insecure GitHub Actions workflow fixture and confirms
 * pull_request_target, missing permissions, unpinned actions, script injection, and secret-echo findings,
 * and that CI findings score under Security. Also verifies a hardened workflow yields no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-cicd', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('CicdScanner (§V.19 pipeline security)', () => {
  it('detects insecure GitHub Actions patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cicd-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_cicd', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'CI-PR-TARGET-001',
      'CI-PERMISSIONS-000',
      'CI-ACTION-UNPINNED-001',
      'CI-SCRIPT-INJECTION-001',
      'CI-SECRET-ECHO-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    const inj = result.findings.find((f) => f.ruleId === 'CI-SCRIPT-INJECTION-001');
    expect(inj?.severity).toBe('High');
    expect(inj?.cwe).toContain('CWE-94');

    // CI findings score under the Security dimension.
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for a hardened workflow', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cicd-ok-'));
    const wf = path.join(dir, '.github', 'workflows');
    await fs.mkdir(wf, { recursive: true });
    await fs.writeFile(
      path.join(wf, 'good.yml'),
      [
        'name: ci',
        'on: [pull_request]',
        'permissions:',
        '  contents: read',
        'jobs:',
        '  build:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678',
        '      - name: build',
        '        run: npm ci && npm test',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_cicd_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('CI-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
