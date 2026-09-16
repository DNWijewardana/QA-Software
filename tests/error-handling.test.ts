/**
 * ErrorHandlingScanner test (§V.14). Scans the poor-error-handling fixture and confirms empty-catch,
 * console-only-catch, stack-exposed, and throw-literal findings, and that the Reliability dimension is
 * scored. Also verifies robust error handling yields no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/bad-error-handling', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('ErrorHandlingScanner (§V.14)', () => {
  it('detects swallowed errors, exposed stack traces, and thrown literals', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-err-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_err', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'ERR-EMPTY-CATCH-001',
      'ERR-CATCH-CONSOLE-001',
      'ERR-STACK-EXPOSED-001',
      'ERR-THROW-LITERAL-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    const stack = result.findings.find((f) => f.ruleId === 'ERR-STACK-EXPOSED-001');
    expect(stack?.severity).toBe('High');
    expect(stack?.cwe).toContain('CWE-209');

    expect(result.scores.some((s) => s.dimension === 'Reliability')).toBe(true);
  });

  it('produces no error-handling findings for robust code', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-err-ok-'));
    await fs.writeFile(
      path.join(dir, 'svc.js'),
      [
        'function safe(logger) {',
        '  try {',
        '    return risky();',
        '  } catch (e) {',
        '    logger.error("risky failed", { code: e.code });',
        '    throw new Error("operation failed");',
        '  }',
        '}',
        'module.exports = { safe };',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_err_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('ERR-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
