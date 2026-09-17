/**
 * PythonScanner test (§V.7). Scans the insecure Python fixture and confirms each dangerous pattern is
 * detected, the comment mentioning eval() is NOT flagged (comment-stripping), and safe Python yields none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-python', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('PythonScanner (§V.7)', () => {
  it('detects dangerous Python patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-py-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_py', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'PY-EVAL-001',
      'PY-OS-SYSTEM-001',
      'PY-SUBPROCESS-SHELL-001',
      'PY-PICKLE-001',
      'PY-YAML-LOAD-001',
      'PY-FLASK-DEBUG-001',
      'PY-WEAK-HASH-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    // eval() appears twice as code (eval + exec) but the comment mentioning it must not add a third.
    expect(result.findings.filter((f) => f.ruleId === 'PY-EVAL-001')).toHaveLength(2);

    const evalF = result.findings.find((f) => f.ruleId === 'PY-EVAL-001');
    expect(evalF?.severity).toBe('High');
    expect(evalF?.cwe).toContain('CWE-95');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe Python', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-py-ok-'));
    await fs.writeFile(
      path.join(dir, 'safe.py'),
      [
        'import ast, subprocess, yaml, hashlib',
        'def run(cmd, data):',
        '    ast.literal_eval(data)',
        '    subprocess.run(["ls", "-l"], shell=False)',
        '    yaml.safe_load(data)',
        '    hashlib.sha256(data)',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_py_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('PY-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
