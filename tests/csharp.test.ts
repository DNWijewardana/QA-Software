/**
 * CSharpScanner test (§V.7). Scans the insecure C# fixture and confirms each dangerous pattern is detected,
 * the comment mentioning Process.Start(/new SqlCommand( is NOT flagged (comment-stripping), the benign
 * literal Process.Start / constant SqlCommand / SHA256 are NOT flagged (precision guards), and safe C#
 * yields none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-csharp', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('CSharpScanner (§V.7)', () => {
  it('detects dangerous C# patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cs-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_cs', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of [
      'CS-PROCESS-START-001',
      'CS-SQL-CONCAT-001',
      'CS-DESERIALIZE-001',
      'CS-CERT-VALIDATION-001',
      'CS-WEAK-CIPHER-001',
      'CS-WEAK-HASH-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // Comment-stripping + precision guards: the injection rules fire exactly once (the comment and the
    // benign literal Process.Start / constant SqlCommand are not flagged).
    expect(rules.filter((r) => r === 'CS-PROCESS-START-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'CS-SQL-CONCAT-001')).toHaveLength(1);

    const proc = result.findings.find((f) => f.ruleId === 'CS-PROCESS-START-001');
    expect(proc?.severity).toBe('High');
    expect(proc?.cwe).toContain('CWE-78');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe C#', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cs-ok-'));
    await fs.writeFile(
      path.join(dir, 'Safe.cs'),
      [
        'using System.Diagnostics;',
        'using System.Data.SqlClient;',
        'using System.Security.Cryptography;',
        'class Safe {',
        '    void Run(SqlConnection conn) {',
        '        Process.Start("notepad.exe");',
        '        var cmd = new SqlCommand("SELECT 1", conn);',
        '        var sha = SHA256.Create();',
        '    }',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_cs_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('CS-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
