/**
 * GoScanner test (§V.7). Scans the insecure Go fixture and confirms each dangerous pattern is detected,
 * the comment mentioning InsecureSkipVerify is NOT flagged (comment-stripping), and safe Go yields none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-go', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('GoScanner (§V.7)', () => {
  it('detects dangerous Go patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-go-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_go', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of ['GO-TLS-INSECURE-001', 'GO-EXEC-SHELL-001', 'GO-SQL-CONCAT-001', 'GO-WEAK-HASH-001']) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // The comment mentioning InsecureSkipVerify must not add a second finding.
    expect(rules.filter((r) => r === 'GO-TLS-INSECURE-001')).toHaveLength(1);

    const tlsF = result.findings.find((f) => f.ruleId === 'GO-TLS-INSECURE-001');
    expect(tlsF?.severity).toBe('High');
    expect(tlsF?.cwe).toContain('CWE-295');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe Go', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-go-ok-'));
    await fs.writeFile(
      path.join(dir, 'main.go'),
      [
        'package main',
        'import ("crypto/sha256"; "crypto/tls"; "database/sql"; "os/exec")',
        'func run(db *sql.DB, name string) {',
        '\tcfg := &tls.Config{}',
        '\t_ = cfg',
        '\texec.Command("ls", "-l")',
        '\tdb.Query("SELECT * FROM users WHERE name = ?", name)',
        '\tsha256.New()',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_go_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('GO-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
