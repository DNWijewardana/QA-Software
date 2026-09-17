/**
 * JavaScanner test (§V.7). Scans the insecure Java fixture and confirms each dangerous pattern is detected,
 * the comment mentioning Runtime.exec is NOT flagged (comment-stripping), and safe Java yields none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-java', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('JavaScanner (§V.7)', () => {
  it('detects dangerous Java patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-java-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_java', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of ['JAVA-RUNTIME-EXEC-001', 'JAVA-SQL-CONCAT-001', 'JAVA-DESERIALIZE-001', 'JAVA-WEAK-HASH-001', 'JAVA-ECB-001']) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // The comment mentioning Runtime.exec must not add a second finding.
    expect(rules.filter((r) => r === 'JAVA-RUNTIME-EXEC-001')).toHaveLength(1);

    const exec = result.findings.find((f) => f.ruleId === 'JAVA-RUNTIME-EXEC-001');
    expect(exec?.severity).toBe('High');
    expect(exec?.cwe).toContain('CWE-78');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe Java', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-java-ok-'));
    await fs.writeFile(
      path.join(dir, 'Safe.java'),
      [
        'import java.security.MessageDigest;',
        'import javax.crypto.Cipher;',
        'import java.sql.PreparedStatement;',
        'public class Safe {',
        '    void run(PreparedStatement ps) throws Exception {',
        '        ps.executeQuery();',
        '        MessageDigest.getInstance("SHA-256");',
        '        Cipher.getInstance("AES/GCM/NoPadding");',
        '    }',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_java_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('JAVA-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
