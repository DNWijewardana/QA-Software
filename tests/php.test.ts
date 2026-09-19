/**
 * PhpScanner test (§V.7). Scans the insecure PHP fixture and confirms each dangerous pattern is detected,
 * the comment mentioning eval(/system( is NOT flagged (comment-stripping), PDO ->exec / static include /
 * sha256 are NOT flagged (safe-pattern guards), and safe PHP yields none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-php', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('PhpScanner (§V.7)', () => {
  it('detects dangerous PHP patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-php-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_php', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of [
      'PHP-EVAL-001',
      'PHP-SHELL-EXEC-001',
      'PHP-SQL-CONCAT-001',
      'PHP-UNSERIALIZE-001',
      'PHP-FILE-INCLUSION-001',
      'PHP-XSS-ECHO-001',
      'PHP-WEAK-HASH-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // The comment mentioning eval( must not add a second finding, and PDO ->exec (no variable) must not
    // masquerade as SQL concatenation — so each fires exactly once.
    expect(rules.filter((r) => r === 'PHP-EVAL-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'PHP-SQL-CONCAT-001')).toHaveLength(1);

    const evil = result.findings.find((f) => f.ruleId === 'PHP-EVAL-001');
    expect(evil?.severity).toBe('High');
    expect(evil?.cwe).toContain('CWE-95');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe PHP', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-php-ok-'));
    await fs.writeFile(
      path.join(dir, 'safe.php'),
      [
        '<?php',
        'function run($pdo) {',
        '    $stmt = $pdo->prepare("SELECT * FROM users WHERE n = ?");',
        '    $stmt->execute([$_GET["n"]]);',
        '    echo htmlspecialchars($_GET["q"], ENT_QUOTES, "UTF-8");',
        '    include __DIR__ . "/config.php";',
        '    $h = hash("sha256", "x");',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_php_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('PHP-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
