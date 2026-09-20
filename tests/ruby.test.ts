/**
 * RubyScanner test (§V.7). Scans the insecure Ruby fixture and confirms each dangerous pattern is detected,
 * the comment mentioning eval(/system( is NOT flagged (comment-stripping), and the safe patterns
 * (YAML.safe_load, parameterized where, SHA-256, argument-list system) are NOT flagged; safe Ruby → none.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-ruby', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('RubyScanner (§V.7)', () => {
  it('detects dangerous Ruby patterns', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-ruby-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_ruby', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of ['RB-EVAL-001', 'RB-COMMAND-EXEC-001', 'RB-DESERIALIZE-001', 'RB-SQL-INJECTION-001', 'RB-WEAK-HASH-001']) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // Comment-stripping + precision: eval / deserialize / command each fire exactly once (comment and the
    // safe YAML.safe_load / parameterized where / argument-list system are not flagged).
    expect(rules.filter((r) => r === 'RB-EVAL-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'RB-DESERIALIZE-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'RB-COMMAND-EXEC-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'RB-SQL-INJECTION-001')).toHaveLength(1);

    const evil = result.findings.find((f) => f.ruleId === 'RB-EVAL-001');
    expect(evil?.severity).toBe('High');
    expect(evil?.cwe).toContain('CWE-95');
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);
  });

  it('produces no findings for safe Ruby', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-ruby-ok-'));
    await fs.writeFile(
      path.join(dir, 'safe.rb'),
      [
        "require 'yaml'",
        "require 'digest'",
        'def run(name)',
        '  YAML.safe_load(name)',
        '  User.where("name = ?", name)',
        '  Digest::SHA256.hexdigest(name)',
        '  system("ls", "-la")',
        'end',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_ruby_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('RB-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
