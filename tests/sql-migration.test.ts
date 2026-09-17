/**
 * SqlMigrationScanner test (§V.31). Scans the dangerous-migration fixture and confirms each destructive
 * statement is flagged AND that the safe variants (DELETE/UPDATE with WHERE, nullable/defaulted columns)
 * are NOT flagged — the counts prove no false positives.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/dangerous-migration', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('SqlMigrationScanner (§V.31)', () => {
  it('flags destructive statements but not their safe variants', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-sql-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_sql', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const count = (rule: string) => result.findings.filter((f) => f.ruleId === rule).length;

    // Each destructive statement appears exactly once.
    expect(count('SQL-DROP-TABLE-001')).toBe(1);
    expect(count('SQL-DROP-COLUMN-001')).toBe(1);
    expect(count('SQL-TRUNCATE-001')).toBe(1);
    // WHERE-scoped DELETE/UPDATE and defaulted/nullable columns must NOT add extra findings.
    expect(count('SQL-DELETE-NO-WHERE-001')).toBe(1);
    expect(count('SQL-UPDATE-NO-WHERE-001')).toBe(1);
    expect(count('SQL-NOTNULL-NO-DEFAULT-001')).toBe(1);

    const drop = result.findings.find((f) => f.ruleId === 'SQL-DROP-TABLE-001');
    expect(drop?.severity).toBe('High');
    expect(result.scores.some((s) => s.dimension === 'Reliability')).toBe(true);
  });

  it('produces no findings for a safe, additive migration', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-sql-ok-'));
    await fs.writeFile(
      path.join(dir, 'safe.sql'),
      [
        'CREATE TABLE widgets (id SERIAL PRIMARY KEY, name TEXT NOT NULL DEFAULT \'\');',
        'ALTER TABLE widgets ADD COLUMN color TEXT;',
        'UPDATE widgets SET color = \'red\' WHERE id = 1;',
        'DELETE FROM widgets WHERE id = 2;',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_sql_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('SQL-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
