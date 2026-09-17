/**
 * Regression test for scanning secrets/PII in SQL files. `.sql` is now a recognised text type, so the
 * secret and privacy engines analyse SQL seed/migration data. Confirms detection AND that no raw
 * secret/PII value reaches evidence (§VIII.10).
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/sql-with-secrets', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('secrets & PII in SQL files', () => {
  it('detects an AWS key and PII in SQL seed data', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-sqlsec-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_sqlsec', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules).toContain('SEC-SECRET-001'); // AWS key
    expect(rules).toContain('PRIV-PII-EMAIL-001');
    expect(rules).toContain('PRIV-PII-CARD-001');
  });

  it('never leaks the raw secret/PII values into evidence (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    for (const file of await fs.readdir(evDir)) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(content).not.toContain('4111111111111111');
      expect(content).not.toContain('john.doe@gmail.com');
    }
  });
});
