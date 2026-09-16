/**
 * PrivacyScanner test (§V.16). Scans the PII fixture and confirms Luhn-validated card, SSN, and email
 * findings, the Privacy dimension is scored, and — critically — that NO raw PII value reaches evidence.
 * Also verifies a Luhn-invalid number and a placeholder email produce no false positives.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/pii-in-source', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('PrivacyScanner (§V.16)', () => {
  it('detects Luhn-valid cards, SSNs, and personal emails', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-priv-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_priv', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules).toContain('PRIV-PII-CARD-001');
    expect(rules).toContain('PRIV-PII-SSN-001');
    expect(rules).toContain('PRIV-PII-EMAIL-001');

    const card = result.findings.find((f) => f.ruleId === 'PRIV-PII-CARD-001');
    expect(card?.severity).toBe('High');
    expect(card?.cwe).toContain('CWE-312');

    expect(result.scores.some((s) => s.dimension === 'Privacy')).toBe(true);
  });

  it('never leaks the raw PII values into evidence (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    for (const file of await fs.readdir(evDir)) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('4111111111111111');
      expect(content).not.toContain('123-45-6789');
      expect(content).not.toContain('john.doe@gmail.com');
    }
  });

  it('does not flag a Luhn-invalid number or a placeholder email (no false positives)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-priv-ok-'));
    await fs.writeFile(
      path.join(dir, 'order.js'),
      'const orderId = "1234567890123456";\nconst support = "support@example.com";\nmodule.exports = { orderId, support };\n',
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_priv_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('PRIV-PII-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
