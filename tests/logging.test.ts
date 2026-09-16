/**
 * LoggingScanner test (§V.25). Scans the leaky-logging fixture and confirms sensitive-data, PII-object, and
 * console-usage findings, the Observability dimension is scored, and the "no sensitive data in logs"
 * compliance control shows a gap. Also verifies clean logging yields no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-logging', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('LoggingScanner (§V.25 logging quality)', () => {
  it('detects sensitive data in logs, PII-object logging, and console usage', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-log-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_log', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules).toContain('OBS-LOG-SENSITIVE-001');
    expect(rules).toContain('OBS-LOG-PII-OBJECT-001');
    expect(rules).toContain('OBS-LOG-CONSOLE-001');

    const sensitive = result.findings.find((f) => f.ruleId === 'OBS-LOG-SENSITIVE-001');
    expect(sensitive?.severity).toBe('High');
    expect(sensitive?.cwe).toContain('CWE-532');

    expect(result.scores.some((s) => s.dimension === 'Observability')).toBe(true);

    // The "no sensitive data in logs" compliance control is a gap.
    const ctrl = result.compliance?.controls.find((c) => c.controlId === 'CC7.2');
    expect(ctrl?.status).toBe('GAPS');
  });

  it('produces no logging findings for clean, structured logging', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-log-ok-'));
    await fs.writeFile(
      path.join(dir, 'svc.js'),
      'function ok(logger, userId) {\n  logger.info("user logged in", { userId });\n  return true;\n}\nmodule.exports = { ok };\n',
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_log_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('OBS-LOG-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
