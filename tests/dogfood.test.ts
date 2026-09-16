/**
 * Dogfooding test (§X.1, §X.2): run the platform against the intentionally-vulnerable fixture
 * and confirm it detects the KNOWN seeded defects. This is the detection-quality guarantee.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url));
let tmp: string;

describe('dogfood: scan the vulnerable fixture', () => {
  afterAll(async () => {
    if (tmp) await fs.rm(tmp, { recursive: true, force: true });
  });

  it('detects seeded secrets, produces valid contract output, and blocks release', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-dogfood-'));
    const result = await runScan({
      projectDir: fixtureDir,
      scanId: 'scan_test',
      evidenceDir: path.join(tmp, 'evidence'),
    });

    // Output must conform to the canonical contract (§IX.4).
    expect(() => validateScanResult(result)).not.toThrow();

    const ruleIds = result.findings.map((f) => f.ruleId);
    // Seeded security defect: hardcoded secret(s).
    expect(ruleIds).toContain('SEC-SECRET-001');
    // Seeded maintainability defects.
    expect(ruleIds).toContain('MNT-TODO-001');
    expect(ruleIds).toContain('MNT-VAR-001');

    // The AWS key finding must be Critical.
    const secret = result.findings.find((f) => f.ruleId === 'SEC-SECRET-001');
    expect(secret?.severity).toBe('Critical');

    // Critical finding ⇒ release blocked (§VII.9).
    expect(result.overall.criticalBlockers).toBeGreaterThan(0);
    expect(result.releaseDecision.decision).toBe('NO_GO');

    // Profiler detected JS + frameworks with recorded confidence (§III.3).
    expect(result.projectProfile.languages.some((l) => l.name === 'JavaScript')).toBe(true);
    expect(result.projectProfile.detectionConfidence).toBeGreaterThan(0);
  });

  it('NEVER leaks the raw secret value into any evidence artifact (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'evidence');
    const files = await fs.readdir(evDir);
    for (const file of files) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(content).not.toContain('SuperSecretP@ssw0rd123');
    }
  });
});
