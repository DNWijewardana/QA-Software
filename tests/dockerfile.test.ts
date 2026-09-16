/**
 * DockerfileScanner test (§V.18, CIS Docker Benchmark). Scans the intentionally-insecure Dockerfile
 * fixture and confirms each seeded misconfiguration is detected, the secret is redacted, and the
 * CloudIaCPosture dimension is scored. Runs against an ISOLATED fixture so existing tests are unaffected.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-docker', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('DockerfileScanner (CIS Docker checks)', () => {
  it('detects every seeded Dockerfile misconfiguration', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-docker-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_docker', evidenceDir: path.join(tmp, 'ev') });

    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'IAC-DOCKER-TAG-001',
      'IAC-DOCKER-USER-001',
      'IAC-DOCKER-CURLBASH-001',
      'IAC-DOCKER-ADD-001',
      'IAC-DOCKER-SECRET-001',
      'IAC-DOCKER-APTCLEAN-001',
      'IAC-DOCKER-HEALTHCHECK-000',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    // The CloudIaCPosture dimension is scored and explains itself.
    const dim = result.scores.find((s) => s.dimension === 'CloudIaCPosture');
    expect(dim).toBeDefined();
    expect(dim!.why.length).toBeGreaterThan(0);

    // "runs as root" is High severity.
    const rootFinding = result.findings.find((f) => f.ruleId === 'IAC-DOCKER-USER-001');
    expect(rootFinding?.severity).toBe('High');
  });

  it('never leaks the raw secret value into any evidence artifact (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    const files = await fs.readdir(evDir);
    let sawConfigEvidence = false;
    for (const file of files) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('abcd1234secretvalue');
      if (content.includes('API_KEY')) sawConfigEvidence = true;
    }
    expect(sawConfigEvidence).toBe(true); // the secret line WAS captured — just redacted
  });
});
