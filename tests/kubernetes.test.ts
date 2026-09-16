/**
 * KubernetesScanner test (§V.18, CIS Kubernetes Benchmark / Pod Security Standards). Scans the
 * intentionally-insecure Deployment fixture and confirms each seeded misconfiguration is detected.
 * Isolated fixture — existing tests are unaffected.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-k8s', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('KubernetesScanner (CIS / Pod Security Standards)', () => {
  it('detects every seeded workload misconfiguration', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-k8s-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_k8s', evidenceDir: path.join(tmp, 'ev') });

    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'IAC-K8S-HOSTNS-001',
      'IAC-K8S-HOSTPATH-001',
      'IAC-K8S-SATOKEN-001',
      'IAC-K8S-PRIV-001',
      'IAC-K8S-PRIVESC-001',
      'IAC-K8S-ROOT-001',
      'IAC-K8S-CAP-001',
      'IAC-K8S-ROFS-001',
      'IAC-K8S-LIMITS-001',
      'IAC-K8S-IMGTAG-001',
      'IAC-K8S-PROBES-000',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    // Privileged container is Critical → release blocked.
    const priv = result.findings.find((f) => f.ruleId === 'IAC-K8S-PRIV-001');
    expect(priv?.severity).toBe('Critical');
    expect(result.overall.criticalBlockers).toBeGreaterThan(0);
    expect(result.releaseDecision.decision).toBe('NO_GO');

    // CloudIaCPosture dimension is scored and explains itself.
    const dim = result.scores.find((s) => s.dimension === 'CloudIaCPosture');
    expect(dim).toBeDefined();
    expect(dim!.why.length).toBeGreaterThan(0);
  });

  it('does not flag non-workload YAML', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-k8s-plain-'));
    await fs.writeFile(path.join(dir, 'config.yaml'), 'name: build\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n', 'utf8');
    const result = await runScan({ projectDir: dir, scanId: 'scan_plain', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('IAC-K8S-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
