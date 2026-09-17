/**
 * CloudFormationScanner test (§V.18). Scans the insecure CloudFormation JSON template and confirms each
 * misconfiguration is detected, the hardcoded secret is redacted, and a secure template + non-CFN JSON
 * yield no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-cloudformation', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('CloudFormationScanner (§V.18 IaC/CSPM)', () => {
  it('detects CloudFormation misconfigurations and redacts secrets', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cfn-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_cfn', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'CFN-S3-PUBLIC-001',
      'CFN-SG-OPEN-001',
      'CFN-UNENCRYPTED-001',
      'CFN-IAM-WILDCARD-001',
      'CFN-SECRET-001',
      'CFN-PUBLIC-IP-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    expect(result.scores.some((s) => s.dimension === 'CloudIaCPosture')).toBe(true);
  });

  it('never leaks the raw secret into evidence (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    for (const file of await fs.readdir(evDir)) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('supersecretpw123');
    }
  });

  it('does not flag a secure template or a non-CloudFormation JSON', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cfn-ok-'));
    await fs.writeFile(
      path.join(dir, 'secure.json'),
      JSON.stringify({
        Resources: {
          Vol: { Type: 'AWS::EC2::Volume', Properties: { Encrypted: true } },
        },
      }),
      'utf8',
    );
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }), 'utf8');
    const result = await runScan({ projectDir: dir, scanId: 'scan_cfn_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('CFN-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
