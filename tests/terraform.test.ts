/**
 * TerraformScanner test (§V.18). Scans the insecure Terraform fixture and confirms each misconfiguration is
 * detected, the hardcoded secret is redacted, the comment mentioning a public ACL is NOT flagged
 * (comment-stripping), and a secure config yields no findings.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-terraform', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('TerraformScanner (§V.18 IaC/CSPM)', () => {
  it('detects Terraform misconfigurations and redacts secrets', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-tf-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_tf', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of [
      'TF-S3-PUBLIC-001',
      'TF-SG-OPEN-001',
      'TF-UNENCRYPTED-001',
      'TF-IAM-WILDCARD-001',
      'TF-SECRET-001',
      'TF-PUBLIC-IP-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // The comment that mentions acl = "public-read" must NOT produce a second S3 finding.
    expect(rules.filter((r) => r === 'TF-S3-PUBLIC-001')).toHaveLength(1);
    expect(result.scores.some((s) => s.dimension === 'CloudIaCPosture')).toBe(true);
  });

  it('never leaks the raw Terraform secret into evidence (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    for (const file of await fs.readdir(evDir)) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('hunter2secretpw');
    }
  });

  it('produces no findings for a secure Terraform config', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-tf-ok-'));
    await fs.writeFile(
      path.join(dir, 'main.tf'),
      [
        'resource "aws_ebs_volume" "vol" {',
        '  encrypted = true',
        '}',
        'resource "aws_security_group" "web" {',
        '  ingress {',
        '    cidr_blocks = ["10.0.0.0/16"]',
        '  }',
        '}',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_tf_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('TF-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
