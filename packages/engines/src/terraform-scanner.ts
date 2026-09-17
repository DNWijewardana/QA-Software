/**
 * TerraformScanner — Terraform (HCL) misconfiguration checks (CloudIaCPosture dimension).
 * Spec ref: §V.18 (IaC scanning / CSPM: public buckets, over-broad IAM, unencrypted stores, open SGs).
 *
 * Deterministic (§0.2.2): regex analysis over `.tf` files after stripping HCL comments (so patterns inside
 * comments don't false-positive). Regex-based (no HCL parser) keeps it dependency-light and predictable;
 * high-signal patterns keep false positives low. Hardcoded secret values are REDACTED in evidence.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 6;
const S3_PUBLIC = /\bacl\s*=\s*"public-read(-write)?"/i;
const SG_OPEN = /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/i;
const UNENCRYPTED = /\bencrypted\s*=\s*false\b/i;
const IAM_WILDCARD = /\b(Action|Resource)\s*[:=]\s*"\*"/;
const TF_SECRET = /\b(password|secret|access_key|secret_key|token|api_key)\s*=\s*"([^"$\n]{6,})"/i;
const PUBLIC_IP = /\bassociate_public_ip_address\s*=\s*true\b/i;

function isTf(f: ProjectFile): boolean {
  return /\.tf$/i.test(f.path);
}

/** Replace HCL comments with spaces (keeping newlines) so line positions are preserved. */
function stripHcl(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(#|\/\/)[^\n]*/g, (m) => ' '.repeat(m.length));
}

export class TerraformScanner implements Engine {
  readonly name = 'terraform-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'CloudIaCPosture' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isTf);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const tfFiles = ctx.files.filter(isTf);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], file: string, line: number, desc: string, snippet: string, fix: string, cwe: string[], cis: string) => {
      const art = addArtifact(`${file}:${line}:${rule}`, `File: ${file}:${line}\n${snippet}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, { file, line }, desc, art, snippet, fix, cwe, cis));
    };

    for (const file of tfFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripHcl(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const n = i + 1;

        if (S3_PUBLIC.test(line)) {
          emit('TF-S3-PUBLIC-001', 'Public S3 bucket ACL', 'High', file.path, n,
            'An S3 bucket ACL is set to public-read/public-read-write, exposing its objects to the internet.',
            redactedSnippet(line), 'Remove the public ACL; use `aws_s3_bucket_public_access_block` to block public access.', ['CWE-284'], 'CIS AWS 2.1.x');
        }
        if (SG_OPEN.test(line)) {
          emit('TF-SG-OPEN-001', 'Security group open to 0.0.0.0/0', 'High', file.path, n,
            'A security group rule allows `0.0.0.0/0` (the whole internet). If this is an ingress rule to a sensitive port it exposes the resource to the world.',
            redactedSnippet(line), 'Restrict CIDR ranges to known sources; never open management ports (22/3389) to 0.0.0.0/0.', ['CWE-284'], 'CIS AWS 5.x');
        }
        if (UNENCRYPTED.test(line)) {
          emit('TF-UNENCRYPTED-001', 'Encryption explicitly disabled', 'Medium', file.path, n,
            'A storage/volume resource sets `encrypted = false`, leaving data at rest unencrypted.',
            redactedSnippet(line), 'Enable encryption at rest (and require a managed KMS key).', ['CWE-311'], 'CIS AWS 2.2.x');
        }
        const iam = IAM_WILDCARD.exec(line);
        if (iam) {
          emit('TF-IAM-WILDCARD-001', `Over-broad IAM ${iam[1]} = "*"`, 'High', file.path, n,
            `An IAM policy grants \`${iam[1]} = "*"\`, violating least privilege and enabling privilege escalation / broad access.`,
            redactedSnippet(line), 'Scope actions and resources to the minimum required ARNs and operations.', ['CWE-284'], 'CIS AWS 1.x');
        }
        const sec = TF_SECRET.exec(line);
        if (sec) {
          const masked = line.replace(sec[2]!, '«REDACTED:secret»');
          emit('TF-SECRET-001', `Hardcoded secret in Terraform: ${sec[1]}`, 'High', file.path, n,
            'A secret value is hardcoded in a Terraform file. It persists in state and version control. The value has been redacted.',
            redactedSnippet(masked), 'Pass secrets via variables from a secrets manager / TF_VAR + a secure backend; never inline literals.', ['CWE-798'], 'CIS AWS 1.x');
        }
        if (PUBLIC_IP.test(line)) {
          emit('TF-PUBLIC-IP-001', 'Instance auto-assigns a public IP', 'Low', file.path, n,
            'A resource sets `associate_public_ip_address = true`, placing it directly on the public internet.',
            redactedSnippet(line), 'Keep instances in private subnets; use a load balancer / NAT for egress.', [], 'CIS AWS 5.x');
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(tfFiles.length * CHECK_CATEGORIES, 1),
      executedChecks: executed,
      findings,
      artifacts,
    };
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    snippet: string,
    remediation: string,
    cwe: string[],
    cisId: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CloudIaC',
      subcategory: 'Terraform',
      title,
      description,
      status: severity === 'Low' ? 'WARNING' : 'FAIL',
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'config',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-scan after remediation; validate with a plan/apply in a non-prod account.',
      standards: [
        { framework: 'CIS AWS Foundations', version: 'latest', id: cisId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
