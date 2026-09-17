/**
 * CloudFormationScanner — AWS CloudFormation template misconfiguration checks (CloudIaCPosture dimension).
 * Spec ref: §V.18 (IaC scanning / CSPM: public buckets, open SGs, unencrypted stores, over-broad IAM).
 *
 * Deterministic (§0.2.2). JSON templates are parsed reliably with JSON.parse; YAML templates are parsed
 * best-effort (CloudFormation's `!Ref`/`!Sub` intrinsic short-forms can defeat a plain YAML parser, in which
 * case the file is skipped rather than mis-analysed). Only files whose `Resources` contain `AWS::*` types are
 * treated as templates, so ordinary JSON/YAML is ignored. Hardcoded secret values are REDACTED in evidence.
 */

import { parse as parseYaml } from 'yaml';
import type { Finding } from '@qa/core';
import { redact } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 6;
const PUBLIC_ACL = new Set(['PublicRead', 'PublicReadWrite']);
const MAX_DEPTH = 25;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function isCandidate(f: ProjectFile): boolean {
  return /\.(ya?ml|json)$/i.test(f.path);
}

function parseTemplate(content: string, path: string): Record<string, unknown> | null {
  try {
    const doc = /\.json$/i.test(path) ? JSON.parse(content) : parseYaml(content);
    return isRecord(doc) ? doc : null;
  } catch {
    return null;
  }
}

function isCloudFormation(doc: Record<string, unknown>): boolean {
  const resources = doc.Resources;
  if (!isRecord(resources)) return false;
  return Object.values(resources).some((r) => isRecord(r) && (str(r.Type)?.startsWith('AWS::') ?? false));
}

interface Hit {
  rule: string;
  title: string;
  severity: Finding['severity'];
  desc: string;
  evidence: string;
  fix: string;
  cwe: string[];
  cis: string;
}

export class CloudFormationScanner implements Engine {
  readonly name = 'cloudformation-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'CloudIaCPosture' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isCandidate);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;
    let templates = 0;

    const addArtifact = (key: string, content: string): string => {
      const red = redact(content);
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content: red.text, contentHash: sha256(red.text), redactedClasses: red.redactedClasses });
      return id;
    };

    for (const file of ctx.files.filter(isCandidate)) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const doc = parseTemplate(content, file.path);
      if (!doc || !isCloudFormation(doc)) continue;
      templates++;

      const hits: Hit[] = [];
      collectHits(doc, hits, 0);
      for (const h of hits) {
        const art = addArtifact(`${file.path}:${h.rule}:${ordinal}`, `File: ${file.path}\n${h.evidence}`);
        findings.push(this.mk(findingId(h.rule, ordinal++), h.rule, h.title, h.severity, { file: file.path }, h.desc, art, h.fix, h.cwe, h.cis));
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: templates * CHECK_CATEGORIES,
      executedChecks: templates * CHECK_CATEGORIES,
      findings,
      artifacts,
      degraded: templates === 0,
      degradedReason: templates === 0 ? 'no CloudFormation template found' : undefined,
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
    remediation: string,
    cwe: string[],
    cisId: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CloudIaC',
      subcategory: 'CloudFormation',
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
      evidence: [{ type: 'configuration', ref: artifactId, redacted: true }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-scan after remediation; validate with a change set in a non-prod account.',
      standards: [
        { framework: 'CIS AWS Foundations', version: 'latest', id: cisId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}

/** Recursively collect misconfiguration hits from a parsed template. */
function collectHits(node: unknown, hits: Hit[], depth: number): void {
  if (depth > MAX_DEPTH) return;
  if (Array.isArray(node)) {
    for (const item of node) collectHits(item, hits, depth + 1);
    return;
  }
  if (!isRecord(node)) return;

  for (const [key, value] of Object.entries(node)) {
    if (key === 'AccessControl' && typeof value === 'string' && PUBLIC_ACL.has(value)) {
      hits.push({ rule: 'CFN-S3-PUBLIC-001', title: 'Public S3 bucket ACL', severity: 'High',
        desc: 'An S3 bucket sets a public AccessControl ACL, exposing its objects to the internet.',
        evidence: `AccessControl: ${value}`, fix: 'Use private ACLs and a PublicAccessBlock configuration.', cwe: ['CWE-284'], cis: 'CIS AWS 2.1.x' });
    }
    if (key === 'CidrIp' && value === '0.0.0.0/0') {
      hits.push({ rule: 'CFN-SG-OPEN-001', title: 'Security group open to 0.0.0.0/0', severity: 'High',
        desc: 'A security group ingress rule allows 0.0.0.0/0 (the whole internet).',
        evidence: 'CidrIp: 0.0.0.0/0', fix: 'Restrict CIDR ranges; never open management ports to the world.', cwe: ['CWE-284'], cis: 'CIS AWS 5.x' });
    }
    if (key === 'Encrypted' && value === false) {
      hits.push({ rule: 'CFN-UNENCRYPTED-001', title: 'Encryption explicitly disabled', severity: 'Medium',
        desc: 'A resource sets Encrypted: false, leaving data at rest unencrypted.',
        evidence: 'Encrypted: false', fix: 'Enable encryption at rest (and a managed KMS key).', cwe: ['CWE-311'], cis: 'CIS AWS 2.2.x' });
    }
    if (key === 'AssociatePublicIpAddress' && value === true) {
      hits.push({ rule: 'CFN-PUBLIC-IP-001', title: 'Instance auto-assigns a public IP', severity: 'Low',
        desc: 'A resource sets AssociatePublicIpAddress: true, placing it directly on the public internet.',
        evidence: 'AssociatePublicIpAddress: true', fix: 'Keep instances in private subnets behind a NAT/load balancer.', cwe: [], cis: 'CIS AWS 5.x' });
    }
    if ((key === 'Action' || key === 'Resource') && isWildcard(value)) {
      hits.push({ rule: 'CFN-IAM-WILDCARD-001', title: `Over-broad IAM ${key} = "*"`, severity: 'High',
        desc: `An IAM policy grants ${key} "*", violating least privilege.`,
        evidence: `${key}: "*"`, fix: 'Scope actions and resources to the minimum required.', cwe: ['CWE-284'], cis: 'CIS AWS 1.x' });
    }
    if (/password/i.test(key) && typeof value === 'string' && value.length >= 6) {
      hits.push({ rule: 'CFN-SECRET-001', title: `Hardcoded secret in template: ${key}`, severity: 'High',
        desc: 'A secret value is hardcoded in the template. It persists in the template and change history. The value has been redacted.',
        evidence: `${key}: «REDACTED:secret»`, fix: 'Reference secrets from AWS Secrets Manager / SSM, never inline literals.', cwe: ['CWE-798'], cis: 'CIS AWS 1.x' });
    }
    collectHits(value, hits, depth + 1);
  }
}

function isWildcard(value: unknown): boolean {
  if (value === '*') return true;
  return Array.isArray(value) && value.some((v) => v === '*');
}
