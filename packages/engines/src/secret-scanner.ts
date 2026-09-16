/**
 * SecretScanner — detects hardcoded secrets/credentials in source (Security dimension).
 * Spec ref: §V.7 (Secrets), §VIII.10 (safe redaction — NEVER expose secrets in reports).
 *
 * Deterministic (§0.2.2): pure regex/AST-free scan; every finding carries redacted evidence.
 * The raw secret value is NEVER stored — only a redacted snippet + the class of secret.
 */

import { redact, redactedSnippet, REDACTION_PATTERNS, type Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ScanContext } from './types.js';
import { findingId, isLikelyTextFile, sha256 } from './util.js';

const RULE = 'SEC-SECRET-001';

/** Map a redaction class to CWE + severity. Hardcoded credentials => CWE-798. */
function classToMeta(label: string): { cwe: string; severity: Finding['severity']; kind: string } {
  switch (label) {
    case 'private-key-block':
      return { cwe: 'CWE-321', severity: 'Critical', kind: 'hardcoded private key' };
    case 'aws-access-key':
    case 'aws-secret-key':
    case 'google-api-key':
    case 'github-token':
    case 'slack-token':
      return { cwe: 'CWE-798', severity: 'Critical', kind: `hardcoded ${label}` };
    case 'jwt':
      return { cwe: 'CWE-522', severity: 'High', kind: 'embedded JWT' };
    case 'generic-secret-assignment':
      return { cwe: 'CWE-798', severity: 'High', kind: 'hardcoded credential assignment' };
    default:
      return { cwe: 'CWE-200', severity: 'Medium', kind: `possible ${label}` };
  }
}

export class SecretScanner implements Engine {
  readonly name = 'secret-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(): boolean {
    return true; // secrets can hide in any text file
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const textFiles = ctx.files.filter((f) => isLikelyTextFile(f.path));
    let ordinal = 1;

    for (const file of textFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        for (const { label, regex } of REDACTION_PATTERNS) {
          // email alone is PII, not necessarily a secret — skip for the security engine.
          if (label === 'email') continue;
          regex.lastIndex = 0;
          if (!regex.test(line)) continue;

          const meta = classToMeta(label);
          const snippet = redactedSnippet(line);
          const artifactId = `ev-${sha256(`${file.path}:${i}:${label}`).slice(0, 16)}`;
          const evContent = `File: ${file.path}:${i + 1}\n${snippet}`;
          const red = redact(evContent);
          artifacts.push({
            id: artifactId,
            type: 'source-code',
            content: red.text,
            contentHash: sha256(red.text),
            redactedClasses: red.redactedClasses,
          });

          findings.push({
            id: findingId(RULE, ordinal++),
            ruleId: RULE,
            category: 'Security',
            subcategory: 'Secrets',
            title: `Detected ${meta.kind}`,
            description: `A ${meta.kind} was detected in source. Hardcoded secrets can be extracted from the repository and reused by attackers. The value has been redacted in all evidence.`,
            status: 'FAIL',
            evidenceClass: 'AUTOMATICALLY_DETECTED',
            severity: meta.severity,
            risk: meta.severity,
            confidence: 'Highly likely',
            reproducibility: 'Always',
            cwe: [meta.cwe],
            cve: [],
            affectedComponent: file.path,
            location: { file: file.path, line: i + 1 },
            detectionMethod: 'static',
            toolUsed: `${this.name}@${this.version}`,
            evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet: red.text }],
            remediation: {
              summary:
                'Remove the secret from source, rotate it immediately, and load it at runtime from a secrets manager / environment variable.',
              effort: 'S',
              riskReduction: 'High',
            },
            verificationMethod:
              'Re-scan after removal; confirm the secret is absent from git history and has been rotated.',
            standards: [
              { framework: 'OWASP Top 10', version: '2025', id: 'A05-Security-Misconfiguration' },
              { framework: 'CWE', version: '4.x', id: meta.cwe },
            ],
            traceability: { requirements: [], tests: [] },
          });
        }
      }
    }

    // Coverage: one "check" per scanned text file (honest denominator).
    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(textFiles.length, 1),
      executedChecks: textFiles.length,
      findings,
      artifacts,
    };
  }
}
