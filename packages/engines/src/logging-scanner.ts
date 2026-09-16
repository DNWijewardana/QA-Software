/**
 * LoggingScanner — logging-quality checks (Observability dimension).
 * Spec ref: §V.25 (logging: sensitive-data leakage, structured logging). Flagship check: sensitive data
 * written to logs (CWE-532).
 *
 * Deterministic (§0.2.2): line-based analysis of log calls in JS/TS source. HONEST SCOPE: this covers
 * logging quality only; full observability (metrics/traces coverage, alert-to-runbook linkage, SLIs) needs
 * runtime/config inspection and is out of scope for SAFE_STATIC.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CODE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const CHECK_CATEGORIES = 3;
const LOG_CALL =
  /\b(console\.(?:log|info|warn|error|debug|trace)|(?:logger|log|winston|pino)\.(?:info|warn|error|debug|trace|log|fatal|verbose))\s*\(/;
const SENSITIVE =
  /\b(pass(?:word|wd)?|secret|tokens?|api[_-]?keys?|access[_-]?keys?|private[_-]?keys?|ssn|credit[_-]?card|card[_-]?number|cvv|authorization|auth[_-]?tokens?|session[_-]?ids?)\b/i;
const PII_OBJECT = /\b(req|request)\.(body|headers|params|query)\b|^\s*(user|account|profile|req|request)\s*[),]/;

function isCodeFile(f: ProjectFile): boolean {
  return CODE_EXT.test(f.path) && !/\.(test|spec)\./.test(f.path);
}

export class LoggingScanner implements Engine {
  readonly name = 'logging-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Observability' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isCodeFile);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const codeFiles = ctx.files.filter(isCodeFile);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'log', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of codeFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = content.split(/\r?\n/);
      let consoleCount = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const m = LOG_CALL.exec(line);
        if (!m) continue;
        if (m[1]!.startsWith('console.')) consoleCount++;
        const argText = line.slice(m.index + m[0].length);

        if (SENSITIVE.test(argText)) {
          const art = addArtifact(`${file.path}:${i}:sens`, `File: ${file.path}:${i + 1}\n${redactedSnippet(line)}`);
          findings.push(this.mk(findingId('OBS-LOG-SENSITIVE-001', ordinal++), 'OBS-LOG-SENSITIVE-001', 'Sensitive data written to logs', 'High', 'FAIL',
            { file: file.path, line: i + 1 },
            'A log statement references a sensitive value (password/token/key/PII). Logged secrets and PII persist in log stores and aggregators, where they are broadly readable (CWE-532).',
            art, redactedSnippet(line), 'Never log secrets/PII; log a redacted placeholder or a non-sensitive identifier instead.', ['CWE-532']));
        } else if (PII_OBJECT.test(argText)) {
          const art = addArtifact(`${file.path}:${i}:pii`, `File: ${file.path}:${i + 1}\n${redactedSnippet(line)}`);
          findings.push(this.mk(findingId('OBS-LOG-PII-OBJECT-001', ordinal++), 'OBS-LOG-PII-OBJECT-001', 'Logging a request/user object wholesale', 'Medium', 'FAIL',
            { file: file.path, line: i + 1 },
            'A log statement dumps a whole request/user object, which commonly contains headers, tokens, or PII.',
            art, redactedSnippet(line), 'Log only the specific, non-sensitive fields you need.', ['CWE-532']));
        }
      }

      if (consoleCount > 0) {
        const art = addArtifact(`${file.path}:console`, `File: ${file.path}\nconsole.* used ${consoleCount} time(s).`);
        findings.push(this.mk(findingId('OBS-LOG-CONSOLE-001', ordinal++), 'OBS-LOG-CONSOLE-001', `Uses console.* (${consoleCount}) instead of structured logging`, 'Low', 'WARNING',
          { file: file.path },
          `\`${file.path}\` logs via console.* (${consoleCount} call(s)). Unstructured console output is hard to search, correlate, and control in production.`,
          art, `${file.path}: console.* x${consoleCount}`, 'Use a structured logger with levels and correlation IDs; strip console.* from production builds.', []));
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(codeFiles.length * CHECK_CATEGORIES, 1),
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
    status: Finding['status'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    snippet: string,
    remediation: string,
    cwe: string[],
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Observability',
      subcategory: 'Logging',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: severity === 'High' ? 'Likely' : 'Highly likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'log', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-scan after redacting the log statement; verify logs contain no secret/PII.',
      standards: [
        { framework: 'OWASP Logging', version: 'n/a', id: ruleId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
