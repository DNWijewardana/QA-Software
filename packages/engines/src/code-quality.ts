/**
 * CodeQualityAnalyzer — lightweight, deterministic maintainability checks (Maintainability dimension).
 * Spec ref: §V.9 (code quality metrics), §VII.6. NOTE (§V.9): "Never treat one metric as complete quality."
 *
 * These are heuristic signals, not a maintainability verdict. AST-based complexity/duplication engines
 * (e.g. an ESLint/Semgrep adapter) plug in later behind the same Engine interface.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CODE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const LONG_FILE_LINES = 400;

export class CodeQualityAnalyzer implements Engine {
  readonly name = 'code-quality';
  readonly version = '0.1.0';
  readonly dimension = 'Maintainability' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some((f) => CODE_EXT.test(f.path));
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const codeFiles = ctx.files.filter((f) => CODE_EXT.test(f.path) && !/\.(test|spec)\./.test(f.path));
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({
        id,
        type: 'source-code',
        content,
        contentHash: sha256(content),
        redactedClasses: {},
      });
      return id;
    };

    for (const file of codeFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed++;
      const lines = content.split(/\r?\n/);

      // 1) Overly long file (maintainability signal).
      if (lines.length > LONG_FILE_LINES) {
        const artId = addArtifact(`${file.path}:len`, `File ${file.path} has ${lines.length} lines.`);
        findings.push(
          this.mk(findingId('MNT-LONGFILE-001', ordinal++), 'MNT-LONGFILE-001', 'Overly long file', 'Low', 'WARNING', {
            file: file.path,
          }, `\`${file.path}\` has ${lines.length} lines (> ${LONG_FILE_LINES}). Large files are harder to test and maintain; consider splitting by responsibility.`, artId, `${file.path}: ${lines.length} lines`, 'Split into smaller, cohesive modules.'),
        );
      }

      // 2) TODO/FIXME markers (tech-debt density).
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (/\b(TODO|FIXME|HACK|XXX)\b/.test(line)) {
          const artId = addArtifact(`${file.path}:${i}:todo`, `File: ${file.path}:${i + 1}\n${redactedSnippet(line)}`);
          findings.push(
            this.mk(findingId('MNT-TODO-001', ordinal++), 'MNT-TODO-001', 'Tech-debt marker (TODO/FIXME)', 'Informational', 'WARNING', {
              file: file.path,
              line: i + 1,
            }, 'A tech-debt marker indicates known incomplete or fragile code. Track and resolve it.', artId, redactedSnippet(line), 'Resolve the marked item or convert it into a tracked issue.'),
          );
        }
        // 3) `var` usage in JS/TS (prefer let/const).
        if (/(^|[^.\w])var\s+[A-Za-z_$]/.test(line)) {
          const artId = addArtifact(`${file.path}:${i}:var`, `File: ${file.path}:${i + 1}\n${redactedSnippet(line)}`);
          findings.push(
            this.mk(findingId('MNT-VAR-001', ordinal++), 'MNT-VAR-001', "Use of 'var'", 'Low', 'WARNING', {
              file: file.path,
              line: i + 1,
            }, "`var` has function scope and hoisting pitfalls. Prefer `let`/`const`.", artId, redactedSnippet(line), "Replace `var` with `const` (or `let` if reassigned)."),
          );
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(codeFiles.length, 1),
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
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Maintainability',
      subcategory: 'Code smell',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe: [],
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: remediation, effort: 'S', riskReduction: 'Low' },
      verificationMethod: 'Re-run static analysis after refactor.',
      standards: [{ framework: 'ISO/IEC 25010', version: '2023', id: 'Maintainability' }],
      traceability: { requirements: [], tests: [] },
    };
  }
}
