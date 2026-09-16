/**
 * ErrorHandlingScanner — error-handling quality checks (Reliability dimension).
 * Spec ref: §V.14 (swallowed failures, stack traces exposed to users, error swallowing).
 *
 * Deterministic (§0.2.2): static analysis of JS/TS. Uses conservative brace matching for catch bodies
 * (skips nested-brace bodies rather than risk a miscount) and line regexes for stack exposure / throw.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CODE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const CHECK_CATEGORIES = 4;
const CATCH_RE = /catch\s*(\([^)]*\))?\s*\{/g;
const STACK_SEND = /\.(send|json|end|write)\s*\([^)]*\b(?:err|error|e)\.stack\b/;
const RAW_ERR_SEND = /\.(send|json|end)\s*\(\s*(?:err|error|e)\s*\)/;
const THROW_LITERAL = /\bthrow\s+(['"`]|\{)/;

function isCodeFile(f: ProjectFile): boolean {
  return CODE_EXT.test(f.path) && !/\.(test|spec)\./.test(f.path);
}
function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}
function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line++;
  return line;
}

export class ErrorHandlingScanner implements Engine {
  readonly name = 'error-handling-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Reliability' as const;

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
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], status: Finding['status'], loc: Finding['location'], desc: string, snippet: string, fix: string, cwe: string[]) => {
      const art = addArtifact(`${loc.file}:${loc.line}:${rule}`, `File: ${loc.file}:${loc.line ?? '?'}\n${snippet}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, status, loc, desc, art, snippet, fix, cwe));
    };

    for (const file of codeFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;

      // 1) empty / swallowing catch blocks (conservative brace matching)
      CATCH_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = CATCH_RE.exec(content)) !== null) {
        const braceIdx = m.index + m[0].length - 1;
        const rest = content.slice(braceIdx + 1);
        const closeIdx = rest.indexOf('}');
        if (closeIdx === -1) continue;
        const body = rest.slice(0, closeIdx);
        if (body.includes('{')) continue; // nested body — skip rather than risk a miscount
        const stripped = stripComments(body).trim();
        const line = lineOf(content, m.index);
        if (stripped === '') {
          emit('ERR-EMPTY-CATCH-001', 'Empty catch block swallows errors', 'Medium', 'FAIL', { file: file.path, line },
            'A catch block is empty, so failures are silently swallowed — the system cannot detect, log, or recover from them.',
            'catch { } (empty)', 'Handle, log (without secrets), or rethrow the error; never swallow it.', ['CWE-390']);
        } else if (/console\./.test(stripped) && !/(throw|return|reject|next\s*\(|logger\.)/.test(stripped)) {
          emit('ERR-CATCH-CONSOLE-001', 'Catch only logs to console (error not handled)', 'Low', 'WARNING', { file: file.path, line },
            'A catch block only writes to console and neither rethrows nor handles the error, so the failure is effectively swallowed.',
            redactedSnippet(stripped), 'Rethrow, return an error result, or perform real recovery — not just a console call.', ['CWE-390']);
        }
      }

      // 2) stack trace / raw error exposed to the response, 3) throw non-Error
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (STACK_SEND.test(line) || RAW_ERR_SEND.test(line)) {
          emit('ERR-STACK-EXPOSED-001', 'Error/stack trace sent to the client', 'High', 'FAIL', { file: file.path, line: i + 1 },
            'An error object or stack trace is written to the HTTP response, leaking internal implementation details (paths, versions, logic) to users and attackers (CWE-209).',
            redactedSnippet(line), 'Return a generic error message + correlation id to the client; log details server-side only.', ['CWE-209']);
        }
        if (THROW_LITERAL.test(line)) {
          emit('ERR-THROW-LITERAL-001', 'Throwing a non-Error value', 'Low', 'WARNING', { file: file.path, line: i + 1 },
            'A string or object literal is thrown instead of an Error, losing the stack trace and breaking `instanceof Error` handling.',
            redactedSnippet(line), 'Throw `new Error(message)` (or a subclass).', []);
        }
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
      category: 'Reliability',
      subcategory: 'Error handling',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Add a failing-path test that asserts the error is handled and no internal detail leaks.',
      standards: [
        { framework: 'ISO/IEC 25010', version: '2023', id: 'Reliability' },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
