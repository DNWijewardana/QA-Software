/**
 * SqlMigrationScanner — destructive / unsafe SQL migration checks (Reliability dimension).
 * Spec ref: §V.31 (flag destructive migrations), §V.11 (database quality).
 *
 * Deterministic (§0.2.2): strips SQL comments (preserving line numbers), splits on statement boundaries,
 * and classifies each statement. Comment stripping + statement-scoped WHERE checks keep false positives low.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 6;

function isSql(f: ProjectFile): boolean {
  return /\.sql$/i.test(f.path);
}

/** Replace comments with spaces (keeping newlines) so statement/line positions are preserved. */
function stripSqlComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
}

interface Statement {
  text: string;
  startIndex: number;
}

/** Split into `;`-terminated statements, recording each statement's first non-whitespace index. */
function splitStatements(clean: string): Statement[] {
  const out: Statement[] = [];
  let start = 0;
  const push = (from: number, to: number) => {
    const seg = clean.slice(from, to);
    if (seg.trim() === '') return;
    const rel = seg.search(/\S/);
    out.push({ text: seg.trim(), startIndex: from + (rel < 0 ? 0 : rel) });
  };
  for (let i = 0; i < clean.length; i++) {
    if (clean[i] === ';') {
      push(start, i);
      start = i + 1;
    }
  }
  push(start, clean.length);
  return out;
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === '\n') line++;
  return line;
}

export class SqlMigrationScanner implements Engine {
  readonly name = 'sql-migration-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Reliability' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isSql);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const sqlFiles = ctx.files.filter(isSql);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], file: string, line: number, desc: string, snippet: string, fix: string) => {
      const art = addArtifact(`${file}:${line}:${rule}`, `File: ${file}:${line}\n${snippet}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, { file, line }, desc, art, snippet, fix));
    };

    for (const file of sqlFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const clean = stripSqlComments(content);
      for (const stmt of splitStatements(clean)) {
        const t = stmt.text;
        const line = lineOf(content, stmt.startIndex);
        const snip = redactedSnippet(t);

        if (/\bDROP\s+TABLE\b/i.test(t)) {
          emit('SQL-DROP-TABLE-001', 'Destructive migration: DROP TABLE', 'High', file.path, line,
            'The migration drops a table, permanently deleting its data. If deployed forward without a verified backup/rollback it is irreversible.',
            snip, 'Confirm a backup + a tested rollback; consider a soft-deprecate (rename) step before dropping.');
        }
        if (/\bDROP\s+COLUMN\b/i.test(t)) {
          emit('SQL-DROP-COLUMN-001', 'Destructive migration: DROP COLUMN', 'High', file.path, line,
            'The migration drops a column, permanently deleting its data and potentially breaking older running app versions.',
            snip, 'Deploy in phases: stop writing the column, verify, then drop in a later migration.');
        }
        if (/\bTRUNCATE\b/i.test(t)) {
          emit('SQL-TRUNCATE-001', 'Destructive migration: TRUNCATE', 'High', file.path, line,
            'TRUNCATE removes all rows from a table (and is usually non-transactional / non-rollbackable).',
            snip, 'Avoid TRUNCATE in migrations; if required, guard with backups and explicit approval.');
        }
        if (/\bDELETE\s+FROM\b/i.test(t) && !/\bWHERE\b/i.test(t)) {
          emit('SQL-DELETE-NO-WHERE-001', 'DELETE without a WHERE clause', 'High', file.path, line,
            'A DELETE statement has no WHERE clause, so it removes every row in the table.',
            snip, 'Add a WHERE clause; never issue an unbounded DELETE in a migration.');
        }
        if (/^\s*UPDATE\b/i.test(t) && !/\bWHERE\b/i.test(t)) {
          emit('SQL-UPDATE-NO-WHERE-001', 'UPDATE without a WHERE clause', 'High', file.path, line,
            'An UPDATE statement has no WHERE clause, so it rewrites every row in the table.',
            snip, 'Add a WHERE clause to scope the update.');
        }
        if (/\bADD\s+COLUMN\b/i.test(t) && /\bNOT\s+NULL\b/i.test(t) && !/\bDEFAULT\b/i.test(t)) {
          emit('SQL-NOTNULL-NO-DEFAULT-001', 'ADD COLUMN NOT NULL without a DEFAULT', 'Medium', file.path, line,
            'Adding a NOT NULL column without a DEFAULT fails on any table that already has rows, and can take a long/locking rewrite on large tables.',
            snip, 'Add the column as nullable (or with a DEFAULT), backfill, then add the NOT NULL constraint.');
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(sqlFiles.length * CHECK_CATEGORIES, 1),
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
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Reliability',
      subcategory: 'DB migration',
      title,
      description,
      status: severity === 'Medium' ? 'WARNING' : 'FAIL',
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
      remediation: { summary: remediation, effort: 'M', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Rehearse the migration (and its rollback) against a production-like copy with a backup.',
      standards: [{ framework: 'DB migration safety', version: 'n/a', id: ruleId }, { framework: 'ISO/IEC 25010', version: '2023', id: 'Reliability' }],
      traceability: { requirements: [], tests: [] },
    };
  }
}
