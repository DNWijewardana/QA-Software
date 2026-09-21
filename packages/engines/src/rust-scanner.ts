/**
 * RustScanner — Rust security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (command injection, SQL injection, memory-safety, crypto), broadening coverage beyond
 * JS/TS/Python/Go/Java/PHP/C#/Ruby.
 *
 * Deterministic (§0.2.2): strips block comments and `//` line comments (tracking only DOUBLE-quoted strings,
 * so Rust lifetimes like `'a` never confuse the stripper), then applies high-signal regexes. The command and
 * SQL rules require a shell/variable/format! signal so benign literal calls (`Command::new("ls")`,
 * `sqlx::query("SELECT 1")`) are not flagged (precision — see docs/09).
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 4;

function isRust(f: ProjectFile): boolean {
  return /\.rs$/i.test(f.path) && !/(^|\/)tests?\//i.test(f.path) && !/_test\.rs$/i.test(f.path);
}

/** Strip a Rust `//` line comment, respecting DOUBLE-quoted strings only (lifetimes use a lone `'`). */
function stripRustLineComment(line: string): string {
  let inStr = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inStr) {
      if (c === '\\') i++;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '/' && line[i + 1] === '/') return line.slice(0, i);
  }
  return line;
}

function stripBlockComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

interface Rule {
  id: string;
  test: (line: string) => boolean;
  title: string;
  severity: Finding['severity'];
  desc: string;
  fix: string;
  cwe: string;
}

const SHELL_CMD = /Command::new\s*\(\s*"(sh|bash|zsh|cmd|powershell)"/;
const VAR_CMD = /Command::new\s*\(\s*&?[a-z_][A-Za-z0-9_]*\s*\)/; // program name from a variable
const SQL_SINK = /(query|query_as|query_scalar|execute)\s*\(\s*&?format!|sqlx::query\w*\s*\(\s*&?format!/;

const RULES: Rule[] = [
  { id: 'RS-COMMAND-EXEC-001', test: (l) => SHELL_CMD.test(l) || VAR_CMD.test(l), title: 'OS command execution (shell or variable program)', severity: 'High',
    desc: 'Command::new invoked with a shell (sh/bash/cmd) or a variable program name enables command injection (CWE-78).',
    fix: 'Invoke a fixed binary with an argument array and validated inputs; never pass a shell or attacker-controlled program.', cwe: 'CWE-78' },
  { id: 'RS-SQL-FORMAT-001', test: (l) => SQL_SINK.test(l), title: 'SQL query built with format!()', severity: 'High',
    desc: 'A SQL query is built with format!() string interpolation, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use parameterised/bind queries (e.g. sqlx::query!("… $1 …", value)), never format!().', cwe: 'CWE-89' },
  { id: 'RS-UNSAFE-001', test: (l) => /\bunsafe\s*\{/.test(l) || /\bunsafe\s+fn\b/.test(l), title: 'Unsafe block (memory-safety escape hatch)', severity: 'Low',
    desc: 'unsafe bypasses Rust’s memory-safety guarantees; misuse can cause undefined behavior / memory corruption (CWE-119).',
    fix: 'Confine unsafe to a small, reviewed, documented block with justified invariants; prefer safe abstractions.', cwe: 'CWE-119' },
  { id: 'RS-WEAK-HASH-001', test: (l) => /\b(Md5|Sha1)::(new|digest)\b/.test(l) || /\bmd5::compute\b/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use SHA-256+ for integrity and a slow KDF (argon2/bcrypt/scrypt/PBKDF2) for passwords.', cwe: 'CWE-327' },
];

export class RustScanner implements Engine {
  readonly name = 'rust-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isRust);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const rustFiles = ctx.files.filter(isRust);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of rustFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripRustLineComment(lines[i]!);
        if (code.trim() === '') continue;
        for (const rule of RULES) {
          if (rule.test(code)) {
            const snippet = redactedSnippet(code);
            const art = addArtifact(`${file.path}:${i}:${rule.id}`, `File: ${file.path}:${i + 1}\n${snippet}`);
            findings.push(this.mk(findingId(rule.id, ordinal++), rule, { file: file.path, line: i + 1 }, art, snippet));
          }
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(rustFiles.length * CHECK_CATEGORIES, 1),
      executedChecks: executed,
      findings,
      artifacts,
    };
  }

  private mk(id: string, rule: Rule, location: Finding['location'], artifactId: string, snippet: string): Finding {
    return {
      id,
      ruleId: rule.id,
      category: 'Security',
      subcategory: 'Rust',
      title: rule.title,
      description: rule.desc,
      status: rule.severity === 'Low' ? 'WARNING' : 'FAIL',
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity: rule.severity,
      risk: rule.severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe: [rule.cwe],
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: rule.fix, effort: 'M', riskReduction: rule.severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Add a test for the untrusted-input path; confirm the unsafe call is removed.',
      standards: [
        { framework: 'OWASP Top 10', version: '2025', id: 'A03-Injection' },
        { framework: 'CWE', version: '4.x', id: rule.cwe },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
