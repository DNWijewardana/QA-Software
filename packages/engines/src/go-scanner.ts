/**
 * GoScanner — Go security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, TLS/crypto), broadening coverage beyond JS/TS + Python.
 *
 * Deterministic (§0.2.2): strips Go comments (block, and quote-aware line comments so `//` inside strings
 * is respected), then applies high-signal regexes.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 4;

function isGo(f: ProjectFile): boolean {
  return /\.go$/i.test(f.path) && !/_test\.go$/i.test(f.path);
}

/** Strip a Go `//` line comment, respecting "double", 'rune', and `raw` strings. */
function stripGoLineComment(line: string): string {
  let inStr = false;
  let inRaw = false;
  let strCh = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inRaw) {
      if (c === '`') inRaw = false;
      continue;
    }
    if (inStr) {
      if (c === '\\') i++;
      else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '`') inRaw = true;
    else if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
    } else if (c === '/' && line[i + 1] === '/') {
      return line.slice(0, i);
    }
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

const QUERY_CALL = /\.(Query|Exec|QueryRow)\w*\s*\(/;
const RULES: Rule[] = [
  { id: 'GO-TLS-INSECURE-001', test: (l) => /InsecureSkipVerify\s*:\s*true/.test(l), title: 'TLS certificate verification disabled', severity: 'High',
    desc: 'InsecureSkipVerify: true disables TLS certificate validation, enabling man-in-the-middle attacks (CWE-295).',
    fix: 'Remove InsecureSkipVerify; validate certificates (pin a CA/cert if needed).', cwe: 'CWE-295' },
  { id: 'GO-EXEC-SHELL-001', test: (l) => /exec\.Command\s*\(\s*"(sh|bash|zsh|cmd|powershell)"/.test(l) || (/exec\.Command\s*\(/.test(l) && /"-c"/.test(l)), title: 'Command executed through a shell', severity: 'High',
    desc: 'exec.Command invokes a shell (e.g. sh -c), enabling command injection when arguments are influenced by input (CWE-78).',
    fix: 'Call the program directly with an argument slice; never pass user input through `sh -c`.', cwe: 'CWE-78' },
  { id: 'GO-SQL-CONCAT-001', test: (l) => QUERY_CALL.test(l) && (/"\s*\+|\+\s*"/.test(l) || /fmt\.Sprintf/.test(l)), title: 'SQL query built by string concatenation', severity: 'Medium',
    desc: 'A SQL query is assembled with string concatenation / Sprintf, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use parameterized queries (placeholders + args), never string building.', cwe: 'CWE-89' },
  { id: 'GO-WEAK-HASH-001', test: (l) => /\b(md5|sha1)\.(New|Sum)\b/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2) for passwords.', cwe: 'CWE-327' },
];

export class GoScanner implements Engine {
  readonly name = 'go-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isGo);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const goFiles = ctx.files.filter(isGo);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of goFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripGoLineComment(lines[i]!);
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
      applicableChecks: Math.max(goFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'Go',
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
