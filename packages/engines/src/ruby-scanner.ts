/**
 * RubyScanner — Ruby/Rails security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, insecure deserialization, crypto), broadening coverage beyond
 * JS/TS/Python/Go/Java/PHP/C#.
 *
 * Deterministic (§0.2.2): strips `=begin/=end` block comments and quote-aware `#` line comments (leaving
 * `#{…}` string interpolation intact), then applies high-signal regexes. The command-injection and
 * SQL-injection rules require string interpolation (`#{…}`) / concatenation, so benign literal calls
 * (`system("ls", "-la")`, `where("name = ?", n)`) are not flagged (precision — see docs/09).
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 5;

function isRuby(f: ProjectFile): boolean {
  return /\.rb$/i.test(f.path) && !/(^|\/)(spec|test)\//i.test(f.path) && !/_(spec|test)\.rb$/i.test(f.path);
}

/** Strip a Ruby `#` line comment, respecting "double"/'single' strings and leaving `#{…}` interpolation intact. */
function stripRubyLineComment(line: string): string {
  let inStr = false;
  let strCh = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inStr) {
      if (c === '\\') i++;
      else if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strCh = c;
    } else if (c === '#') {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Strip `=begin … =end` block comments (must start at column 0), preserving newlines. */
function stripRubyBlockComments(s: string): string {
  return s.replace(/^=begin[\s\S]*?^=end[^\n]*/gm, (m) => m.replace(/[^\n]/g, ' '));
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

const CMD_INTERP =
  /`[^`]*#\{|%x[([{][^\n]*#\{|\bsystem\s*\([^)]*#\{|\bexec\s*\([^)]*#\{|(?:IO\.popen|Open3\.\w+)\s*\([^)]*#\{/;
const SQL_SINK = /\.(where|find_by_sql|exists\?|group|order|having|joins|pluck|select)\s*\(\s*"[^"]*#\{|\bexecute\s*\(\s*"[^"]*#\{/;

const RULES: Rule[] = [
  { id: 'RB-EVAL-001', test: (l) => /\beval\s*\(/.test(l) || /\b(?:instance|class|module)_eval\b/.test(l), title: 'Dynamic code execution via eval', severity: 'High',
    desc: 'eval / instance_eval / class_eval execute an arbitrary Ruby string; building it from input allows code injection (CWE-95).',
    fix: 'Remove eval; use a safe dispatch table / whitelist instead of executing dynamic code.', cwe: 'CWE-95' },
  { id: 'RB-COMMAND-EXEC-001', test: (l) => CMD_INTERP.test(l), title: 'OS command injection (interpolated shell command)', severity: 'High',
    desc: 'A shell command (backticks/%x/system/exec/IO.popen/Open3) is built with string interpolation, enabling command injection (CWE-78).',
    fix: 'Pass the command and arguments as a list (e.g. system("cmd", arg1, arg2)); never interpolate input into a shell string.', cwe: 'CWE-78' },
  { id: 'RB-DESERIALIZE-001', test: (l) => /\bMarshal\.(load|restore)\b/.test(l) || /\bYAML\.(unsafe_)?load\s*\(/.test(l), title: 'Insecure deserialization (Marshal/YAML.load)', severity: 'High',
    desc: 'Marshal.load and YAML.load deserialise arbitrary objects and can execute code from untrusted data (CWE-502).',
    fix: 'Use JSON for untrusted data, or YAML.safe_load with an allow-list of permitted classes.', cwe: 'CWE-502' },
  { id: 'RB-SQL-INJECTION-001', test: (l) => SQL_SINK.test(l), title: 'SQL injection via interpolated query', severity: 'High',
    desc: 'An ActiveRecord/SQL query is built with string interpolation, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use parameterised queries — where("name = ?", value) or hash conditions where(name: value).', cwe: 'CWE-89' },
  { id: 'RB-WEAK-HASH-001', test: (l) => /\b(?:OpenSSL::)?Digest::(MD5|SHA1)\b/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2/PBKDF2) for passwords.', cwe: 'CWE-327' },
];

export class RubyScanner implements Engine {
  readonly name = 'ruby-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isRuby);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const rubyFiles = ctx.files.filter(isRuby);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of rubyFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripRubyBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripRubyLineComment(lines[i]!);
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
      applicableChecks: Math.max(rubyFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'Ruby',
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
