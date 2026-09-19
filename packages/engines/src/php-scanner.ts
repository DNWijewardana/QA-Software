/**
 * PhpScanner — PHP security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, insecure deserialization, file inclusion, XSS, crypto), broadening coverage
 * beyond JS/TS/Python/Go/Java.
 *
 * Deterministic (§0.2.2): strips block comments and quote-aware `//`/`#` line comments, then applies
 * high-signal regexes. Comment-aware stripping avoids flagging patterns that appear only in comments.
 * Negative look-behinds keep method calls (e.g. PDO `$pdo->exec($sql)`) from firing the shell-exec rule.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 7;

function isPhp(f: ProjectFile): boolean {
  return /\.(php|phtml|php[0-9]|phps)$/i.test(f.path);
}

/** Strip a PHP `//` or `#` line comment, respecting "double" and 'single' quotes (and `#[Attribute]`). */
function stripPhpLineComment(line: string): string {
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
    } else if (c === '/' && line[i + 1] === '/') {
      return line.slice(0, i);
    } else if (c === '#' && line[i + 1] !== '[') {
      // `#` is a line comment, but `#[...]` is a PHP 8 attribute — keep those.
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

// A query call built by concatenating (`. $var`) or interpolating (`"...$var..."`) a variable.
const QUERY_CALL = /(mysqli_query|mysql_query|pg_query|->query|->exec)\s*\(/;
const VAR_CONCAT = /\.\s*\$\w+|\$\w+\s*\.|"[^"]*\$\w+[^"]*"/;

const RULES: Rule[] = [
  { id: 'PHP-EVAL-001', test: (l) => /(?<![>:\w])eval\s*\(/.test(l), title: 'Dynamic code execution via eval()', severity: 'High',
    desc: 'eval() executes an arbitrary PHP string; building it from input allows remote code execution (CWE-95).',
    fix: 'Remove eval(); use a safe dispatch table / whitelist instead of executing dynamic code.', cwe: 'CWE-95' },
  { id: 'PHP-SHELL-EXEC-001', test: (l) => /(?<![>:\w])(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/.test(l), title: 'OS command execution', severity: 'High',
    desc: 'system/exec/shell_exec/passthru/proc_open/popen run OS commands; building them from input enables command injection (CWE-78).',
    fix: 'Avoid shelling out; if unavoidable use escapeshellarg() on every argument and pass a fixed command.', cwe: 'CWE-78' },
  { id: 'PHP-SQL-CONCAT-001', test: (l) => QUERY_CALL.test(l) && VAR_CONCAT.test(l), title: 'SQL query built by string concatenation/interpolation', severity: 'High',
    desc: 'A database query is executed from a string built with a variable, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use prepared statements with bound parameters (PDO::prepare / mysqli_prepare), never string building.', cwe: 'CWE-89' },
  { id: 'PHP-UNSERIALIZE-001', test: (l) => /(?<![>:\w])unserialize\s*\(/.test(l), title: 'Insecure deserialization (unserialize)', severity: 'High',
    desc: 'unserialize() on untrusted data enables object injection / property-oriented programming attacks (CWE-502).',
    fix: 'Use json_decode() for untrusted data, or pass ["allowed_classes" => false] to unserialize().', cwe: 'CWE-502' },
  { id: 'PHP-FILE-INCLUSION-001', test: (l) => /\b(include|include_once|require|require_once)\b\s*\(?\s*[^;]*\$\w+/.test(l), title: 'Dynamic file inclusion (LFI/RFI)', severity: 'High',
    desc: 'include/require of a path built from a variable can load attacker-controlled local or remote files (CWE-98).',
    fix: 'Include only fixed paths, or map input through a strict whitelist; never pass raw input to include/require.', cwe: 'CWE-98' },
  { id: 'PHP-XSS-ECHO-001', test: (l) => /\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)\b/.test(l) && !/\b(htmlspecialchars|htmlentities|urlencode|json_encode|intval|filter_var)\s*\(/.test(l), title: 'Reflected XSS (request data echoed unescaped)', severity: 'High',
    desc: 'Request data ($_GET/$_POST/$_REQUEST/$_COOKIE) is echoed without encoding, allowing reflected XSS (CWE-79).',
    fix: 'Encode on output with htmlspecialchars($v, ENT_QUOTES, "UTF-8"); prefer a templating engine with auto-escaping.', cwe: 'CWE-79' },
  { id: 'PHP-WEAK-HASH-001', test: (l) => /(?<![>:\w])(md5|sha1)\s*\(/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use password_hash()/password_verify() for passwords and hash("sha256", …) for integrity.', cwe: 'CWE-327' },
];

export class PhpScanner implements Engine {
  readonly name = 'php-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isPhp);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const phpFiles = ctx.files.filter(isPhp);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of phpFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripPhpLineComment(lines[i]!);
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
      applicableChecks: Math.max(phpFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'PHP',
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
