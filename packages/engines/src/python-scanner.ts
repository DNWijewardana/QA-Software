/**
 * PythonScanner — Python security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, insecure deserialization, crypto), broadening coverage beyond JS/TS.
 *
 * Deterministic (§0.2.2): quote-aware comment stripping per line, then high-signal regexes for well-known
 * dangerous Python patterns. Comment-aware stripping avoids flagging patterns that appear only in comments.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 7;

function isPy(f: ProjectFile): boolean {
  return /\.py$/i.test(f.path) && !/(^|\/)(test_|.*_test)\.py$/i.test(f.path);
}

/** Strip a Python inline/full-line comment, respecting single/double quotes. */
function stripPyComment(line: string): string {
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === '#' && !inS && !inD) return line.slice(0, i);
  }
  return line;
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

const RULES: Rule[] = [
  { id: 'PY-EVAL-001', test: (l) => /\b(eval|exec)\s*\(/.test(l), title: 'Use of eval()/exec()', severity: 'High',
    desc: 'eval()/exec() execute arbitrary code. With any attacker-influenced input this is remote code execution (CWE-95).',
    fix: 'Avoid eval/exec; use ast.literal_eval for data, or explicit parsing/dispatch.', cwe: 'CWE-95' },
  { id: 'PY-OS-SYSTEM-001', test: (l) => /\bos\.system\s*\(/.test(l), title: 'Use of os.system()', severity: 'High',
    desc: 'os.system() runs a string through the shell, enabling command injection (CWE-78).',
    fix: 'Use subprocess with an argument list and shell=False; never build shell strings from input.', cwe: 'CWE-78' },
  { id: 'PY-SUBPROCESS-SHELL-001', test: (l) => /\bshell\s*=\s*True\b/.test(l), title: 'subprocess called with shell=True', severity: 'High',
    desc: 'shell=True runs the command through a shell, enabling command injection when any argument is influenced by input (CWE-78).',
    fix: 'Pass an argument list and keep shell=False (the default).', cwe: 'CWE-78' },
  { id: 'PY-PICKLE-001', test: (l) => /\bc?[Pp]ickle\.loads?\s*\(/.test(l), title: 'Insecure deserialization via pickle', severity: 'High',
    desc: 'pickle.load/loads deserialises arbitrary objects and can execute code from untrusted data (CWE-502).',
    fix: 'Never unpickle untrusted data; use JSON or a safe schema-validated format.', cwe: 'CWE-502' },
  { id: 'PY-YAML-LOAD-001', test: (l) => /\byaml\.load\s*\(/.test(l) && !/Loader\s*=/.test(l), title: 'Unsafe yaml.load() without a safe Loader', severity: 'High',
    desc: 'yaml.load() without an explicit safe Loader can construct arbitrary Python objects from untrusted YAML (CWE-20).',
    fix: 'Use yaml.safe_load() (or Loader=yaml.SafeLoader).', cwe: 'CWE-20' },
  { id: 'PY-FLASK-DEBUG-001', test: (l) => /\brun\s*\([^)]*\bdebug\s*=\s*True/.test(l), title: 'Flask app run with debug=True', severity: 'Medium',
    desc: 'Running with debug=True exposes the Werkzeug interactive debugger (an RCE console) and verbose errors (CWE-489).',
    fix: 'Never enable debug in production; gate it behind an environment flag.', cwe: 'CWE-489' },
  { id: 'PY-WEAK-HASH-001', test: (l) => /\bhashlib\.(md5|sha1)\s*\(/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken. If used for passwords or integrity they are unsafe (CWE-327).',
    fix: 'Use SHA-256+ for integrity, and a slow KDF (bcrypt/scrypt/argon2/PBKDF2) for passwords.', cwe: 'CWE-327' },
];

export class PythonScanner implements Engine {
  readonly name = 'python-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isPy);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const pyFiles = ctx.files.filter(isPy);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of pyFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripPyComment(lines[i]!);
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
      applicableChecks: Math.max(pyFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'Python',
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
      verificationMethod: 'Add a test exercising the untrusted-input path; confirm the unsafe call is removed.',
      standards: [
        { framework: 'OWASP Top 10', version: '2025', id: 'A03-Injection' },
        { framework: 'CWE', version: '4.x', id: rule.cwe },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
