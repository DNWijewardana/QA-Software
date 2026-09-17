/**
 * JavaScanner — Java security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, insecure deserialization, crypto), broadening coverage beyond JS/TS/Python/Go.
 *
 * Deterministic (§0.2.2): strips block comments and quote-aware `//` line comments, then applies high-signal
 * regexes. Comment-aware stripping avoids flagging patterns that appear only in comments.
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 5;

function isJava(f: ProjectFile): boolean {
  return /\.java$/i.test(f.path);
}

/** Strip a Java `//` line comment, respecting "double" and 'char' literals. */
function stripJavaLineComment(line: string): string {
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

const EXEC_CALL = /\.(execute|executeQuery|executeUpdate)\s*\(/;
const RULES: Rule[] = [
  { id: 'JAVA-RUNTIME-EXEC-001', test: (l) => /Runtime\.getRuntime\(\)\.exec\s*\(/.test(l), title: 'Command execution via Runtime.exec()', severity: 'High',
    desc: 'Runtime.getRuntime().exec() runs an external command; building it from input enables command injection (CWE-78).',
    fix: 'Use ProcessBuilder with an argument list and validated inputs; never build a shell string.', cwe: 'CWE-78' },
  { id: 'JAVA-SQL-CONCAT-001', test: (l) => EXEC_CALL.test(l) && (/"\s*\+|\+\s*"/.test(l) || /String\.format/.test(l)), title: 'SQL query built by string concatenation', severity: 'High',
    desc: 'A JDBC statement is executed from a concatenated/formatted string, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use PreparedStatement with parameter placeholders (?), never string building.', cwe: 'CWE-89' },
  { id: 'JAVA-DESERIALIZE-001', test: (l) => /\.readObject\s*\(/.test(l), title: 'Insecure Java deserialization (readObject)', severity: 'High',
    desc: 'ObjectInputStream.readObject() deserialises arbitrary objects and can execute code from untrusted data (CWE-502).',
    fix: 'Avoid native serialization for untrusted data; use JSON with a strict schema, or an allow-list ObjectInputFilter.', cwe: 'CWE-502' },
  { id: 'JAVA-WEAK-HASH-001', test: (l) => /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"/i.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use SHA-256+ for integrity and a slow KDF (bcrypt/scrypt/argon2/PBKDF2) for passwords.', cwe: 'CWE-327' },
  { id: 'JAVA-ECB-001', test: (l) => /Cipher\.getInstance\s*\(\s*"[^"]*(ECB|DES)/i.test(l), title: 'Weak cipher/mode (ECB or DES)', severity: 'Medium',
    desc: 'ECB mode leaks plaintext structure and DES is broken; both are insecure for confidentiality (CWE-327).',
    fix: 'Use AES-GCM (authenticated encryption) with a random IV/nonce.', cwe: 'CWE-327' },
];

export class JavaScanner implements Engine {
  readonly name = 'java-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isJava);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const javaFiles = ctx.files.filter(isJava);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of javaFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripJavaLineComment(lines[i]!);
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
      applicableChecks: Math.max(javaFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'Java',
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
