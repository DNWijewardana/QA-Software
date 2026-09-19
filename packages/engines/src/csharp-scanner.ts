/**
 * CSharpScanner — C#/.NET security anti-pattern checks (Security dimension).
 * Spec ref: §V.7 (injection, insecure deserialization, transport security, crypto), broadening coverage
 * beyond JS/TS/Python/Go/Java/PHP.
 *
 * Deterministic (§0.2.2): strips block comments and quote-aware `//` line comments, then applies high-signal
 * regexes. Injection rules require a concrete signal (concatenation / interpolation / String.Format) so a
 * benign literal call (e.g. `Process.Start("notepad.exe")`) is not flagged (precision — see docs/09).
 */

import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 6;

function isCSharp(f: ProjectFile): boolean {
  return /\.cs$/i.test(f.path);
}

/** Strip a C# `//` line comment, respecting "double" and 'char' literals. */
function stripCsLineComment(line: string): string {
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

// A string built by concatenation (`" +`) or interpolation (`$"`) or String.Format.
const BUILT_STRING = /"\s*\+|\+\s*"|\$@?"|String\.Format\s*\(/;
const SQL_SINK = /(new\s+(Sql|MySql|Npgsql|Oracle|Sqlite)Command)\s*\(|\.CommandText\s*=/;

const RULES: Rule[] = [
  { id: 'CS-PROCESS-START-001', test: (l) => /Process\.Start\s*\(/.test(l) && BUILT_STRING.test(l), title: 'OS command execution via Process.Start', severity: 'High',
    desc: 'Process.Start with a command built from input enables OS command injection (CWE-78).',
    fix: 'Pass a fixed file name and an argument array via ProcessStartInfo (UseShellExecute=false); never build a shell string.', cwe: 'CWE-78' },
  { id: 'CS-SQL-CONCAT-001', test: (l) => SQL_SINK.test(l) && BUILT_STRING.test(l), title: 'SQL query built by string concatenation/interpolation', severity: 'High',
    desc: 'A SqlCommand/CommandText is built from a concatenated or interpolated string, which is vulnerable to SQL injection (CWE-89).',
    fix: 'Use parameterised queries (SqlParameter / command.Parameters.AddWithValue), never string building.', cwe: 'CWE-89' },
  { id: 'CS-DESERIALIZE-001', test: (l) => /\b(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)\b/.test(l), title: 'Insecure deserialization formatter', severity: 'High',
    desc: 'BinaryFormatter/SoapFormatter/NetDataContractSerializer and similar deserialise arbitrary types and can execute code from untrusted data (CWE-502).',
    fix: 'Do not use these formatters for untrusted data; use System.Text.Json / DataContractJsonSerializer with known types.', cwe: 'CWE-502' },
  { id: 'CS-CERT-VALIDATION-001', test: (l) => /ServerCertificateValidationCallback\b[^;]*=>\s*true\b/.test(l) || /DangerousAcceptAnyServerCertificateValidator/.test(l), title: 'TLS certificate validation disabled', severity: 'High',
    desc: 'Accepting any server certificate disables TLS authentication and enables man-in-the-middle attacks (CWE-295).',
    fix: 'Remove the override; validate the certificate chain, or pin the expected certificate/public key.', cwe: 'CWE-295' },
  { id: 'CS-WEAK-CIPHER-001', test: (l) => /\b(DES|TripleDES)\s*\.\s*Create\s*\(/.test(l) || /new\s+(DESCryptoServiceProvider|TripleDESCryptoServiceProvider)\s*\(/.test(l) || /CipherMode\.ECB/.test(l), title: 'Weak cipher/mode (DES/3DES or ECB)', severity: 'Medium',
    desc: 'DES/3DES are broken and ECB mode leaks plaintext structure; both are insecure for confidentiality (CWE-327).',
    fix: 'Use AES-GCM (authenticated encryption) with a random nonce; avoid ECB.', cwe: 'CWE-327' },
  { id: 'CS-WEAK-HASH-001', test: (l) => /\b(MD5|SHA1)\s*\.\s*Create\s*\(/.test(l) || /new\s+(MD5|SHA1)(CryptoServiceProvider|Managed)\s*\(/.test(l), title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'Low',
    desc: 'MD5/SHA-1 are cryptographically broken; unsafe for passwords or integrity (CWE-327).',
    fix: 'Use SHA-256+ for integrity and a slow KDF (PBKDF2/Rfc2898DeriveBytes, bcrypt, argon2) for passwords.', cwe: 'CWE-327' },
];

export class CSharpScanner implements Engine {
  readonly name = 'csharp-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isCSharp);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const csFiles = ctx.files.filter(isCSharp);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of csFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const lines = stripBlockComments(content).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const code = stripCsLineComment(lines[i]!);
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
      applicableChecks: Math.max(csFiles.length * CHECK_CATEGORIES, 1),
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
      subcategory: 'C#',
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
