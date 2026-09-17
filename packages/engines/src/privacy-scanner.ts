/**
 * PrivacyScanner — PII discovery in source (Privacy dimension).
 * Spec ref: §V.16 (PII discovery & mapping, sensitive-data handling), §VIII.10 (never expose PII).
 *
 * Deterministic (§0.2.2) and HIGH-CONFIDENCE: credit-card candidates are validated with the Luhn
 * checksum, SSNs exclude invalid/placeholder ranges, and emails exclude placeholder domains — so false
 * positives are rare. Every detected PII value is REDACTED before it is stored in evidence.
 */

import type { Finding } from '@qa/core';
import { redact } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, isLikelyTextFile, sha256 } from './util.js';

const CHECK_CATEGORIES = 3;
const CARD_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;
const SSN = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
const PLACEHOLDER_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net', 'test.com', 'localhost', 'domain.com', 'email.com',
  'your-domain.com', 'yourcompany.com', 'acme.com', 'sample.com', 'mail.com',
]);

function luhnValid(raw: string): boolean {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function validSsn(area: string, group: string, serial: string): boolean {
  if (area === '000' || area === '666' || area[0] === '9') return false;
  if (group === '00' || serial === '0000') return false;
  if (new Set(area + group + serial).size === 1) return false; // 111-11-1111 etc. — placeholder
  return true;
}

function isScanTarget(f: ProjectFile): boolean {
  const base = f.path.split('/').pop() ?? '';
  if (/(package-lock\.json|pnpm-lock\.yaml|yarn-lock|yarn\.lock)$/.test(base)) return false;
  if (/\.(map|min\.js|min\.css)$/.test(base)) return false;
  return isLikelyTextFile(f.path);
}

/**
 * Redact ALL PII from a line (cards, SSNs, then emails/secrets via the shared redactor), so a finding's
 * evidence never leaks a different PII value that happens to share the line. Uses fresh regexes to avoid
 * interfering with the caller's stateful `exec` loops.
 */
function redactAllPii(line: string): string {
  let out = line.replace(/\b(?:\d[ -]?){13,19}\b/g, (m) => (luhnValid(m) ? '«REDACTED:credit-card»' : m));
  out = out.replace(/\b(\d{3})-(\d{2})-(\d{4})\b/g, (m, a: string, g: string, s: string) =>
    validSsn(a, g, s) ? '«REDACTED:ssn»' : m,
  );
  return redact(out).text;
}

export class PrivacyScanner implements Engine {
  readonly name = 'privacy-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Privacy' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isScanTarget);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const targets = ctx.files.filter(isScanTarget);
    let ordinal = 1;

    const addArtifact = (key: string, redactedContent: string): { id: string; classes: Record<string, number> } => {
      const red = redact(redactedContent); // defence in depth — content is already masked
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content: red.text, contentHash: sha256(red.text), redactedClasses: red.redactedClasses });
      return { id, classes: red.redactedClasses };
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], loc: Finding['location'], desc: string, redactedSnippet: string, fix: string, cwe: string[]) => {
      const art = addArtifact(`${loc.file}:${loc.line}:${rule}`, `File: ${loc.file}:${loc.line ?? '?'}\n${redactedSnippet}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, loc, desc, art.id, redactedSnippet, fix, cwe));
    };

    for (const file of targets) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const loc = (): Finding['location'] => ({ file: file.path, line: i + 1 });

        // credit cards — Luhn-validated
        CARD_CANDIDATE.lastIndex = 0;
        let cm: RegExpExecArray | null;
        while ((cm = CARD_CANDIDATE.exec(line)) !== null) {
          const value = cm[0];
          if (!luhnValid(value)) continue;
          emit('PRIV-PII-CARD-001', 'Credit-card number in source', 'High', loc(),
            'A Luhn-valid credit-card number is hardcoded in source. Storing card data in code is a serious PCI/privacy violation (CWE-312). The value has been redacted.',
            redactAllPii(line), 'Remove the card number; never store PAN in source. Use a tokenized/PCI-compliant vault.', ['CWE-312']);
        }

        // SSNs — valid ranges only
        SSN.lastIndex = 0;
        let sm: RegExpExecArray | null;
        while ((sm = SSN.exec(line)) !== null) {
          if (!validSsn(sm[1]!, sm[2]!, sm[3]!)) continue;
          emit('PRIV-PII-SSN-001', 'Social Security Number in source', 'Medium', loc(),
            'A value matching a US SSN is hardcoded in source. Personal identifiers in code are a privacy exposure (CWE-359). The value has been redacted.',
            redactAllPii(line), 'Remove the SSN from source; handle personal identifiers only in protected, access-controlled stores.', ['CWE-359']);
        }

        // emails — exclude placeholder domains
        EMAIL.lastIndex = 0;
        let em: RegExpExecArray | null;
        while ((em = EMAIL.exec(line)) !== null) {
          const domain = (em[1] ?? '').toLowerCase();
          const local = em[0].split('@')[0]!.toLowerCase();
          if (PLACEHOLDER_DOMAINS.has(domain) || /\.(local|test|example|invalid)$/.test(domain)) continue;
          if (local.startsWith('noreply') || local.startsWith('no-reply')) continue;
          emit('PRIV-PII-EMAIL-001', 'Personal email address in source', 'Informational', loc(),
            'A real-looking email address is hardcoded in source. Confirm it is not personal data and belongs in the repository. The value has been redacted.',
            redactAllPii(line), 'Move contact addresses to configuration; avoid embedding personal emails in code.', []);
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(targets.length * CHECK_CATEGORIES, 1),
      executedChecks: targets.length * CHECK_CATEGORIES,
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
    cwe: string[],
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Privacy',
      subcategory: 'PII',
      title,
      description,
      status: severity === 'Informational' ? 'WARNING' : 'FAIL',
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
      verificationMethod: 'Re-scan after removal; confirm the PII is absent from source and git history.',
      standards: [
        { framework: 'Privacy (GDPR/CCPA context)', version: 'n/a', id: ruleId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
