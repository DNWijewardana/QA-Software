/**
 * Redaction — mandatory secret/PII masking applied BEFORE any evidence is stored or shown.
 * Spec ref: §VIII.10 (never expose secrets/PII), §04 evidence model, §XIII rule 11.
 *
 * The raw value is never written to disk or into any report. We replace it with a typed
 * placeholder and (optionally) report WHAT class was removed — never the value itself.
 */

export interface RedactionPattern {
  /** class label used in the placeholder, e.g. 'aws-access-key'. */
  label: string;
  regex: RegExp;
}

/** Conservative, high-signal patterns. Extended over time; false positives are safer than leaks. */
export const REDACTION_PATTERNS: RedactionPattern[] = [
  { label: 'aws-access-key', regex: /AKIA[0-9A-Z]{16}/g },
  { label: 'aws-secret-key', regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g },
  { label: 'google-api-key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { label: 'slack-token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { label: 'github-token', regex: /gh[pousr]_[0-9A-Za-z]{36,}/g },
  { label: 'jwt', regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  { label: 'private-key-block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { label: 'email', regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { label: 'generic-secret-assignment', regex: /((?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*)(['"]?)([^\s'"]{6,})\2/gi },
];

export interface RedactionResult {
  text: string;
  /** counts of each redacted class — never the values. */
  redactedClasses: Record<string, number>;
  redacted: boolean;
}

/** Redact all known secret/PII patterns from a string. */
export function redact(input: string): RedactionResult {
  let text = input;
  const redactedClasses: Record<string, number> = {};

  for (const { label, regex } of REDACTION_PATTERNS) {
    text = text.replace(regex, (...args: unknown[]) => {
      // generic-secret-assignment keeps the key name, masks only the value (group 3).
      if (label === 'generic-secret-assignment') {
        const prefix = args[1] as string;
        const quote = args[2] as string;
        redactedClasses[label] = (redactedClasses[label] ?? 0) + 1;
        return `${prefix}${quote}«REDACTED:${label}»${quote}`;
      }
      redactedClasses[label] = (redactedClasses[label] ?? 0) + 1;
      return `«REDACTED:${label}»`;
    });
  }

  return {
    text,
    redactedClasses,
    redacted: Object.keys(redactedClasses).length > 0,
  };
}

/** Produce a short, already-redacted snippet around a line for evidence display. */
export function redactedSnippet(line: string, maxLen = 200): string {
  const r = redact(line);
  const t = r.text.trim();
  return t.length > maxLen ? t.slice(0, maxLen) + '…' : t;
}
