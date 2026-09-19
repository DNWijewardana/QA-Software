/**
 * Golden test corpus — ground truth (§X.3). For each intentionally-flawed fixture, the set of rule IDs the
 * platform MUST detect (the seeded defects), and the non-seeded rule IDs that legitimately also fire on that
 * fixture (real incidental issues, NOT false positives). Detection effectiveness is measured against this (§X.4).
 *
 * This fully labels the corpus so BOTH recall and precision can be measured honestly:
 *  - `expected` = seeded defects → RECALL (did we find every known defect?).
 *  - `expected` ∪ `allowedExtra` ∪ GLOBAL_ALLOWED = every rule that is *correct* to fire here → any detection
 *    outside that set is a candidate FALSE POSITIVE → PRECISION.
 *
 * Every `allowedExtra` entry is a genuine issue present in the fixture (verified), not a mislabel used to
 * inflate precision. Each engine additionally has its own clean-input "no findings" test, which is the
 * independent guard that rules do not mis-fire on safe code. A NEW, unaccounted detection appearing here
 * fails the precision gate and forces a human to classify it (seeded? legitimately incidental? or a real FP
 * to fix) — a precision regression is itself a quality gate (§X.4).
 */

export interface CorpusEntry {
  fixture: string;
  /** Seeded defects that MUST be detected (recall). */
  expected: string[];
  /** Non-seeded rule IDs that legitimately also fire on this fixture (real issues, not false positives). */
  allowedExtra?: string[];
}

/**
 * Rule IDs that legitimately fire on essentially every fixture and are not false positives. Each corpus
 * fixture is a minimal directory with no README/LICENSE, so the Informational config/docs hygiene checks
 * fire everywhere; counting them as false positives would be dishonest.
 */
export const GLOBAL_ALLOWED: string[] = ['DOC-README-001', 'DOC-LICENSE-001'];

export const GOLDEN_CORPUS: CorpusEntry[] = [
  {
    fixture: 'vulnerable-sample',
    expected: ['SEC-SECRET-001', 'MNT-VAR-001', 'MNT-TODO-001', 'SUP-LOCK-001', 'SUP-PIN-001', 'SUP-VULN-000'],
    // package.json declares no license field → LicenseScanner legitimately reports it.
    allowedExtra: ['LIC-MISSING-001'],
  },
  {
    fixture: 'insecure-docker',
    expected: ['IAC-DOCKER-TAG-001', 'IAC-DOCKER-USER-001', 'IAC-DOCKER-CURLBASH-001', 'IAC-DOCKER-ADD-001', 'IAC-DOCKER-SECRET-001', 'IAC-DOCKER-APTCLEAN-001', 'IAC-DOCKER-HEALTHCHECK-000'],
    // The seeded ENV secret is also (correctly) caught by the generic secret-scanner.
    allowedExtra: ['SEC-SECRET-001'],
  },
  {
    fixture: 'insecure-k8s',
    expected: ['IAC-K8S-HOSTNS-001', 'IAC-K8S-HOSTPATH-001', 'IAC-K8S-SATOKEN-001', 'IAC-K8S-PRIV-001', 'IAC-K8S-PRIVESC-001', 'IAC-K8S-ROOT-001', 'IAC-K8S-CAP-001', 'IAC-K8S-ROFS-001', 'IAC-K8S-LIMITS-001', 'IAC-K8S-IMGTAG-001', 'IAC-K8S-PROBES-000'],
  },
  {
    fixture: 'insecure-compose',
    expected: ['IAC-COMPOSE-PRIV-001', 'IAC-COMPOSE-DOCKERSOCK-001', 'IAC-COMPOSE-HOSTMOUNT-001', 'IAC-COMPOSE-HOSTNET-001', 'IAC-COMPOSE-CAP-001', 'IAC-COMPOSE-IMGTAG-001', 'IAC-COMPOSE-SECRET-001', 'IAC-COMPOSE-NNP-001'],
    // The seeded env secret is also (correctly) caught by the generic secret-scanner.
    allowedExtra: ['SEC-SECRET-001'],
  },
  {
    fixture: 'insecure-openapi',
    expected: ['API-SPEC-NOAUTH-001', 'API-SPEC-OP-NOAUTH-001', 'API-SPEC-HTTP-001', 'API-SPEC-APIKEY-QUERY-001', 'API-SPEC-NO-ERRORS-001', 'API-SPEC-NO-OPID-001'],
  },
  {
    fixture: 'inaccessible-html',
    expected: ['A11Y-IMG-ALT-001', 'A11Y-HTML-LANG-001', 'A11Y-TITLE-001', 'A11Y-INPUT-LABEL-001', 'A11Y-BUTTON-NAME-001', 'A11Y-LINK-NAME-001', 'A11Y-TABINDEX-001', 'A11Y-IFRAME-TITLE-001', 'A11Y-VIEWPORT-001'],
    // The inaccessible page also genuinely lacks SEO essentials (title/meta/canonical/OG/h1/robots/sitemap).
    allowedExtra: ['SEO-TITLE-001', 'SEO-META-DESC-001', 'SEO-CANONICAL-001', 'SEO-H1-001', 'SEO-OG-001', 'SEO-ROBOTSTXT-001', 'SEO-SITEMAP-001'],
  },
  {
    fixture: 'seo-issues',
    expected: ['SEO-TITLE-001', 'SEO-META-DESC-001', 'SEO-CANONICAL-001', 'SEO-ROBOTS-NOINDEX-001', 'SEO-H1-001', 'SEO-OG-001', 'SEO-VIEWPORT-001', 'SEO-ROBOTSTXT-001', 'SEO-SITEMAP-001'],
    // The page also has no <title>, which is a WCAG 2.4.2 accessibility issue as well as an SEO one.
    allowedExtra: ['A11Y-TITLE-001'],
  },
  {
    fixture: 'insecure-logging',
    expected: ['OBS-LOG-SENSITIVE-001', 'OBS-LOG-PII-OBJECT-001', 'OBS-LOG-CONSOLE-001'],
  },
  {
    fixture: 'bad-error-handling',
    expected: ['ERR-EMPTY-CATCH-001', 'ERR-CATCH-CONSOLE-001', 'ERR-STACK-EXPOSED-001', 'ERR-THROW-LITERAL-001'],
    // The fixture genuinely uses console.* logging, which the logging engine correctly flags.
    allowedExtra: ['OBS-LOG-CONSOLE-001'],
  },
  {
    fixture: 'pii-in-source',
    expected: ['PRIV-PII-CARD-001', 'PRIV-PII-SSN-001', 'PRIV-PII-EMAIL-001'],
  },
  {
    fixture: 'insecure-cicd',
    expected: ['CI-SCRIPT-INJECTION-001', 'CI-PR-TARGET-001', 'CI-ACTION-UNPINNED-001', 'CI-SECRET-ECHO-001', 'CI-PERMISSIONS-000', 'CI-ACTION-TAG-001'],
  },
  {
    fixture: 'dangerous-migration',
    expected: ['SQL-DROP-TABLE-001', 'SQL-DROP-COLUMN-001', 'SQL-TRUNCATE-001', 'SQL-DELETE-NO-WHERE-001', 'SQL-UPDATE-NO-WHERE-001', 'SQL-NOTNULL-NO-DEFAULT-001'],
  },
  {
    fixture: 'sql-with-secrets',
    expected: ['SEC-SECRET-001', 'PRIV-PII-EMAIL-001', 'PRIV-PII-CARD-001'],
  },
  {
    fixture: 'insecure-terraform',
    expected: ['TF-S3-PUBLIC-001', 'TF-SG-OPEN-001', 'TF-IAM-WILDCARD-001', 'TF-SECRET-001', 'TF-UNENCRYPTED-001', 'TF-PUBLIC-IP-001'],
  },
  {
    fixture: 'insecure-cloudformation',
    expected: ['CFN-S3-PUBLIC-001', 'CFN-SG-OPEN-001', 'CFN-UNENCRYPTED-001', 'CFN-IAM-WILDCARD-001', 'CFN-SECRET-001', 'CFN-PUBLIC-IP-001'],
  },
  {
    fixture: 'insecure-python',
    expected: ['PY-EVAL-001', 'PY-OS-SYSTEM-001', 'PY-SUBPROCESS-SHELL-001', 'PY-PICKLE-001', 'PY-YAML-LOAD-001', 'PY-FLASK-DEBUG-001', 'PY-WEAK-HASH-001'],
  },
  {
    fixture: 'insecure-go',
    expected: ['GO-TLS-INSECURE-001', 'GO-EXEC-SHELL-001', 'GO-SQL-CONCAT-001', 'GO-WEAK-HASH-001'],
  },
  {
    fixture: 'insecure-java',
    expected: ['JAVA-RUNTIME-EXEC-001', 'JAVA-SQL-CONCAT-001', 'JAVA-DESERIALIZE-001', 'JAVA-ECB-001', 'JAVA-WEAK-HASH-001'],
  },
  {
    fixture: 'insecure-php',
    expected: ['PHP-EVAL-001', 'PHP-SHELL-EXEC-001', 'PHP-SQL-CONCAT-001', 'PHP-UNSERIALIZE-001', 'PHP-FILE-INCLUSION-001', 'PHP-XSS-ECHO-001', 'PHP-WEAK-HASH-001'],
  },
  {
    fixture: 'insecure-csharp',
    expected: ['CS-PROCESS-START-001', 'CS-SQL-CONCAT-001', 'CS-DESERIALIZE-001', 'CS-CERT-VALIDATION-001', 'CS-WEAK-CIPHER-001', 'CS-WEAK-HASH-001'],
  },
];
