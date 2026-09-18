/**
 * Golden test corpus — ground truth (§X.3). For each intentionally-flawed fixture, the set of rule IDs the
 * platform MUST detect (the seeded defects). Detection effectiveness is measured against this (§X.4).
 *
 * This measures RECALL of the seeded defects (did we find every known defect?). Precision is deliberately
 * NOT computed here: the fixtures are single-purpose, so engines legitimately raise additional, unrelated
 * findings (e.g. a missing README) that are not false positives. A fully-labelled corpus would be required
 * to measure precision honestly.
 */

export interface CorpusEntry {
  fixture: string;
  expected: string[];
}

export const GOLDEN_CORPUS: CorpusEntry[] = [
  {
    fixture: 'vulnerable-sample',
    expected: ['SEC-SECRET-001', 'MNT-VAR-001', 'MNT-TODO-001', 'SUP-LOCK-001', 'SUP-PIN-001', 'SUP-VULN-000'],
  },
  {
    fixture: 'insecure-docker',
    expected: ['IAC-DOCKER-TAG-001', 'IAC-DOCKER-USER-001', 'IAC-DOCKER-CURLBASH-001', 'IAC-DOCKER-ADD-001', 'IAC-DOCKER-SECRET-001', 'IAC-DOCKER-APTCLEAN-001', 'IAC-DOCKER-HEALTHCHECK-000'],
  },
  {
    fixture: 'insecure-k8s',
    expected: ['IAC-K8S-HOSTNS-001', 'IAC-K8S-HOSTPATH-001', 'IAC-K8S-SATOKEN-001', 'IAC-K8S-PRIV-001', 'IAC-K8S-PRIVESC-001', 'IAC-K8S-ROOT-001', 'IAC-K8S-CAP-001', 'IAC-K8S-ROFS-001', 'IAC-K8S-LIMITS-001', 'IAC-K8S-IMGTAG-001', 'IAC-K8S-PROBES-000'],
  },
  {
    fixture: 'insecure-compose',
    expected: ['IAC-COMPOSE-PRIV-001', 'IAC-COMPOSE-DOCKERSOCK-001', 'IAC-COMPOSE-HOSTMOUNT-001', 'IAC-COMPOSE-HOSTNET-001', 'IAC-COMPOSE-CAP-001', 'IAC-COMPOSE-IMGTAG-001', 'IAC-COMPOSE-SECRET-001', 'IAC-COMPOSE-NNP-001'],
  },
  {
    fixture: 'insecure-openapi',
    expected: ['API-SPEC-NOAUTH-001', 'API-SPEC-OP-NOAUTH-001', 'API-SPEC-HTTP-001', 'API-SPEC-APIKEY-QUERY-001', 'API-SPEC-NO-ERRORS-001', 'API-SPEC-NO-OPID-001'],
  },
  {
    fixture: 'inaccessible-html',
    expected: ['A11Y-IMG-ALT-001', 'A11Y-HTML-LANG-001', 'A11Y-TITLE-001', 'A11Y-INPUT-LABEL-001', 'A11Y-BUTTON-NAME-001', 'A11Y-LINK-NAME-001', 'A11Y-TABINDEX-001', 'A11Y-IFRAME-TITLE-001', 'A11Y-VIEWPORT-001'],
  },
  {
    fixture: 'seo-issues',
    expected: ['SEO-TITLE-001', 'SEO-META-DESC-001', 'SEO-CANONICAL-001', 'SEO-ROBOTS-NOINDEX-001', 'SEO-H1-001', 'SEO-OG-001', 'SEO-VIEWPORT-001', 'SEO-ROBOTSTXT-001', 'SEO-SITEMAP-001'],
  },
  {
    fixture: 'insecure-logging',
    expected: ['OBS-LOG-SENSITIVE-001', 'OBS-LOG-PII-OBJECT-001', 'OBS-LOG-CONSOLE-001'],
  },
  {
    fixture: 'bad-error-handling',
    expected: ['ERR-EMPTY-CATCH-001', 'ERR-CATCH-CONSOLE-001', 'ERR-STACK-EXPOSED-001', 'ERR-THROW-LITERAL-001'],
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
];
