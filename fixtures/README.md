# Golden Test Corpus (fixtures)

> Spec ref: §X.2 / §X.3 — "Create intentionally vulnerable toy projects as fixtures; the platform must
> correctly detect known seeded defects." Detection effectiveness is measured against these (§X.4).

⚠️ **These projects are intentionally insecure and imperfect. They are NOT real applications and must never
be deployed or copied into real code.** Secret-looking values are well-known public documentation examples,
not live credentials.

## `vulnerable-sample/`

Seeded defects (each maps to a rule the platform must detect):

| Seeded defect | Location | Expected rule | Severity |
|---|---|---|---|
| Hardcoded AWS access key | `src/config.js` | `SEC-SECRET-001` | Critical |
| Hardcoded credential assignment (`dbPassword`) | `src/config.js` | `SEC-SECRET-001` | High |
| Use of `var` (×2) | `src/config.js`, `src/app.js` | `MNT-VAR-001` | Low |
| TODO / tech-debt markers (×2) | `src/app.js` | `MNT-TODO-001` | Informational |
| Missing dependency lockfile | `package.json` | `SUP-LOCK-001` | Medium |
| Unpinned/wildcard dependency (`left-pad: "*"`) | `package.json` | `SUP-PIN-001` | Medium |
| Dependency vuln scan not performed (offline) | `package.json` | `SUP-VULN-000` | Informational (NOT_TESTED) |

The dogfooding test `tests/dogfood.test.ts` scans this fixture and asserts the seeded defects are found,
the output validates against the canonical contract, and **no raw secret value leaks into any evidence file**.

## `insecure-docker/`

An intentionally-insecure `Dockerfile` for the `DockerfileScanner` (spec V.18, CIS Docker Benchmark):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Unpinned base image (`node:latest`) | `IAC-DOCKER-TAG-001` | Medium |
| Container runs as root (no `USER`) | `IAC-DOCKER-USER-001` | High |
| Remote script piped to shell (`curl … \| sh`) | `IAC-DOCKER-CURLBASH-001` | High |
| `ADD` fetches a remote URL | `IAC-DOCKER-ADD-001` | Medium |
| Hardcoded secret in `ENV` | `IAC-DOCKER-SECRET-001` | High |
| `apt install` without cache cleanup | `IAC-DOCKER-APTCLEAN-001` | Low |
| No `HEALTHCHECK` | `IAC-DOCKER-HEALTHCHECK-000` | Informational |

`tests/dockerfile.test.ts` asserts each rule fires, the `CloudIaCPosture` dimension is scored, and the
seeded secret never leaks into evidence (it is captured but redacted).

## `insecure-k8s/`

An intentionally-insecure Kubernetes `Deployment` for the `KubernetesScanner` (spec V.18, CIS Kubernetes
Benchmark / Pod Security Standards):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| `hostNetwork: true` | `IAC-K8S-HOSTNS-001` | High |
| `hostPath` volume | `IAC-K8S-HOSTPATH-001` | Medium |
| SA token auto-mounted | `IAC-K8S-SATOKEN-001` | Low |
| `privileged: true` | `IAC-K8S-PRIV-001` | Critical |
| `allowPrivilegeEscalation` not false | `IAC-K8S-PRIVESC-001` | Medium |
| Runs as root (no runAsNonRoot) | `IAC-K8S-ROOT-001` | High |
| Dangerous capability (`SYS_ADMIN`) | `IAC-K8S-CAP-001` | High |
| Writable root filesystem | `IAC-K8S-ROFS-001` | Low |
| Missing CPU/memory limits | `IAC-K8S-LIMITS-001` | Medium |
| Unpinned image (`nginx:latest`) | `IAC-K8S-IMGTAG-001` | Medium |
| Missing liveness/readiness probes | `IAC-K8S-PROBES-000` | Informational |

`tests/kubernetes.test.ts` asserts each rule fires, the privileged container forces `NO_GO`, the
`CloudIaCPosture` dimension is scored, and non-workload YAML (e.g. a CI workflow) is NOT flagged.

## `insecure-compose/`

An intentionally-insecure `docker-compose.yml` for the `ComposeScanner` (spec V.18, CIS Docker Benchmark):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Privileged service | `IAC-COMPOSE-PRIV-001` | Critical |
| Docker socket mounted (container escape) | `IAC-COMPOSE-DOCKERSOCK-001` | Critical |
| Sensitive host path bind mount (`/etc`) | `IAC-COMPOSE-HOSTMOUNT-001` | High |
| Host network mode | `IAC-COMPOSE-HOSTNET-001` | High |
| Dangerous capability (`SYS_ADMIN`) | `IAC-COMPOSE-CAP-001` | High |
| Hardcoded secret in `environment` | `IAC-COMPOSE-SECRET-001` | High |
| Unpinned image (`nginx:latest`) | `IAC-COMPOSE-IMGTAG-001` | Medium |
| `no-new-privileges` not set | `IAC-COMPOSE-NNP-001` | Medium |

`tests/compose.test.ts` asserts each rule fires, the privileged service + socket mount force `NO_GO`, the
seeded secret is redacted, and the CIS Docker 5.31 (Docker-socket) compliance control shows a gap.

## `insecure-openapi/`

A weak OpenAPI spec pair (`openapi.yaml` with schemes; `api-no-auth.json` with none) for the
`OpenApiScanner` (spec V.6, OWASP API Security Top 10 2023):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| No security scheme defined (JSON spec) | `API-SPEC-NOAUTH-001` | High |
| Operation unprotected while schemes exist | `API-SPEC-OP-NOAUTH-001` | High |
| Cleartext HTTP server | `API-SPEC-HTTP-001` | Medium |
| API key in query string | `API-SPEC-APIKEY-QUERY-001` | Medium |
| Operation with no error responses | `API-SPEC-NO-ERRORS-001` | Low |
| Operation missing `operationId` | `API-SPEC-NO-OPID-001` | Informational |

`tests/openapi.test.ts` asserts each rule fires, the OWASP API2 compliance control shows a gap, findings
score under Security, and ordinary (non-spec) JSON/YAML is NOT flagged.

## `inaccessible-html/`

An intentionally-inaccessible HTML page for the `HtmlAccessibilityScanner` (spec V.5, WCAG 2.2):

| Seeded defect | Expected rule | WCAG | Severity |
|---|---|---|---|
| `<html>` without `lang` | `A11Y-HTML-LANG-001` | 3.1.1 (A) | Medium |
| Missing `<title>` | `A11Y-TITLE-001` | 2.4.2 (A) | Medium |
| `<img>` without `alt` | `A11Y-IMG-ALT-001` | 1.1.1 (A) | Medium |
| Form control with no label | `A11Y-INPUT-LABEL-001` | 1.3.1 (A) | High |
| Button with no accessible name | `A11Y-BUTTON-NAME-001` | 4.1.2 (A) | High |
| Link with no accessible name | `A11Y-LINK-NAME-001` | 2.4.4 (A) | High |
| Positive `tabindex` | `A11Y-TABINDEX-001` | 2.4.3 (A) | Low |
| `<iframe>` without title | `A11Y-IFRAME-TITLE-001` | 4.1.2 (A) | Medium |
| Viewport disables zoom | `A11Y-VIEWPORT-001` | 1.4.4 (AA) | Medium |

`tests/accessibility.test.ts` asserts each rule fires, findings carry the WCAG criterion, the Accessibility
dimension is scored, a **manual WCAG audit** is queued (automation cannot prove conformance — §V.5), and a
clean page yields no findings.

## `seo-issues/`

An SEO-poor HTML page for the SEO analyzer (spec V.24). SEO is reported **separately** from software
quality — these findings never affect the quality dimensions, overall score, or release decision.

| Seeded defect | Expected rule |
|---|---|
| Missing `<title>` | `SEO-TITLE-001` |
| Missing meta description | `SEO-META-DESC-001` |
| Missing canonical link | `SEO-CANONICAL-001` |
| `noindex` robots meta | `SEO-ROBOTS-NOINDEX-001` |
| No `<h1>` (or multiple) | `SEO-H1-001` |
| Incomplete Open Graph | `SEO-OG-001` |
| Missing viewport meta | `SEO-VIEWPORT-001` |
| No robots.txt / sitemap.xml | `SEO-ROBOTSTXT-001` / `SEO-SITEMAP-001` |

`tests/seo.test.ts` asserts each rule fires **and** that SEO findings stay out of the scored findings and
dimensions (the V.24 separation requirement).

## `insecure-logging/`

A JS file with leaky logging for the `LoggingScanner` (spec V.25):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Sensitive value written to logs (password, token) | `OBS-LOG-SENSITIVE-001` | High (CWE-532) |
| Logging a whole request/user object | `OBS-LOG-PII-OBJECT-001` | Medium |
| `console.*` instead of structured logging | `OBS-LOG-CONSOLE-001` | Low |

`tests/logging.test.ts` asserts each rule fires, the Observability dimension is scored, the SOC 2 CC7.2
("no sensitive data in logs") compliance control shows a gap, and clean structured logging yields no findings.

## `bad-error-handling/`

A JS file with poor error handling for the `ErrorHandlingScanner` (spec V.14):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Empty catch block | `ERR-EMPTY-CATCH-001` | Medium |
| Catch only logs to console | `ERR-CATCH-CONSOLE-001` | Low |
| Stack trace sent to the client | `ERR-STACK-EXPOSED-001` | High (CWE-209) |
| Throwing a non-Error value | `ERR-THROW-LITERAL-001` | Low |

`tests/error-handling.test.ts` asserts each rule fires, the Reliability dimension is scored, and robust
error handling (real recovery / rethrow, generic client errors) yields no findings.

## `pii-in-source/`

A JS file with hardcoded PII for the `PrivacyScanner` (spec V.16). All values are fabricated / well-known
test values, and the scanner **redacts every PII value** before it reaches evidence.

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Luhn-valid credit-card number | `PRIV-PII-CARD-001` | High (CWE-312) |
| Social Security Number | `PRIV-PII-SSN-001` | Medium (CWE-359) |
| Personal email address | `PRIV-PII-EMAIL-001` | Informational |

`tests/privacy.test.ts` asserts each rule fires, the Privacy dimension is scored, **no raw PII reaches
evidence**, and that a Luhn-invalid number + a placeholder email produce no false positives.

## `insecure-cicd/`

An intentionally-insecure GitHub Actions workflow (`.github/workflows/ci.yml`) for the `CicdScanner`
(spec V.19):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Script injection from PR title | `CI-SCRIPT-INJECTION-001` | High (CWE-94) |
| `pull_request_target` trigger | `CI-PR-TARGET-001` | Medium |
| Action pinned to branch / no version | `CI-ACTION-UNPINNED-001` | Medium |
| Secret echoed in a run step | `CI-SECRET-ECHO-001` | Medium |
| No least-privilege permissions | `CI-PERMISSIONS-000` | Informational |
| Action pinned to a tag (not SHA) | `CI-ACTION-TAG-001` | Informational |

`tests/cicd.test.ts` asserts each rule fires, script-injection is High/CWE-94, CI findings score under
Security, and a hardened workflow (SHA-pinned action, permissions block, `pull_request`) yields no findings.

## `dangerous-migration/`

A SQL migration with destructive statements for the `SqlMigrationScanner` (spec V.31). It also contains
safe variants that must NOT be flagged (the test asserts exact counts).

| Seeded defect | Expected rule | Severity |
|---|---|---|
| `DROP TABLE` | `SQL-DROP-TABLE-001` | High |
| `DROP COLUMN` | `SQL-DROP-COLUMN-001` | High |
| `TRUNCATE` | `SQL-TRUNCATE-001` | High |
| `DELETE` without `WHERE` | `SQL-DELETE-NO-WHERE-001` | High |
| `UPDATE` without `WHERE` | `SQL-UPDATE-NO-WHERE-001` | High |
| `ADD COLUMN NOT NULL` without `DEFAULT` | `SQL-NOTNULL-NO-DEFAULT-001` | Medium |

`tests/sql-migration.test.ts` asserts each destructive rule fires exactly once (so WHERE-scoped and
defaulted statements are not false-flagged), and a safe additive migration yields no findings.

## Adding fixtures

Each new engine (Phase 2+) ships with a fixture that seeds the defect it detects, so detection precision/recall
can be benchmarked and regressions in detection quality fail the build (§X.4).
