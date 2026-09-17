# 08 — Implementation Roadmap

> Spec ref: PART XI (Development Process, Phases & Definition of Done), PART XIV (Start Now).
> This is the living phase tracker. Update the status column as work proceeds.

## Guiding rules (spec XI.1, XI.5)

- **Think first; do not dump untested code.** Build → run tests → inspect → fix → re-run → review → continue.
- **One complete vertical slice before breadth** (XI.3 step 15).
- **Determinism first** (§0.2): deterministic engines produce facts; AI only reasons/correlates.
- **Definition of Done is evidence-based** (XI.6), not "pages render."

## Phase status legend

`☐ planned` · `▶ in progress` · `✅ done` · `⏸ blocked`

## Phase 0 — Design documents (spec XI.4)

| # | Document | Status |
|---|---|---|
| 1 | Product Requirements (`01`) | ▶ |
| 2 | Quality Model | ☐ (folded into 01 + spec PART IV/V for now) |
| 3 | System Architecture (`02`) | ▶ |
| 4 | Threat Model | ☐ (STRIDE pass in `06`) |
| 5 | Data Model (`03`) | ▶ |
| 6 | API Specification (`07`) | ▶ |
| 7 | Test Engine Architecture (`02` §Engines) | ▶ |
| 8 | Evidence Architecture (`04`) | ▶ |
| 9 | Scoring Methodology (`05`) | ▶ |
| 10 | Security Model (`06`) | ▶ |
| 11 | Execution Sandbox Model (`06`) | ▶ |
| 12 | UI/UX Information Architecture | ☐ |
| 13 | Implementation Roadmap (this doc) | ✅ |
| 14 | Testing Strategy | ☐ |
| 15 | Definition of Done | ✅ (see below) |
| 16 | Compliance & Privacy Model | ☐ |
| 17 | AI/LLM Governance Model | ☐ (only if AI features enabled) |
| 18 | Supply-Chain Security Model | ☐ |

## Phase 1 — Foundation + first vertical slice (current)

**Vertical slice goal (SAFE STATIC):**
`Upload code → detect stack (Profiler) → run ONE static-analysis engine → produce Findings with Evidence →
score ONE dimension (Maintainability or Security) → emit dual output (canonical JSON contract IX.4 + human report).`

| Step | Deliverable | Status |
|---|---|---|
| 1.1 | `packages/core`: vocabularies + Finding/Evidence/Score domain types with enforced invariants | ✅ |
| 1.2 | `packages/contracts`: Zod schema for canonical output contract (IX.4); validates every emitted result | ✅ |
| 1.3 | `packages/engines`: engine interfaces + two real static analyzers (secret-scanner, code-quality) | ✅ |
| 1.4 | Project Profiler (technology detection with confidence) | ✅ |
| 1.5 | Scoring engine with score-gaming invariants (VII.8) + unit tests | ✅ |
| 1.6 | `apps/api`: scans/findings/reports endpoints (async job) | ☐ (Phase 2) |
| 1.7 | `apps/worker`: sandboxed job runner executing the slice | ☐ (Phase 2 — orchestrator exists in `apps/cli`, ready to wrap) |
| 1.8 | `apps/web`: upload → live job status (no fake progress) → findings → report | ☐ (Phase 2) |
| 1.9 | `fixtures`: intentionally-vulnerable toy project (golden corpus seed) | ✅ |
| 1.10 | Run the slice against a fixture; verify seeded defects are detected (dogfooding, X.1) | ✅ (18/18 tests pass; CLI verified) |

**Phase 1 result:** a genuinely runnable, tested pipeline —
`Profiler → static engines → Findings+Evidence (redacted) → ScoreEngine → dual output (JSON contract + human report)`.
The CLI (`npm run scan -- <dir>`) drives the same orchestrator the worker will host. Typecheck clean (strict),
18/18 tests pass, seeded defects detected, no secret leaked to disk, NO_GO on the vulnerable fixture.
The web/api/worker are the **delivery layer** around this proven core, scheduled next.

## Phase 2 — Breadth (spec XI.3 step 16)

Add engines incrementally, each behind the plugin interface, each with golden-corpus fixtures,
a precision/recall benchmark (X.4), and its report type (IX.1).

| Step | Deliverable | Status |
|---|---|---|
| 2.1 | Dependency/Supply-Chain engine + CycloneDX SBOM (`SupplyChainHealth` dim) | ✅ |
| 2.2 | Export formats: SARIF · CycloneDX · JUnit XML · CSV (`packages/reporters`, IX.3) | ✅ |
| 2.3 | Accessibility engine (axe-core adapter) — needs browser/DOM | ☐ |
| 2.4 | API contract testing (OpenAPI drift) | ☐ |
| 2.5 | Async delivery core `packages/jobs` (`JobQueue`/`ScanStore`/`ScanService`) + `apps/worker` | ✅ (in-memory adapter; BullMQ/Postgres next) |
| 2.6 | `apps/api` — submit/status/findings/report+export endpoints, path-safety guard | ✅ (node:http; NestJS migration deferred — see doc 02) |
| 2.7 | `apps/web` (Next.js) — submit → live status → findings → report/exports (WCAG 2.2 AA) | ✅ |
| 2.21 | `apps/web` dashboard panels — overall + dimension meters + compliance matrix (WCAG 2.2 AA) | ✅ |
| 2.24 | `apps/web` SBOM + SEO panels — supply-chain inventory + SEO report on the scan page | ✅ |
| 2.26 | `apps/web` Manual-review queue + Limitations panels (§IX.5, Rule 10 — honesty UI) | ✅ |
| 2.8 | Compliance mapping (control-coverage matrix, IV.3) | ✅ |
| 2.9 | Security (safe/authorized) · performance · AI/LLM evals | ☐ |
| 2.11 | Dockerfile/container security engine (CIS Docker Benchmark → `CloudIaCPosture`) | ✅ |
| 2.12 | Kubernetes manifest security engine (CIS K8s / Pod Security Standards → `CloudIaCPosture`) | ✅ |
| 2.13 | docker-compose security engine (CIS Docker → `CloudIaCPosture`; Docker-socket → compliance) | ✅ |
| 2.14 | OpenAPI spec quality/security engine (OWASP API Security Top 10 → Security dim) | ✅ |
| 2.15 | Static HTML accessibility engine (WCAG 2.2 → Accessibility dim) | ✅ |
| 2.16 | Static performance/asset-budget engine (§V.12 → Performance dim) | ✅ |
| 2.17 | Static SEO analyzer (§V.24 — reported separately from software quality) | ✅ |
| 2.18 | Logging-quality engine (§V.25 — sensitive-data-in-logs → Observability dim) | ✅ |
| 2.19 | Error-handling engine (§V.14 — swallowed errors, exposed stack traces → Reliability dim) | ✅ |
| 2.20 | Privacy / PII-discovery engine (§V.16 — Luhn-validated cards, SSN, email → Privacy dim) | ✅ |
| 2.22 | CI/CD security engine (§V.19 — GitHub Actions: unpinned/injection/PR-target → Security dim) | ✅ |
| 2.23 | SQL migration-safety engine (§V.31 — destructive migrations → Reliability dim) | ✅ |
| 2.25 | Extend secret/PII scanning to `.sql`/`.xml`/`.properties` (+ fix multi-PII redaction leak) | ✅ |
| 2.27 | Config/documentation-quality engine (§V.29 → Maintainability dim) | ✅ |
| 2.28 | Terraform IaC/CSPM engine (§V.18 — public buckets/IAM/SG/encryption → CloudIaCPosture) | ✅ |
| 2.29 | CloudFormation IaC/CSPM engine (§V.18 — same CSPM checks over CFN templates) | ✅ |
| 2.30 | License/legal-checks engine (§V.30 — declared license metadata → SupplyChainHealth) | ✅ |
| 2.31 | Python security engine (§V.7 — eval/pickle/shell/yaml.load → Security dim; broadens beyond JS/TS) | ✅ |
| 2.32 | Go security engine (§V.7 — TLS-skip/shell-exec/SQL-concat/weak-hash → Security dim) | ✅ |
| 2.33 | Java security engine (§V.7 — Runtime.exec/SQL-concat/readObject/ECB → Security dim) | ✅ |
| 2.10 | Distributed adapters: BullMQ/Redis queue + PostgreSQL store (implement `JobQueue`/`ScanStore`) | ✅ |

**2.1–2.2 result:** `dependency-scanner` inventories declared deps into a CycloneDX 1.5 SBOM and flags
missing lockfile + unpinned versions; it is HONEST that offline vulnerability status is `NOT_TESTED`
(no CVE/OSV DB), never a false "clean". `packages/reporters` emits SARIF 2.1.0 (CI code-scanning),
CycloneDX SBOM, JUnit XML, and CSV.

**2.10 result (distributed deployment):** `@qa/jobs/adapters` ships REAL adapters — `BullMqJobQueue`
(bullmq + ioredis) and `PostgresScanStore` (node-postgres), both implementing the same `JobQueue`/`ScanStore`
interfaces so the API and worker are backend-agnostic. Selected by env (`QA_REDIS_URL` + `QA_DATABASE_URL`);
otherwise in-memory. Verified LIVE against Redis+Postgres containers (`docker-compose.yml`): the Postgres
adapter's real SQL is tested via pg-mem (4 tests), the BullMQ adapter via a Redis-gated integration test,
and the full **multi-process** path end-to-end — API (producer) → Redis → **separate worker process** →
Postgres → API serves the result (COMPLETED, NO_GO, Critical persisted; Postgres row confirmed). No fake
adapters (§XIII rule 27). 38/38 tests pass with services enabled.

**2.8 result (compliance mapping):** `mapCompliance` (`packages/core`) maps findings to a control-coverage
matrix (§IV.3) across SOC 2 (illustrative), OWASP Top 10 2025, CIS Docker, and CIS Kubernetes. Each control:
mapped rules → evidence (finding IDs) → status. Statuses are honest — `SATISFIED` = the check ran and found no
violation (NOT "compliant"); `GAPS` = mapped violations exist (with finding IDs); `NOT_ASSESSED` = the
providing check did not run (never silently satisfied). A prominent disclaimer states this is technical
evidence only, not a certification (§I.5). Feeds the `ComplianceReadiness` dimension, a new top-level
`compliance` field on the result (in the Zod contract), a `?format=compliance` API/web export, and a report
section. 3 tests (unit statuses + end-to-end matrix).

**2.26 result (honesty UI panels):** the scan detail page now renders a **Manual review required** panel
(the human-judgment items — subjective UX/architecture review, and the full WCAG 2.2 manual audit when the
a11y engine ran — spec IX.5) and a **Limitations (never hidden)** panel (spec Rule 10 — what was not tested
and why). This completes the dashboard's honesty story: scores, evidence, *and* an explicit account of what
automation cannot cover. `next build` clean; verified live (the inaccessible-html scan surfaces 2 manual
items and 2 limitations).

**2.24 result (SBOM + SEO web panels):** the scan detail page now also renders a **Supply-chain (SBOM)**
panel (CycloneDX components table with scope + honest `NOT_TESTED` vulnerability status prominently noted)
and an **SEO** panel (issue list, labelled "separate from software quality" per §V.24). Both render only when
present in the result. `next build` clean; verified live — `vulnerable-sample` shows 4 SBOM components,
`seo-issues` shows 9 SEO issues.

**2.21 result (web dashboard):** the scan detail page now visualizes the full result: an **Overall** KPI
panel (score, evidence coverage, critical blockers, high-risk, manual verification), **Quality dimensions**
with accessible score meters (`role="meter"`, value shown as text + "why" explanation), and a **Compliance**
panel (control-coverage table with satisfied/gaps/not-assessed status conveyed by text+mark, never colour
alone). `ScanLive` fetches the full result via the `?format=json` proxy on completion. `next build` clean;
verified live end-to-end (API + web): a scan of `insecure-k8s` renders 4 dimensions and the 14-control
compliance matrix with 4 gaps. (Also cleaned up leaked API dev-processes from earlier phases that had held
port 4000 with stale code.)

**2.33 result (Java engine):** `JavaScanner` flags Java security anti-patterns — `Runtime.getRuntime().exec`
(CWE-78), JDBC statements built by string concatenation/`String.format` (CWE-89), `readObject()`
deserialization (CWE-502), ECB/DES ciphers (CWE-327), and MD5/SHA-1 (CWE-327) — feeding the Security
dimension. Block + quote-aware `//` comment stripping prevents comment false positives. Isolated fixture
`fixtures/insecure-java`; 2 tests including a safe-Java no-false-positive check (`PreparedStatement`,
`SHA-256`, `AES/GCM`).

**2.32 result (Go engine):** `GoScanner` flags Go security anti-patterns — `InsecureSkipVerify: true`
(CWE-295), shell exec via `exec.Command("sh","-c",…)` (CWE-78), SQL built by string concatenation/Sprintf
(CWE-89), and MD5/SHA-1 (CWE-327) — feeding the Security dimension. It strips block comments and uses a
quote/raw-string-aware `//` line-comment stripper, so patterns in comments (and `//` inside strings) don't
false-positive. Isolated fixture `fixtures/insecure-go`; 2 tests including a safe-Go no-false-positive check.

**2.31 result (Python engine):** `PythonScanner` broadens coverage beyond JS/TS. With quote-aware Python
comment-stripping (so patterns in comments don't false-positive), it flags `eval`/`exec` (CWE-95),
`os.system` and `shell=True` (CWE-78), `pickle.load(s)` (CWE-502), unsafe `yaml.load()` without a Loader
(CWE-20), Flask `debug=True` (CWE-489), and MD5/SHA-1 (CWE-327) — feeding the Security dimension. Word
boundaries prevent false positives (e.g. `ast.literal_eval` is not flagged). Isolated fixture
`fixtures/insecure-python`; 2 tests including a safe-Python no-false-positive check.

**2.30 result (license engine):** `LicenseScanner` inspects declared license metadata in package.json files
(§V.30) and reports FACTS only — no license field (`LIC-MISSING-001`), deprecated object/array form or a
non-SPDX identifier (`LIC-NONSTANDARD-001`), `UNLICENSED` that isn't `private` and could be published
(`LIC-UNLICENSED-NOT-PRIVATE-001`), and a declared strong-copyleft GPL/AGPL license (`LIC-COPYLEFT-DECLARED-001`,
informational). It draws no legal conclusions and never claims license compatibility (spec V.30). Valid SPDX
(including expressions like `(MIT OR Apache-2.0)`) and `private + UNLICENSED` produce nothing. Feeds
SupplyChainHealth. 5 temp-project tests.

**2.29 result (CloudFormation engine):** `CloudFormationScanner` recursively walks CloudFormation templates
(JSON parsed reliably; YAML best-effort inside try/catch since `!Ref`/`!Sub` intrinsics can defeat a plain
YAML parser) and flags public S3 ACLs, security groups open to `0.0.0.0/0`, `Encrypted: false`, over-broad
IAM (`Action`/`Resource = "*"`, found even when nested in `Policies[].PolicyDocument.Statement[]`), hardcoded
secrets (redacted, CWE-798), and auto-assigned public IPs — feeding CloudIaCPosture. Only files whose
`Resources` contain `AWS::*` types are treated as templates, so ordinary JSON/YAML is ignored. Isolated
fixture `fixtures/insecure-cloudformation` (JSON, so the verified path is deterministic); 3 tests.

**2.28 result (Terraform engine):** `TerraformScanner` analyses `.tf` files with deterministic regex after
stripping HCL comments (so patterns inside comments don't false-positive) — no HCL parser dependency. It
flags public S3 ACLs, security groups open to `0.0.0.0/0`, `encrypted = false`, over-broad IAM
(`Action`/`Resource = "*"`), hardcoded secrets (redacted, CWE-798), and auto-assigned public IPs — feeding
the CloudIaCPosture dimension (CIS AWS references). Isolated fixture `fixtures/insecure-terraform`; 3 tests
(all rules + no-leak + comment-stripping/secure-config yields none).

**2.27 result (config/docs engine):** `ConfigDocsScanner` runs project-hygiene checks (§V.29): missing
README (`DOC-README-001`) / LICENSE (`DOC-LICENSE-001`) (Informational), a committed `.env` file
(`CFG-ENV-COMMITTED-001`, Medium), and env-vars used in code without a `.env.example`
(`CFG-NO-ENV-EXAMPLE-001`, Low) — feeding the Maintainability dimension. Findings are deliberately
low-severity so they don't distort scores (Informational carries zero penalty — Maintainability stays 97/100
on the sample). Tests use runtime temp projects (so no `.env` fixture fights `.gitignore`); 2 tests including
a no-false-positive check on a well-formed project.

**2.25 result (SQL/text secret+PII + redaction fix):** `.sql`, `.xml`, and `.properties` are now recognised
text types, so the secret-scanner and privacy-scanner analyse SQL seed/migration data (hardcoded credentials
and PII are common there). This surfaced and fixed a **redaction bug**: the privacy engine previously masked
only the value that triggered a finding, so a finding's evidence could still leak a *different* PII value on
the same line (e.g. the email finding left the card number visible). `redactAllPii` now masks all cards/SSNs/
emails from a line for every finding's evidence. Verified by a no-leak test and on disk. Isolated fixture
`fixtures/sql-with-secrets`; 2 tests.

**2.23 result (SQL migration engine):** `SqlMigrationScanner` analyses `.sql` files by stripping comments
(preserving line numbers), splitting into statements, and classifying each: DROP TABLE / DROP COLUMN /
TRUNCATE / DELETE-without-WHERE / UPDATE-without-WHERE (High) and ADD COLUMN NOT NULL without DEFAULT
(Medium), feeding the Reliability dimension. Comment-stripping + statement-scoped WHERE checks keep false
positives low — the test asserts safe variants (WHERE-scoped, defaulted/nullable columns) are not flagged
via exact counts. Isolated fixture `fixtures/dangerous-migration`; 2 tests.

**2.22 result (CI/CD engine):** `CicdScanner` parses `.github/workflows/*.yml` and flags pipeline-security
issues (§V.19): script injection from untrusted event data (`CI-SCRIPT-INJECTION-001`, High, CWE-94),
`pull_request_target` triggers, unpinned actions (branch/no-ref, and tag-not-SHA as informational), secrets
echoed in run steps (CWE-532), and missing least-privilege permissions. Findings score under Security
(category `CICD` → `Security`). Only files under `.github/workflows/` are analysed. Isolated fixture
`fixtures/insecure-cicd`; 2 tests (all rules + hardened workflow yields none).

**2.20 result (privacy engine):** `PrivacyScanner` discovers hardcoded PII in source — credit-card numbers
(Luhn-validated to avoid false positives, `PRIV-PII-CARD-001`, High, CWE-312), US SSNs in valid ranges
(`PRIV-PII-SSN-001`, CWE-359), and personal emails excluding placeholder domains (`PRIV-PII-EMAIL-001`) —
feeding the Privacy dimension. Every detected PII value is REDACTED before it reaches evidence (§VIII.10),
verified by a no-leak test. Isolated fixture `fixtures/pii-in-source`; 3 tests including a false-positive
guard (a Luhn-invalid number + a placeholder email produce nothing).

**2.19 result (error-handling engine):** `ErrorHandlingScanner` statically analyses JS/TS and flags empty
catch blocks (`ERR-EMPTY-CATCH-001`), catch blocks that only console-log (`ERR-CATCH-CONSOLE-001`), error/
stack traces sent to the client (`ERR-STACK-EXPOSED-001`, High, CWE-209), and thrown non-Error literals
(`ERR-THROW-LITERAL-001`), feeding the Reliability dimension (default weight 0.15). Catch-body detection uses
conservative brace matching — it skips nested-brace bodies rather than risk a miscount, avoiding false
positives. Isolated fixture `fixtures/bad-error-handling`; 2 tests (all rules + robust code yields none).

**2.18 result (logging engine):** `LoggingScanner` does line-based analysis of log calls in JS/TS and flags
sensitive data written to logs (`OBS-LOG-SENSITIVE-001`, High, CWE-532), wholesale request/user-object
logging (`OBS-LOG-PII-OBJECT-001`), and `console.*` instead of structured logging (`OBS-LOG-CONSOLE-001`),
feeding the Observability dimension. Mapped into the compliance catalog as SOC 2 (illustrative) CC7.2. Honest
scope: logging quality only — full observability (metrics/traces/alerting coverage, SLIs) needs runtime/config
inspection. Isolated fixture `fixtures/insecure-logging`; 2 tests. The compliance integration assertion was
relaxed to relationships (assessed ≥ 4) to stay robust as engine-backed controls grow.

**2.17 result (SEO analyzer):** `analyzeSeo` runs static on-page + project SEO checks (title, meta
description, canonical, robots/noindex, headings, Open Graph, viewport, robots.txt, sitemap.xml). Per §V.24
it is deliberately NOT a scoring engine: the orchestrator calls it directly and places the result in
`scan.seo`, keeping SEO findings OUT of `findings[]`, the quality dimensions, the overall score, and the
release decision (verified by a dedicated separation test). Exposed via a `?format=seo` API/web export and a
report section. Isolated fixture `fixtures/seo-issues`; 2 tests.

**2.16 result (performance engine):** `PerformanceScanner` runs static budget checks (no build/page load,
using file sizes): oversized images/fonts/media, over-budget shipped JS/CSS, render-blocking `<script>` in
`<head>` (async/defer/module exempt), and committed source maps — feeding the Performance dimension (default
weight 0.1). It only applies to web-relevant files (assets/CSS/HTML/maps and asset-path or `.min`/`.bundle`
JS), so plain Node source is untouched (no impact on existing scans). Honestly scoped: static budgets only,
NOT a substitute for runtime latency/Core-Web-Vitals testing (which needs an authorized dynamic target). The
test builds oversized files at runtime (nothing large committed); 2 tests (budgets + no false positives).

**2.15 result (accessibility engine):** `HtmlAccessibilityScanner` parses HTML (via `node-html-parser`) and
runs 9 static WCAG 2.2 checks — missing image alt, no document lang, no title, unlabeled form controls,
buttons/links with no accessible name, positive tabindex, iframe without title, zoom-blocking viewport —
each tagged with its WCAG criterion + level, feeding the Accessibility dimension. Honesty (§V.5): the engine
is static-markup only, so the orchestrator queues a "full WCAG 2.2 manual accessibility audit" whenever it
runs (automation cannot prove conformance). Isolated fixture `fixtures/inaccessible-html`; 2 tests (all 9
rules + WCAG mapping + manual-audit queued, and no false positives on a clean page).

**2.14 result (OpenAPI engine):** `OpenApiScanner` analyses OpenAPI 3.x / Swagger 2.0 specs (YAML or JSON)
and flags 6 issues mapped to OWASP API Security Top 10 2023 — no auth scheme, unprotected operation,
cleartext HTTP server, API key in query string, missing error responses, missing operationId. Findings
score under Security (category `API` → `Security` mapping) and the OWASP API2 control is added to the
compliance catalog. Only files declaring `openapi`/`swagger` + `paths` are analysed, and the engine reports
zero executed checks when no spec is present — so the API control is honestly `NOT_ASSESSED` (not a false
"satisfied") on projects without a spec. Isolated fixture `fixtures/insecure-openapi`; 2 tests (all rules +
no-false-positive on plain JSON/YAML).

**2.13 result (docker-compose engine):** `ComposeScanner` parses compose files and flags 8 CIS-aligned
service risks — privileged, **Docker socket mount** (container escape), host network mode, sensitive host
bind mounts, dangerous capabilities, unpinned image, hardcoded env secret (redacted), missing
`no-new-privileges`. Shared `imageUnpinned` helper lifted into `util.ts` (K8s refactored to reuse it). The
Docker-socket rule is mapped into the compliance catalog as CIS Docker 5.31. Isolated fixture
`fixtures/insecure-compose`; 2 tests. The compliance integration test was made robust to catalog growth.

**2.12 result (Kubernetes engine):** `KubernetesScanner` parses multi-document YAML (via the `yaml`
package), extracts the pod spec from Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob, and
evaluates it against 11 CIS Kubernetes / Pod Security Standards checks — privileged (Critical), root user,
host namespaces, hostPath, dangerous capabilities, privilege-escalation, writable root FS, missing
resource limits, unpinned image, SA-token automount, missing probes. Non-workload YAML (no kind/apiVersion)
is ignored, so CI workflows etc. are never flagged. Isolated fixture `fixtures/insecure-k8s`; 2 tests assert
all rules fire, the privileged container forces NO_GO, and plain YAML is not flagged.

**2.11 result (Dockerfile engine):** `DockerfileScanner` (`packages/engines`) parses Dockerfile instructions
(joining line continuations, tracking multi-stage `AS` names) and flags CIS-aligned misconfigurations —
unpinned base image, root user, remote-script-piped-to-shell, remote `ADD`, hardcoded secret in `ENV/ARG`
(redacted), `apt` without cleanup, missing `HEALTHCHECK` — feeding the `CloudIaCPosture` dimension. Isolated
fixture `fixtures/insecure-docker`; 2 tests assert all 7 rules fire, the dimension is scored, and the secret
is captured-but-redacted. Terraform/K8s/Helm scanners plug in next behind the same interface.

**2.7 result (web UI):** `apps/web` is a Next.js 14 App-Router UI built as a thin BFF that proxies to the
API (same-origin route handlers → no CORS, and it bundles no `@qa/*` packages, so no Node-only code reaches
the client). Screens: submit (project dropdown from `GET /targets`), live scan status with an accessible
`role=progressbar`, findings table with severity filter, and one-click report/exports (human/JSON/SARIF/
JUnit/CSV/CycloneDX). Accessibility (spec IX.8, WCAG 2.2 AA): semantic landmarks, skip link, visible focus,
severity/decision conveyed by text+color (never color alone), reduced-motion support, light/dark, phone-width
layout. Verified: `next build` clean (types + 8 routes), and a live run drove submit → COMPLETED → Critical
finding entirely through the web proxy, with both pages server-rendering correctly.

**2.5–2.6 result:** the orchestrator was refactored into `packages/orchestrator` (shared by CLI/worker/API).
`packages/jobs` provides an infra-free async delivery core: an `InMemoryJobQueue` (FIFO, concurrency,
bounded retries, dead-letter, `onIdle`), an `InMemoryScanStore`, and a `ScanService` that submits
non-blocking jobs with honest **stage-based** progress (no fake %). `apps/worker` processes queued jobs;
`apps/api` is a dependency-light `node:http` server implementing the REST contract with a real
path-safety guard (§VIII.5 — scan targets must be under allowed roots). 33/33 tests pass, including an
HTTP integration test that submits a scan, polls to COMPLETED, filters findings, and fetches SARIF/human/
CycloneDX reports; the API server + worker were also verified live via curl.

## Definition of Done (spec XI.6) — applies to every feature

A feature is **not** done because it renders. It is done when:
- automated tests exist and pass · findings are reproducible from a manifest · evidence is collected ·
  scores are explainable ("why?") · `NOT TESTED` is never shown as `PASS` · limitations are disclosed ·
  the engine is benchmarked against the golden corpus · secrets/PII are redacted in all output.

## Known limitations of this build (spec Rule 10 — never hidden)

- Single-session work cannot deliver all 18 design docs + all engines. This roadmap sequences honestly.
- No external target is scanned; dynamic/security engines are stubbed behind the plugin interface until a
  target + written authorization exist (Definition of Ready §0.3.1).
