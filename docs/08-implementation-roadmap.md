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
| 2.8 | Compliance mapping (control-coverage matrix, IV.3) | ✅ |
| 2.9 | Security (safe/authorized) · performance · AI/LLM evals | ☐ |
| 2.11 | Dockerfile/container security engine (CIS Docker Benchmark → `CloudIaCPosture`) | ✅ |
| 2.12 | Kubernetes manifest security engine (CIS K8s / Pod Security Standards → `CloudIaCPosture`) | ✅ |
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
