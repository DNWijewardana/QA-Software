# AI-Powered Universal Software Quality Assurance & Testing Platform

An **evidence-driven Quality Engineering platform** that evaluates software systems across functional,
security, performance, reliability, maintainability, accessibility, compatibility, architecture, data,
DevOps, supply-chain, cloud/IaC, privacy, compliance, and AI/LLM dimensions — and is **honest about
what it tested, what it did not, and how confident it is.**

> Built to the specification in
> [`Master Prompt 2.0 — AI-Powered Universal Software Quality Assurance & Testing Platform.md`](./Master%20Prompt%202.0%20%E2%80%94%20AI-Powered%20Universal%20Software%20Quality%20Assurance%20%26%20Testing%20Platform.md).
> That document (PART 0 and PART XIII) is the always-on constraint set for this codebase.

## Core principles (non-negotiable — see spec §0.2, PART XIII)

1. **Evidence or silence.** No claim without linkable evidence; otherwise `INSUFFICIENT EVIDENCE`.
2. **Determinism first, AI second.** Scanners/tests decide facts; AI only reasons, correlates, prioritizes.
3. **`NOT TESTED` never becomes `PASS`.** Enforced by the data model, not by convention.
4. **Aggregate scores never hide Critical findings.** Critical/High surface independently.
5. **No fabrication, ever.** No fake results, metrics, evidence, progress, or integrations.
6. **Least harm, least privilege.** Default read-only, non-destructive, authorized-only.

## Status

🚧 **Phase 2 — Breadth + full delivery layer.** Design docs + tested vertical slice + supply-chain/SBOM
engine + SARIF/CycloneDX/JUnit/CSV exports + async job queue/worker/HTTP API + distributed BullMQ/Redis +
PostgreSQL adapters + a Next.js web UI (all SAFE_STATIC).
See [`docs/08-implementation-roadmap.md`](./docs/08-implementation-roadmap.md) for phase tracking.

### Run it

```bash
npm install
npm test                                   # 38 tests (BullMQ test auto-skips without Redis)
npm run scan -- fixtures/vulnerable-sample # one-shot CLI scan (dual output + exports)
npm run worker -- fixtures/vulnerable-sample   # async worker demo (in-memory)
npm run api                                # HTTP API on :4000 (SAFE_STATIC, path-guarded)
npm run web                                # Next.js UI on :3000 (proxies to the API on :4000)
```

The web UI needs the API running (`npm run api` in another terminal; set `QA_API_URL` to point elsewhere).

**Distributed deployment** (API + worker as separate processes over Redis + PostgreSQL):

```bash
docker compose up -d                       # Redis (:6380) + Postgres (:5433)
export QA_REDIS_URL=redis://127.0.0.1:6380
export QA_DATABASE_URL=postgres://postgres:qa@127.0.0.1:5433/qa
npm run api        # terminal 1 — pure producer
npm run worker     # terminal 2 — long-lived consumer
```

## Architecture at a glance

```
Frontend (Next.js) → API (NestJS) → Job Orchestrator → Worker Queue (BullMQ/Redis) →
Testing Engines (plugins) → Evidence Store → Analysis/Quality Engine → Reporting Engine
```

Polyglot persistence (spec VI.5): **PostgreSQL** for transactional/traceability data, **object storage**
for evidence artifacts, optional search index for global search.

## Monorepo layout

| Path | Purpose |
|---|---|
| `apps/web` | Next.js UI (BFF proxy): submit → live status → dimension-score meters + compliance matrix + findings → reports; WCAG 2.2 AA |
| `apps/api` | HTTP API: submit scans, poll status, findings, reports/exports (spec VI.9) |
| `apps/worker` | Worker that processes queued scan jobs (spec VI.6/VI.7) |
| `apps/cli` | CLI driver for a one-shot SAFE_STATIC scan with dual output |
| `packages/core` | Shared domain types: findings, evidence, scoring, vocabularies (the enforced invariants) |
| `packages/orchestrator` | The reusable scan pipeline + human report renderer (shared by CLI, worker, API) |
| `packages/jobs` | Async job core: `JobQueue`/`ScanStore`/`ScanService` adapters (in-memory now; BullMQ/Postgres next) |
| `packages/engines` | Pluggable engine adapters (`TestEngine`, `Scanner`, … — spec VI.2): profiler, secret-scanner, code-quality, dependency-scanner, dockerfile-scanner, kubernetes-scanner, compose-scanner, openapi-scanner, html-a11y-scanner, performance-scanner, logging-scanner, error-handling-scanner, privacy-scanner, cicd-scanner, sql-migration-scanner, config-docs-scanner; plus separate SEO analyzer |
| `packages/contracts` | Zod schemas for the canonical output contract (spec IX.4) |
| `packages/reporters` | Export formats: SARIF · CycloneDX SBOM · JUnit XML · CSV (spec IX.3) |
| `fixtures` | Golden test corpus: intentionally-vulnerable toy projects (spec X.3) |
| `docs` | Design documents (spec XI.4) |

## Documentation

| Doc | Spec ref |
|---|---|
| [01 — Product Requirements](./docs/01-product-requirements.md) | XI.4 #1 |
| [02 — System Architecture](./docs/02-system-architecture.md) | XI.4 #3 |
| [03 — Data Model](./docs/03-data-model.md) | XI.4 #5 |
| [04 — Evidence Model](./docs/04-evidence-model.md) | XI.4 #8 |
| [05 — Scoring Methodology](./docs/05-scoring-methodology.md) | XI.4 #9 |
| [06 — Security & Sandbox Model](./docs/06-security-sandbox-model.md) | XI.4 #10, #11 |
| [07 — API & Output Contract](./docs/07-api-and-output-contract.md) | XI.4 #6 |
| [08 — Implementation Roadmap](./docs/08-implementation-roadmap.md) | XI.4 #13 |

## License / honesty note

This platform reports **technical evidence**. It never claims formal certification (ISO/SOC/PCI), never
claims "100% secure" or "100% bug-free," and separates *technical evidence relevant to a control* from
*compliance with a regulation* (the latter requires human/legal sign-off — spec I.5, IV.3).
