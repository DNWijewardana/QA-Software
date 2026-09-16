# 02 — System Architecture

> Spec ref: PART VI (Engines, Orchestration & Platform Architecture), VI.5 reference architecture.

## 1. Reference architecture (spec VI.5)

```
                          ┌────────────────────────────────────────────┐
   Browser ──HTTPS──►  apps/web (Next.js)                               │
                          └───────────────┬────────────────────────────┘
                                          │ REST (versioned, IX.4 contract)
                          ┌───────────────▼────────────────────────────┐
                          │  apps/api (NestJS)                          │
                          │  auth · projects · scans · jobs · findings  │
                          │  reports · policies · suppressions · audit  │
                          └───────┬───────────────────────┬────────────┘
             enqueue job (BullMQ) │                       │ read/write
                          ┌───────▼────────┐      ┌───────▼────────────┐
                          │  Redis queue   │      │  PostgreSQL        │
                          │  (jobs/states) │      │  (traceability)    │
                          └───────┬────────┘      └────────────────────┘
                          ┌───────▼──────────────────────────────────┐
                          │ apps/worker (BullMQ worker)               │
                          │  Orchestrator: runs the engine pipeline   │
                          │  inside an EPHEMERAL SANDBOX per job       │
                          └───────┬───────────────────────────────────┘
             ┌────────────────────┼────────────────────────────┐
   packages/engines (plugins) via stable interfaces (VI.2):
   Profiler · Scanner · TestEngine · SecurityEngine · CodeAnalyzer · DependencyAnalyzer …
             │                    │                             │
             ▼                    ▼                             ▼
   Evidence Store (object storage)      Analysis/Quality Engine (scoring, VII.6)
             │                                    │
             └──────────────► Reporting Engine (dual output IX.4 + human IX.1)
```

## 2. Why these choices (spec XI.2 — justify, don't pick by popularity)

| Concern | Choice | Justification |
|---|---|---|
| Language | TypeScript everywhere | One type system spans web/api/worker/engines; the canonical Finding/Evidence types (`packages/core`) are shared and compiler-enforced across all tiers — directly supports invariants like `NOT TESTED ↛ PASS`. |
| API framework | NestJS _(planned)_ | Modular DI, guards for RBAC/tenant isolation, validation pipes, OpenAPI generation. **Phase-2 deviation (spec XI.1 — replacement with justification):** the current `apps/api` is a thin, structured `node:http` layer, because the workspace is ESM/NodeNext and NestJS is CommonJS-first with a brittle ESM story. This keeps the delivery layer verifiable with zero infra/framework friction. The `ScanService`/`JobQueue`/`ScanStore` abstractions are framework-agnostic, so a NestJS migration is low-risk once Postgres/BullMQ adapters land. |
| Frontend | Next.js + Tailwind | SSR for a dense, fast, accessible app UI (must meet WCAG 2.2 AA, IX.8). |
| Job system | BullMQ + Redis | Async, resumable, cancellable, prioritized, retryable, dead-letter, backpressure (VI.7). Never block web tier. |
| Transactional DB | PostgreSQL | Strong constraints enforce traceability & score invariants at the schema level (CHECK constraints, FKs). |
| Evidence store | Object storage (S3-compatible; local FS in dev) | Evidence artifacts (screenshots, traces, HTTP pairs) are large/immutable — wrong fit for a relational row (VI.5 polyglot). |
| Search (later) | OpenSearch/Meilisearch | Global search across findings/files/endpoints (IX.7). Optional. |

**Polyglot persistence is deliberate (VI.5):** relational for transactional/traceability data, object
storage for evidence, time-series (later) for trends, search index for global search, optional graph for
dependency/traceability graphs — each justified, not defaulted.

## 3. Engine plugin architecture (spec VI.2)

No hard-coding around one tool. Every engine implements a stable interface in `packages/engines`:

```
TestEngine · Scanner · BrowserEngine · SecurityEngine · PerformanceEngine · AccessibilityEngine ·
DependencyAnalyzer · CodeAnalyzer · IaCAnalyzer · CloudPostureAnalyzer · ComplianceMapper ·
AIEvalEngine · EvidenceCollector · ReportGenerator · ScoreEngine · PolicyEngine · AIAnalyzer
```

Each engine: declares applicability (which detected tech it runs on), emits `Finding[]` + `Evidence[]`,
records the tools/versions it used into the execution manifest, and is independently runnable/observable.

Concrete adapters are wired lazily; a missing external tool degrades to `UNABLE_TO_TEST`/`INSUFFICIENT_EVIDENCE`
— **never a silent pass** (spec §0.2.1, XII.2).

## 4. Orchestration pipeline (spec VI.1)

```
Project → Profiler → Risk Engine → Test Planner → Static Analysis → Unit → Integration → API →
Browser → Accessibility → Security → Performance → Dependency/Supply-Chain → IaC/Cloud Posture →
Architecture → Observability → Compliance Mapping → Evidence Aggregator → AI Reasoning →
Quality Engine → Report Generator
```

Each stage is independently runnable, observable, and **resumable**. Job states (VI.6):
`QUEUED → PREPARING → PROFILING → STATIC_ANALYSIS → TESTING → SECURITY → PERFORMANCE → AGGREGATING →
REPORTING → COMPLETED` plus `FAILED · CANCELLED · TIMEOUT · PARTIAL`.

Phase 1 exercises a **thin subset**: `Profiler → Static Analysis → Evidence Aggregator → Quality Engine →
Report Generator`. Unimplemented stages are explicitly `NOT TESTED`, never faked.

## 5. Determinism / AI boundary (spec §0.2.2, X.5)

- **Deterministic tier** (compilers, linters, scanners, tests, schema validators) decides all facts.
- **AI tier** only: correlates findings, prioritizes by risk, drafts remediation, hypothesizes root causes,
  interprets requirements. Every AI output carries evidence + reasoning summary + confidence + source, and
  is a **hypothesis requiring verification** (§0.2.3). AI never converts `NOT TESTED` to `PASS`.

## 6. Cross-cutting concerns

- **Security/sandbox:** see `06-security-sandbox-model.md`.
- **Data model & invariants:** see `03-data-model.md`.
- **Output contract:** see `07-api-and-output-contract.md`.
- **Observability:** structured logs (pino), OpenTelemetry traces, health/readiness endpoints, job metrics;
  the platform defines its own SLIs/SLOs (X.6).
