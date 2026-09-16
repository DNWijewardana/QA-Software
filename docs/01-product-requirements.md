# 01 — Product Requirements Document

> Spec ref: PART I (Mission), PART III (Scope), PART V (Quality Domains), PART IX (Reporting).

## 1. Problem & mission

Professional software teams lack a single, honest, evidence-driven system to assess software quality
across all relevant dimensions. Existing tools either (a) produce one misleading score, (b) fake
"AI-powered" recommendations, or (c) look impressive but have hollow internals (spec I.2).

**Mission:** build a universal Software Quality Assessment & Testing platform that combines deterministic
analysis, dynamic testing, and AI-assisted reasoning, and that is **honest about what it tested, what it
did not, and how confident it is** (spec I.1, I.3).

## 2. Users & roles (spec VIII.8)

Owner · Admin · QA Manager · Security Analyst · Developer · Viewer · Auditor · Compliance Officer.
Each org is fully isolated (multi-tenancy; Org A must never access Org B data — a first-class, tested control).

## 3. Two operating capabilities (spec I.3)

1. **Static Quality Assessment** — analyze uploaded code/config only (SAFE STATIC).
2. **Dynamic Quality Testing** — test a controlled/authorized environment (gated by Definition of Ready §0.3.1).

## 4. Functional requirements (MoSCoW)

### MUST (Phase 1 vertical slice targets marked ★)
- FR-1 ★ Ingest a project (ZIP upload for slice; Git/registry integrations later — spec III.2).
- FR-2 ★ Auto-detect stack with **recorded detection confidence** (Profiler — spec III.2/III.3, never assume).
- FR-3 ★ Run engines as **async jobs** with observable, resumable stages; **no fake progress** (VI.6).
- FR-4 ★ Produce **Findings** conforming to the canonical Finding schema (VII.1) with linked **Evidence** (VII.2).
- FR-5 ★ Classify every result with the **evidence-class** and **status** vocabularies (I.4); enforce
  `NOT TESTED` ↛ `PASS` at the data-model level (I.4 invariant, VII.8).
- FR-6 ★ Score dimensions independently, each with score + confidence + coverage + unknowns; every score
  answers **"why?"** (VII.6). No fake single score.
- FR-7 ★ Emit **dual output**: canonical JSON contract (IX.4) + human-readable report (IX.1). Rule 36.
- FR-8 Risk-based test planning (VII.4); regression intelligence (VII.5).
- FR-9 Release Readiness decision: `GO / GO WITH CONDITIONS / NO-GO / INSUFFICIENT EVIDENCE` (VII.9) — never a naive average.
- FR-10 False-positive management: scoped, auditable, expiring suppressions; no global "ignore all" (VII.17).
- FR-11 Differential / trend analysis vs baselines (VII.10).
- FR-12 Report exports: PDF · HTML · JSON · CSV · SARIF · CycloneDX/SPDX · JUnit XML (IX.3).

### SHOULD
- Requirements traceability matrix (VII.13); compliance control-coverage matrix (IV.3); SBOM (V.17).

### COULD
- AI/LLM eval harness (V.26); CSPM/IaC posture (V.18); mutation testing (V.21); visual regression (V.32).

### WON'T (this build)
- Testing unauthorized/external targets; destructive tests by default; legal compliance *certification*.

## 5. Non-functional requirements

- **NFR-1 Honesty (hard bans, spec I.5):** never claim 100% secure/bug-free or formal certification.
- **NFR-2 Security:** treat all uploads as untrusted; sandbox execution; encrypt in transit & at rest;
  redact secrets/PII everywhere (PART VIII).
- **NFR-3 Reproducibility:** every result re-derivable from an execution manifest (§0.2.6, VIII.6).
- **NFR-4 Scalability:** async, queued, parallel, cancellable, rate-limited; never block the web app (VI.7).
- **NFR-5 Accessibility:** the platform's own UI meets **WCAG 2.2 AA** (IX.8).
- **NFR-6 Observability:** structured logs, metrics, traces, health checks; platform has its own SLIs/SLOs (X.6).
- **NFR-7 Auditability:** tamper-evident (append-only/hash-chained) audit log for enterprise (VIII.7).

## 6. Quality domains in scope

The full taxonomy is spec PART V (V.1–V.34). Phase 1 implements a thin path through **code quality (V.9)**
and/or **security (V.7)** to prove the pipeline end-to-end; remaining domains are added incrementally
(roadmap Phase 2+), each behind the plugin interface with golden-corpus benchmarks.

## 7. Acceptance criteria (Phase 1)

Given a fixture project with **known seeded defects**, the platform:
1. detects the stack and records confidence;
2. runs the static engine in a sandboxed async job with truthful progress;
3. reports the seeded defects as Findings with real evidence and correct evidence-class/status;
4. produces a dimension score that explains *why*, with coverage and unknowns;
5. emits both the canonical JSON contract and a human report;
6. never reports an untested item as `PASS`.
