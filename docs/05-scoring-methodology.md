# 05 — Scoring Methodology

> Spec ref: PART VII.6 (multi-dimensional scoring), VII.7 (confidence), VII.8 (anti-gaming invariants),
> VII.9 (gates & release readiness), VII.19 (final recommendation).

## 1. No single fake score (spec VII.6)

Quality is scored **per dimension**, independently. Each dimension carries: raw evidence · measurements ·
weighted score · confidence · coverage · unknowns. An overall score is computed **only when enough evidence
exists**, and never by naive averaging.

Dimensions (spec VII.6): Functional · Security · Performance · Reliability · Accessibility · Maintainability ·
Compatibility · Interaction · Flexibility · Safety · Quality-in-Use · Test Effectiveness · Observability ·
Supply-Chain Health · Compliance Readiness · Privacy · Cloud/IaC Posture.

## 2. Per-dimension score object

```
DimensionScore {
  dimension: string
  score: 0..100            // computed from findings + measurements, NOT invented
  confidence: Confidence   // reflects test count/quality, env realism, tool reliability (VII.7)
  coverage: 0..1           // fraction of applicable checks actually executed
  weight: 0..1             // configurable per project (defaults below)
  why: string[]            // REQUIRED, non-empty — every score explains itself (VII.6)
  unknowns: string[]       // what wasn't tested / is uncertain
}
```

**Every score must answer "WHY?"** e.g. `Security 74 — 3 high-risk findings, 1 critical missing control,
92% automated checks executed, authorization testing incomplete` (spec VII.6). A score with empty `why` is
invalid and rejected.

## 3. Default weights (spec VII.6 — NOT universal truth; configurable per project)

`Security 20 · Functional 20 · Reliability 15 · Performance 10 · Maintainability 10 · Accessibility 10 ·
Compatibility 5 · Interaction 5 · Flexibility 5`. Orgs override via the policy engine (VII.11).

## 4. Confidence model (spec VII.7)

Confidence is a function of: number & quality of tests · environment realism · tool reliability · evidence
quality · manual verification · unknown components · scan limitations. Example:
`Security 91 — Confidence: Low — only static analysis available; dynamic security testing not performed.`

## 5. Anti-gaming invariants (spec VII.8) — enforced in the ScoreEngine + tests

1. **`NOT TESTED` never becomes `PASS`.** (Also enforced at the DB layer, doc 03.)
2. **A high overall score cannot mask a Critical finding.** Critical/High findings surface independently of
   any aggregate, always.
3. **The scoring system never hides serious security or functional failures.**
4. **Coverage floor:** any dimension with `coverage` below a configurable floor is reported **low-confidence**
   and **cannot contribute a "green" status** (spec VII.8 `[v2.0]`).

These are covered by unit tests in the ScoreEngine (a red test for each invariant), so a regression that
would let a score hide a Critical finding fails the build.

## 6. Overall score (only when justified)

Computed as a weighted aggregation **gated by evidence coverage**. The overall result must always include:
`score · confidence · evidenceCoverage · unknownAreas · untestedAreas · criticalBlockers` (spec VII.6).
If evidence coverage is below threshold → overall is reported as `INSUFFICIENT EVIDENCE`, not a number.

## 7. Quality gates & budgets (spec VII.9)

**Gates (configurable) — DO NOT RELEASE if:** critical security issue · critical functional failure ·
required accessibility gate fails · catastrophic data-integrity failure · unacceptable performance threshold ·
required tests fail · prod health checks fail.

**Budgets:** max critical/high · max a11y violations · max perf regression · max dependency risk · max flaky
rate · max complexity · max tech debt · max license-risk · max unresolved KEV vulns.

## 8. Release decision (spec VII.9, VII.19)

`GO · GO WITH CONDITIONS · NO-GO · INSUFFICIENT EVIDENCE` — derived from policy + severity + risk + gates +
evidence + confidence. **Never GO if critical evidence is missing. Never a naive average of category scores.**
The decision object records which gates were evaluated and their results, plus a rationale.

## 9. Worked example of honest reporting (spec XII.1)

> ✅ "Security: 74/100 (Confidence: Low). 3 High findings (2 confirmed, 1 suspected), 1 Critical missing
> authorization control (confirmed via HTTP evidence), 92% of automated security checks executed. Dynamic
> authorization testing was NOT performed; authorization confidence is limited. `NOT TESTED` items were not
> converted to `PASS`."
