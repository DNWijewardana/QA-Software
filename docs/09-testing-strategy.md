# 09 — Testing Strategy

> Spec ref: PART X (Testing the Tester / Dogfooding), PART XI.6 (Definition of Done), PART XIII (Non-negotiables).
> This is a living design document. It describes how *this* platform is tested — a QA tool that is not itself
> trustworthy is worthless (§X). Every claim here is grounded in code that exists in the repository today; where
> a layer is not yet built, it is listed under **Deferred** rather than implied.

## 1. Principles (why this exists)

A platform whose job is to judge software quality must hold *itself* to a higher bar than the code it scans.
Two failure modes are unacceptable and are therefore tested directly, not assumed:

1. **Dishonesty** — reporting `PASS` for something `NOT TESTED`, hiding a Critical finding behind a good
   aggregate score, or leaking a secret/PII into evidence. These are the PART XIII non-negotiables.
2. **Silent detection regression** — a change that stops detecting a defect the platform used to catch. Per
   §X.4 this is *itself* a quality gate: a drop in recall fails the build.

The strategy below maps each of these risks to an automated test that would fail if the risk materialised.

## 2. Test pyramid (what runs, and where)

The suite runs under **Vitest** (`vitest.config.ts`) across the npm workspaces. Commands:

| Command | Purpose |
|---|---|
| `npm run typecheck` | `tsc --noEmit`, strict mode — the type system is the first test (invariants encoded in types). |
| `npm test` | `vitest run` — the whole suite. |
| `npm run benchmark` | Detection-quality benchmark against the golden corpus (exits non-zero on any recall drop). |

Current state: **36 test files pass + 1 skipped** (the BullMQ integration test self-skips without a Redis URL),
**114 tests pass + 1 skipped**. The layers:

| Layer | Scope | Representative tests |
|---|---|---|
| **Type-level** | Domain invariants encoded so illegal states don't compile | `tsc` strict across all workspaces |
| **Unit — invariants** | The non-negotiables as executable assertions | `invariants.test.ts`, `scoring.test.ts`, `redaction.test.ts` |
| **Unit — engines** | Each engine: seeded defects detected + no false positives on safe input | `secret`/`python`/`go`/`java`/`php`/`terraform`/… (one per engine) |
| **Contract** | Every emitted result validates against the Zod canonical contract (§IX.4) | `validateScanResult` called inside most engine tests |
| **Integration — delivery** | Async job lifecycle, HTTP API, auth/tenant isolation, rate-limit/audit | `jobs.test.ts`, `api.test.ts`, `auth.test.ts`, `audit-ratelimit.test.ts` |
| **Integration — persistence** | Real SQL via pg-mem; Redis-gated queue | `postgres-store.test.ts`, `postgres-audit.test.ts`, `bullmq.test.ts` |
| **System — dogfood/benchmark** | Run the platform against the whole corpus; measure recall | `dogfood.test.ts`, `benchmark.test.ts` |

## 3. Determinism first (§0.2)

Deterministic engines produce facts; AI (when enabled) only reasons/correlates/prioritises — it never invents a
finding. Consequences for testing:

- Engine tests assert **exact rule IDs** and, where false positives are a risk, **exact counts** (e.g. the PHP
  test asserts `PHP-EVAL-001` fires exactly once, proving the comment-stripping and the PDO `->exec` guard work).
- The same input always yields the same findings, so tests can assert on stable IDs and evidence hashes.
- No engine test depends on network, wall-clock, or an LLM. Remote-ingestion tests clone over `file://` (hermetic).

## 4. Engine tests: the two-sided contract

Every engine ships with a fixture-backed test that proves **both** directions, because a scanner that flags
everything is as useless as one that flags nothing:

- **Recall (positive):** an intentionally-flawed fixture under `fixtures/` seeds each rule; the test asserts every
  seeded rule ID appears.
- **Precision (negative):** a *safe* input (committed clean fixture or a runtime temp project) must produce **zero**
  findings for that engine's rule prefix. This is where comment-stripping, quote-awareness, and look-behind guards
  are proven — a false positive here fails the build.

New engines are required to add both sides plus a `GOLDEN_CORPUS` entry (see §6) before they are considered done.

## 5. Invariant tests (the non-negotiables, executable)

These encode PART XIII directly:

- **`NOT_TESTED` never becomes `PASS`** — enforced in the data model (`packages/core`) and asserted in
  `invariants.test.ts`; a `NOT_TESTED` status cannot be constructed as a pass.
- **Aggregate scores never hide Critical findings** — `scoring.test.ts` proves the score-gaming guards (§VII.8):
  a Critical finding forces the release decision regardless of a high dimension/overall score.
- **Secrets/PII are redacted in all output** — `redaction.test.ts`, `privacy.test.ts`, and `sql-secrets.test.ts`
  assert the *raw* value never reaches evidence on disk. `sql-secrets.test.ts` specifically guards the
  multi-PII-on-one-line leak that a naive per-value mask missed (see roadmap 2.25).
- **Untrusted input cannot inject into reports** — `html-report.test.ts` proves a `<script>`/`onerror` payload in
  a finding title is HTML-escaped (no stored XSS in the self-contained HTML report).

## 6. Dogfooding & the detection-quality gate (§X.1, §X.4)

`@qa/benchmark` runs the platform against the entire golden corpus and measures **recall** of the seeded defects.
The ground truth is `GOLDEN_CORPUS` (`packages/benchmark/src/corpus.ts`): every intentionally-flawed fixture mapped
to the rule IDs it must trigger — currently **116 seeded defects across all engines**.

- `npm run benchmark` prints a per-fixture recall table, writes `data/benchmark/benchmark.json`, and **exits 1** if
  any seeded defect is undetected.
- `benchmark.test.ts` asserts **100% recall** and an empty `missingRules` list, so any change that regresses
  detection fails CI. This is the spec's "regression on detection quality is itself a quality gate".

**Honest scope:** the benchmark measures recall only. Precision is *not* computed, because the single-purpose
fixtures legitimately raise unrelated findings that are not false positives; a fully-labelled corpus would be
required to measure precision honestly. This limitation is stated here rather than hidden (Rule 10).

## 7. Definition of Done (spec XI.6) — the checklist every feature clears

A feature is **not** done because it renders. It is done when:

- [ ] automated tests exist and pass (both recall and precision sides for an engine);
- [ ] findings are reproducible from a manifest / fixture;
- [ ] evidence is collected and every dynamic value is redacted/escaped;
- [ ] scores are explainable ("why?") and `NOT TESTED` is never shown as `PASS`;
- [ ] limitations are disclosed in the output, not omitted;
- [ ] the engine is added to the golden corpus and the 100%-recall gate still passes;
- [ ] `tsc` strict is clean.

## 8. Test data & fixtures

- Fixtures live under `fixtures/`, each isolated so one engine's fixture does not perturb another's counts.
- Fixtures that would fight `.gitignore` (e.g. a committed `.env`) or that must be large (performance budgets) are
  **built at runtime** into a temp dir and removed in `afterAll`, so nothing unsafe or bulky is committed.
- Every fixture file carries a header comment marking it as intentionally-insecure and **not for real use**.

## 9. CI gates (what must be green to merge)

1. `npm run typecheck` — strict, zero errors.
2. `npm test` — all non-skipped tests pass (BullMQ test requires `QA_REDIS_URL`; Postgres tests use pg-mem so they
   always run).
3. `npm run benchmark` — 100% recall, exit 0.

## 10. Deferred (not yet built — stated, not implied)

These layers are intentionally out of scope for the current SAFE_STATIC build and are gated on the Definition of
Ready (§0.3.1) or external tooling:

- **Dynamic-engine tests** (live security/perf/a11y-axe/API-contract) — require an authorized running target and the
  execution sandbox (§VIII.5); no external target is scanned in this build.
- **Precision benchmark** — requires a fully-labelled corpus (see §6).
- **Real-tool adapter tests** (Semgrep/ESLint/axe/ZAP) — require those binaries in the environment.
- **End-to-end browser tests of `apps/web`** — currently the web layer is verified by `next build` (types + routes)
  and live manual runs through the proxy; automated browser E2E is deferred.
- **Load/soak tests** of the distributed queue/store beyond the functional multi-process verification.
