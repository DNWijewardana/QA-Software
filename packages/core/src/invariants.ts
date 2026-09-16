/**
 * Enforced invariants — the honesty guarantees of the platform, expressed as code.
 *
 * Spec ref: §I.4 (NOT TESTED ↛ PASS), §VII.2 (no evidence ⇒ never "confirmed"),
 * §VII.8 (anti score-gaming), §XIII Tier 1 (integrity rules).
 *
 * These are validated at construction time and again before any result leaves the system.
 * A violation is a BUG, not a warning — callers should treat it as fatal.
 */

import type { DimensionScore, Finding } from './types.js';
import type { Status } from './vocabularies.js';

export interface InvariantViolation {
  code: string;
  message: string;
  subject: string; // finding id / dimension name
}

const VERIFIED_CLASSES = new Set(['AUTOMATICALLY_VERIFIED', 'AUTOMATICALLY_DETECTED']);
const HONEST_NOT_TESTED_CLASSES = new Set([
  'UNABLE_TO_TEST',
  'INSUFFICIENT_EVIDENCE',
  'MANUALLY_REQUIRED',
  'NOT_APPLICABLE',
]);

/**
 * INVARIANT (§I.4, §XIII rule 5): `NOT_TESTED` must NEVER be converted into `PASS`.
 * Any code path that changes a status MUST route through this guard.
 * Returns the requested status only if the transition is legal; otherwise throws.
 */
export function transitionStatus(from: Status, to: Status): Status {
  if (from === 'NOT_TESTED' && to === 'PASS') {
    throw new Error(
      "Invariant violation (§I.4): 'NOT_TESTED' cannot transition to 'PASS'. " +
        'Run a real test that produces verified evidence, or keep it NOT_TESTED.',
    );
  }
  return to;
}

/** Validate a single finding against Tier-1 integrity invariants. */
export function checkFindingInvariants(f: Finding): InvariantViolation[] {
  const v: InvariantViolation[] = [];

  // A PASS may never rest on a non-verified evidence class (§VII.2).
  if (f.status === 'PASS' && !VERIFIED_CLASSES.has(f.evidenceClass)) {
    v.push({
      code: 'PASS_WITHOUT_VERIFICATION',
      subject: f.id,
      message: `PASS requires an AUTOMATICALLY_VERIFIED/DETECTED evidence class, got '${f.evidenceClass}'.`,
    });
  }

  // NOT_TESTED must carry an honest evidence class — never a verified one (§I.4).
  if (f.status === 'NOT_TESTED' && !HONEST_NOT_TESTED_CLASSES.has(f.evidenceClass)) {
    v.push({
      code: 'NOT_TESTED_DISHONEST_CLASS',
      subject: f.id,
      message: `NOT_TESTED must use UNABLE_TO_TEST/INSUFFICIENT_EVIDENCE/MANUALLY_REQUIRED/NOT_APPLICABLE, got '${f.evidenceClass}'.`,
    });
  }

  // "Confirmed" confidence requires at least one evidence artifact (§VII.2).
  if (f.confidence === 'Confirmed' && f.evidence.length === 0) {
    v.push({
      code: 'CONFIRMED_WITHOUT_EVIDENCE',
      subject: f.id,
      message: "A 'Confirmed' finding must carry at least one evidence artifact.",
    });
  }

  // A confirmed, serious FAIL must carry evidence (§VII.2 — no evidence ⇒ never confirmed).
  if (
    f.status === 'FAIL' &&
    (f.severity === 'Critical' || f.severity === 'High') &&
    f.confidence === 'Confirmed' &&
    f.evidence.length === 0
  ) {
    v.push({
      code: 'SERIOUS_FAIL_WITHOUT_EVIDENCE',
      subject: f.id,
      message: `A Confirmed ${f.severity} FAIL must carry evidence.`,
    });
  }

  return v;
}

/** Configurable floor below which a dimension cannot be "green" (§VII.8 [v2.0]). */
export const DEFAULT_COVERAGE_FLOOR = 0.5;

/** Validate a dimension score against anti-gaming invariants (§VII.8). */
export function checkScoreInvariants(
  s: DimensionScore,
  coverageFloor = DEFAULT_COVERAGE_FLOOR,
): InvariantViolation[] {
  const v: InvariantViolation[] = [];

  // Every score must explain itself (§VII.6).
  if (s.why.length === 0) {
    v.push({
      code: 'SCORE_WITHOUT_WHY',
      subject: s.dimension,
      message: 'Every dimension score must answer "why?" — the why[] array is empty.',
    });
  }

  if (s.score < 0 || s.score > 100) {
    v.push({
      code: 'SCORE_OUT_OF_RANGE',
      subject: s.dimension,
      message: `Score must be 0..100, got ${s.score}.`,
    });
  }

  // Coverage floor: a low-coverage dimension cannot present as high-confidence "green" (§VII.8).
  if (s.coverage < coverageFloor && (s.confidence === 'Confirmed' || s.confidence === 'Highly likely')) {
    v.push({
      code: 'GREEN_WITH_LOW_COVERAGE',
      subject: s.dimension,
      message: `Coverage ${s.coverage} is below floor ${coverageFloor}; confidence cannot be '${s.confidence}'.`,
    });
  }

  return v;
}

/**
 * Guard against score-gaming that hides Critical findings (§VII.8 rule 2, §XIII rule 22).
 * Returns violations if any Critical/High FAIL is not surfaced independently of the aggregate.
 */
export function checkCriticalVisibility(
  findings: Finding[],
  overallCriticalBlockers: number,
): InvariantViolation[] {
  const actualCritical = findings.filter(
    (f) => f.status === 'FAIL' && f.severity === 'Critical',
  ).length;
  if (actualCritical > 0 && overallCriticalBlockers < actualCritical) {
    return [
      {
        code: 'CRITICAL_HIDDEN_BY_AGGREGATE',
        subject: 'overall',
        message: `Found ${actualCritical} Critical FAIL findings but overall reports only ${overallCriticalBlockers} critical blockers. Aggregate must not hide Critical findings.`,
      },
    ];
  }
  return [];
}

/** Convenience: assert a batch of findings, throwing on any violation. */
export function assertFindings(findings: Finding[]): void {
  const violations = findings.flatMap(checkFindingInvariants);
  if (violations.length > 0) {
    throw new Error(
      'Finding invariant violations:\n' +
        violations.map((x) => `  [${x.code}] ${x.subject}: ${x.message}`).join('\n'),
    );
  }
}
