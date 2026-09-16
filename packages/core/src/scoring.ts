/**
 * ScoreEngine — deterministic, explainable, multi-dimensional scoring.
 * Spec ref: §VII.6 (per-dimension, "why"), §VII.7 (confidence), §VII.8 (anti-gaming),
 * §VII.9 (gates + release readiness), §VII.19 (final recommendation).
 *
 * There is NO fake single score. Each dimension is computed independently from real findings,
 * and every score explains itself. The overall is gated by evidence coverage.
 */

import { checkCriticalVisibility, checkScoreInvariants, DEFAULT_COVERAGE_FLOOR } from './invariants.js';
import type {
  DimensionScore,
  Finding,
  OverallResult,
  ReleaseDecisionResult,
  GateResult,
} from './types.js';
import type { Confidence, QualityDimension, Severity } from './vocabularies.js';

/** Default weights (§VII.6) — NOT universal truth; overridable per project. */
export const DEFAULT_WEIGHTS: Partial<Record<QualityDimension, number>> = {
  Security: 0.2,
  Functional: 0.2,
  Reliability: 0.15,
  Performance: 0.1,
  Maintainability: 0.1,
  Accessibility: 0.1,
  Compatibility: 0.05,
  Interaction: 0.05,
  Flexibility: 0.05,
};

/** Deterministic penalty per active (FAIL/WARNING) finding, by severity. */
const SEVERITY_PENALTY: Record<Severity, number> = {
  Critical: 40,
  High: 20,
  Medium: 8,
  Low: 3,
  Informational: 0,
};

function isActive(f: Finding): boolean {
  return f.status === 'FAIL' || f.status === 'WARNING';
}

/** Map coverage + evidence to a confidence level (§VII.7). */
export function coverageToConfidence(coverage: number, anyManualNeeded: boolean): Confidence {
  if (anyManualNeeded) return 'Needs human verification';
  if (coverage >= 0.9) return 'Highly likely';
  if (coverage >= 0.7) return 'Likely';
  if (coverage >= 0.4) return 'Possible';
  return 'Informational';
}

export interface DimensionInput {
  dimension: QualityDimension;
  findings: Finding[];
  /** applicableChecks = how many checks the plan intended to run for this dimension. */
  applicableChecks: number;
  executedChecks: number;
  weight?: number;
}

/**
 * Compute one dimension's score from its findings. Deterministic and explainable.
 * WARNING findings count at half penalty; INFORMATIONAL never lowers the score.
 */
export function computeDimensionScore(input: DimensionInput): DimensionScore {
  const { dimension, findings } = input;
  const coverage =
    input.applicableChecks === 0 ? 0 : Math.min(1, input.executedChecks / input.applicableChecks);

  let deduction = 0;
  const counts: Record<Severity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };
  for (const f of findings) {
    if (!isActive(f)) continue;
    counts[f.severity] += 1;
    const factor = f.status === 'WARNING' ? 0.5 : 1;
    deduction += SEVERITY_PENALTY[f.severity] * factor;
  }

  const score = Math.max(0, Math.round(100 - deduction));
  const anyManual = findings.some((f) => f.evidenceClass === 'MANUALLY_REQUIRED');
  const confidence = coverageToConfidence(coverage, anyManual);

  const why: string[] = [];
  const activeTotal = (['Critical', 'High', 'Medium', 'Low'] as Severity[])
    .map((s) => counts[s])
    .reduce((a, b) => a + b, 0);
  if (activeTotal === 0) {
    why.push('No active FAIL/WARNING findings in executed checks.');
  } else {
    const parts = (['Critical', 'High', 'Medium', 'Low'] as Severity[])
      .filter((s) => counts[s] > 0)
      .map((s) => `${counts[s]} ${s}`);
    why.push(`Active findings: ${parts.join(', ')}.`);
  }
  why.push(
    `${input.executedChecks}/${input.applicableChecks} applicable checks executed (coverage ${(coverage * 100).toFixed(0)}%).`,
  );

  const unknowns: string[] = [];
  if (coverage < 1) unknowns.push(`${input.applicableChecks - input.executedChecks} check(s) not executed.`);
  if (anyManual) unknowns.push('Some checks require manual verification.');

  const ds: DimensionScore = {
    dimension,
    score,
    confidence,
    coverage,
    weight: input.weight ?? DEFAULT_WEIGHTS[dimension] ?? 0,
    why,
    unknowns,
  };

  const violations = checkScoreInvariants(ds);
  if (violations.length > 0) {
    throw new Error(
      'Score invariant violation:\n' + violations.map((x) => `  [${x.code}] ${x.message}`).join('\n'),
    );
  }
  return ds;
}

/** Compute overall result. Gated by evidence coverage (§VII.6, §VII.8). */
export function computeOverall(
  scores: DimensionScore[],
  findings: Finding[],
  opts: { coverageFloor?: number; overallCoverageThreshold?: number } = {},
): OverallResult {
  const coverageFloor = opts.coverageFloor ?? DEFAULT_COVERAGE_FLOOR;
  const overallCoverageThreshold = opts.overallCoverageThreshold ?? 0.4;

  const totalWeight = scores.reduce((a, s) => a + s.weight, 0);
  const evidenceCoverage =
    scores.length === 0 ? 0 : scores.reduce((a, s) => a + s.coverage, 0) / scores.length;

  const criticalBlockers = findings.filter(
    (f) => f.status === 'FAIL' && f.severity === 'Critical',
  ).length;
  const highRiskFindings = findings.filter(
    (f) => f.status === 'FAIL' && (f.severity === 'High' || f.severity === 'Critical'),
  ).length;
  const manualVerificationRequired = findings.filter(
    (f) => f.evidenceClass === 'MANUALLY_REQUIRED',
  ).length;

  // Overall score is only computed when evidence is sufficient (§VII.6). Else null.
  let score: number | null = null;
  let confidence: Confidence = 'Informational';
  if (evidenceCoverage >= overallCoverageThreshold && totalWeight > 0) {
    const weighted =
      scores.reduce((a, s) => a + s.score * s.weight, 0) / totalWeight;
    score = Math.round(weighted);
    confidence = coverageToConfidence(evidenceCoverage, manualVerificationRequired > 0);
  }

  const untestedAreas = scores.filter((s) => s.coverage < coverageFloor).map((s) => s.dimension);

  const overall: OverallResult = {
    score,
    confidence,
    evidenceCoverage,
    criticalBlockers,
    highRiskFindings,
    untestedAreas,
    manualVerificationRequired,
  };

  // §VII.8: aggregate must not hide Critical findings.
  const vis = checkCriticalVisibility(findings, criticalBlockers);
  if (vis.length > 0) {
    throw new Error('Critical visibility invariant violation: ' + vis[0]!.message);
  }
  return overall;
}

/** Quality gates → release decision (§VII.9, §VII.19). Never a naive average. */
export function decideRelease(
  overall: OverallResult,
  findings: Finding[],
  opts: { maxHigh?: number } = {},
): ReleaseDecisionResult {
  const maxHigh = opts.maxHigh ?? 0;
  const gatesEvaluated: GateResult[] = [];
  const conditions: string[] = [];

  const criticalFail = findings.some((f) => f.status === 'FAIL' && f.severity === 'Critical');
  gatesEvaluated.push({ gate: 'no-critical-findings', result: criticalFail ? 'FAIL' : 'PASS' });

  const highCount = findings.filter((f) => f.status === 'FAIL' && f.severity === 'High').length;
  gatesEvaluated.push({ gate: `max-high-findings(${maxHigh})`, result: highCount > maxHigh ? 'FAIL' : 'PASS' });

  const evidenceGate = overall.evidenceCoverage >= 0.4 ? 'PASS' : 'INSUFFICIENT_EVIDENCE';
  gatesEvaluated.push({ gate: 'minimum-evidence-coverage', result: evidenceGate });

  // Never GO if critical evidence is missing (§VII.9).
  if (evidenceGate === 'INSUFFICIENT_EVIDENCE' || overall.score === null) {
    return {
      decision: 'INSUFFICIENT_EVIDENCE',
      conditions: ['Increase evidence coverage before a release decision can be made.'],
      gatesEvaluated,
      rationale:
        'Evidence coverage is below the minimum threshold; a release decision cannot be responsibly made.',
    };
  }
  if (criticalFail) {
    return {
      decision: 'NO_GO',
      conditions: ['Resolve all Critical findings.'],
      gatesEvaluated,
      rationale: 'One or more Critical findings failed; release is blocked regardless of aggregate score.',
    };
  }
  if (highCount > maxHigh) {
    conditions.push(`Reduce High findings from ${highCount} to ≤ ${maxHigh}.`);
    return {
      decision: 'GO_WITH_CONDITIONS',
      conditions,
      gatesEvaluated,
      rationale: `No Critical findings, but ${highCount} High finding(s) exceed the budget of ${maxHigh}.`,
    };
  }
  return {
    decision: 'GO',
    conditions,
    gatesEvaluated,
    rationale: 'All configured quality gates passed with sufficient evidence coverage.',
  };
}
