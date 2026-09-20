/**
 * Configurable policy engine (§VII.11, §86). Organizations must not have policy hard-coded: dimension
 * weights, the High-findings budget, and evidence thresholds are configurable per scan/project.
 *
 * HONESTY GUARD (§VII.8, Rule 22/23): a policy can NEVER hide or un-block a Critical finding. Critical
 * findings always block the release decision regardless of policy; the scoring invariants (Critical
 * visibility, NOT_TESTED↛PASS) are enforced independently of weights. Policy tunes emphasis and the
 * High-budget/evidence gates only — it cannot make a serious failure disappear.
 */

import { DEFAULT_WEIGHTS } from './scoring.js';
import { DEFAULT_COVERAGE_FLOOR } from './invariants.js';
import type { QualityDimension } from './vocabularies.js';

export interface QualityGatePolicy {
  /** Maximum tolerated High findings before the decision is GO_WITH_CONDITIONS. Default 0. */
  maxHigh?: number;
  /** Minimum evidence coverage (0..1) required to make a release decision at all. Default 0.4. */
  minEvidenceCoverage?: number;
}

export interface ScanPolicy {
  /** Per-dimension weights (relative; normalized at scoring time). Overrides DEFAULT_WEIGHTS per key. */
  weights?: Partial<Record<QualityDimension, number>>;
  gates?: QualityGatePolicy;
  /** Coverage below this floor marks a dimension as an untested area (0..1). Default DEFAULT_COVERAGE_FLOOR. */
  coverageFloor?: number;
}

export interface ResolvedPolicy {
  weights: Partial<Record<QualityDimension, number>>;
  maxHigh: number;
  minEvidenceCoverage: number;
  coverageFloor: number;
}

function clamp01(n: number, fallback: number): number {
  if (!Number.isFinite(n)) return fallback;
  return Math.min(1, Math.max(0, n));
}

/**
 * Normalize a (possibly partial or absent) policy into concrete, clamped values. Omitting a policy — or any
 * field — reproduces the platform defaults exactly, so the default behavior is unchanged.
 */
export function resolvePolicy(policy?: ScanPolicy): ResolvedPolicy {
  const weights: Partial<Record<QualityDimension, number>> = { ...DEFAULT_WEIGHTS };
  if (policy?.weights) {
    for (const [dim, w] of Object.entries(policy.weights)) {
      // Weights are relative and non-negative; a negative or non-finite weight is ignored (kept default).
      if (typeof w === 'number' && Number.isFinite(w) && w >= 0) {
        weights[dim as QualityDimension] = w;
      }
    }
  }
  const maxHighRaw = policy?.gates?.maxHigh;
  const maxHigh = typeof maxHighRaw === 'number' && Number.isFinite(maxHighRaw) && maxHighRaw >= 0 ? Math.floor(maxHighRaw) : 0;
  const minEvidenceCoverage = policy?.gates?.minEvidenceCoverage === undefined ? 0.4 : clamp01(policy.gates.minEvidenceCoverage, 0.4);
  const coverageFloor = policy?.coverageFloor === undefined ? DEFAULT_COVERAGE_FLOOR : clamp01(policy.coverageFloor, DEFAULT_COVERAGE_FLOOR);
  return { weights, maxHigh, minEvidenceCoverage, coverageFloor };
}
