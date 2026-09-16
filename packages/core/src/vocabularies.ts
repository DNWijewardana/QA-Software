/**
 * Controlled vocabularies — the single source of truth for the evidence-classification
 * and lifecycle vocabularies that MUST be enforced everywhere.
 *
 * Spec ref: Master Prompt v2.0 §I.4 (evidence vocabulary + status), §I.6 (confidence),
 * §VII.1 (finding fields), §VIII.1 (execution modes), §VI.6 (job states).
 *
 * Critical invariant (§I.4): `NOT TESTED` must NEVER be converted into `PASS`.
 * This file defines the vocabularies; `invariants.ts` enforces the rules over them.
 */

/** How a result was established (§I.4). */
export const EVIDENCE_CLASSES = [
  'AUTOMATICALLY_VERIFIED',
  'AUTOMATICALLY_DETECTED',
  'INFERRED',
  'SUSPECTED',
  'MANUALLY_REQUIRED',
  'NOT_APPLICABLE',
  'UNABLE_TO_TEST',
  'INSUFFICIENT_EVIDENCE',
] as const;
export type EvidenceClass = (typeof EVIDENCE_CLASSES)[number];

/** Lifecycle status of a result (§I.4). */
export const STATUSES = [
  'PASS',
  'FAIL',
  'WARNING',
  'NOT_TESTED',
  'NOT_APPLICABLE',
  'BLOCKED',
  'INSUFFICIENT_EVIDENCE',
] as const;
export type Status = (typeof STATUSES)[number];

/** Confidence vocabulary (§I.6). */
export const CONFIDENCE_LEVELS = [
  'Confirmed',
  'Highly likely',
  'Likely',
  'Possible',
  'Informational',
  'Needs human verification',
] as const;
export type Confidence = (typeof CONFIDENCE_LEVELS)[number];

/** Severity / risk bands (§VII.3). */
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Reproducibility (§VII.1). */
export const REPRODUCIBILITY = ['Always', 'Often', 'Sometimes', 'Rarely', 'Unknown'] as const;
export type Reproducibility = (typeof REPRODUCIBILITY)[number];

/** Execution modes (§VIII.1). */
export const EXECUTION_MODES = [
  'SAFE_STATIC',
  'SAFE_DYNAMIC',
  'AUTHORIZED_SECURITY',
  'DESTRUCTIVE',
  'PRODUCTION',
] as const;
export type ExecutionMode = (typeof EXECUTION_MODES)[number];

/** Detection method for a finding (§IX.4). */
export const DETECTION_METHODS = [
  'static',
  'dynamic',
  'dependency',
  'config',
  'ai-assisted',
  'manual',
] as const;
export type DetectionMethod = (typeof DETECTION_METHODS)[number];

/** Job states (§VI.6). */
export const JOB_STATES = [
  'QUEUED',
  'PREPARING',
  'PROFILING',
  'STATIC_ANALYSIS',
  'TESTING',
  'SECURITY',
  'PERFORMANCE',
  'AGGREGATING',
  'REPORTING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
  'TIMEOUT',
  'PARTIAL',
] as const;
export type JobState = (typeof JOB_STATES)[number];

/** Release decisions (§VII.9 / §VII.19). */
export const RELEASE_DECISIONS = [
  'GO',
  'GO_WITH_CONDITIONS',
  'NO_GO',
  'INSUFFICIENT_EVIDENCE',
] as const;
export type ReleaseDecision = (typeof RELEASE_DECISIONS)[number];

/**
 * Quality dimensions scored independently (§VII.6).
 * Weights are configurable per project; these names are the canonical keys.
 */
export const QUALITY_DIMENSIONS = [
  'Functional',
  'Security',
  'Performance',
  'Reliability',
  'Accessibility',
  'Maintainability',
  'Compatibility',
  'Interaction',
  'Flexibility',
  'Safety',
  'QualityInUse',
  'TestEffectiveness',
  'Observability',
  'SupplyChainHealth',
  'ComplianceReadiness',
  'Privacy',
  'CloudIaCPosture',
] as const;
export type QualityDimension = (typeof QUALITY_DIMENSIONS)[number];

/** Evidence artifact types (§VII.2). */
export const EVIDENCE_TYPES = [
  'source-code',
  'test-output',
  'http-request',
  'http-response',
  'screenshot',
  'browser-trace',
  'console-error',
  'network-error',
  'performance-measurement',
  'dependency-record',
  'configuration',
  'log',
  'stack-trace',
] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];
