/**
 * @qa/contracts — the canonical machine-readable output contract (§IX.4) as a Zod schema.
 *
 * This is the single source of truth for the structured output that CI/CD, dashboards, and other
 * agents consume. A JSON Schema can be generated from it. Validation of every emitted ScanResult
 * against this schema is a Definition-of-Done gate (§X.4 — catch contract drift in CI).
 *
 * The schema mirrors @qa/core types; `validateScanResult` also confirms the two never drift, because
 * the parsed output is assignable to the core `ScanResult` type (checked at compile time in tests).
 */

import { z } from 'zod';
import {
  CONFIDENCE_LEVELS,
  DETECTION_METHODS,
  EVIDENCE_CLASSES,
  EVIDENCE_TYPES,
  EXECUTION_MODES,
  QUALITY_DIMENSIONS,
  RELEASE_DECISIONS,
  REPRODUCIBILITY,
  SEVERITIES,
  STATUSES,
} from '@qa/core';

const zEnum = <T extends readonly [string, ...string[]]>(vals: T) => z.enum(vals);

export const EvidenceRefSchema = z.object({
  type: zEnum(EVIDENCE_TYPES as unknown as [string, ...string[]]),
  ref: z.string().min(1),
  redacted: z.boolean(),
  snippet: z.string().optional(),
});

export const CvssSchema = z.object({
  version: z.enum(['3.1', '4.0']),
  vector: z.string(),
  score: z.number().min(0).max(10),
});

export const FindingSchema = z
  .object({
    id: z.string().min(1),
    ruleId: z.string().min(1),
    category: z.string().min(1),
    subcategory: z.string().optional(),
    title: z.string().min(1),
    description: z.string(),
    status: zEnum(STATUSES as unknown as [string, ...string[]]),
    evidenceClass: zEnum(EVIDENCE_CLASSES as unknown as [string, ...string[]]),
    severity: zEnum(SEVERITIES as unknown as [string, ...string[]]),
    risk: zEnum(SEVERITIES as unknown as [string, ...string[]]),
    confidence: zEnum(CONFIDENCE_LEVELS as unknown as [string, ...string[]]),
    reproducibility: zEnum(REPRODUCIBILITY as unknown as [string, ...string[]]),
    cwe: z.array(z.string()),
    cve: z.array(z.string()),
    cvss: CvssSchema.optional(),
    exploitability: z.object({ epss: z.number().nullable(), kev: z.boolean() }).optional(),
    affectedComponent: z.string().optional(),
    location: z.object({
      file: z.string().optional(),
      url: z.string().optional(),
      endpoint: z.string().optional(),
      line: z.number().int().optional(),
    }),
    detectionMethod: zEnum(DETECTION_METHODS as unknown as [string, ...string[]]),
    toolUsed: z.string().optional(),
    evidence: z.array(EvidenceRefSchema),
    rootCauseHypothesis: z
      .object({
        statement: z.string(),
        confidence: zEnum(CONFIDENCE_LEVELS as unknown as [string, ...string[]]),
        verification: z.string(),
      })
      .optional(),
    remediation: z
      .object({
        summary: z.string(),
        effort: z.enum(['S', 'M', 'L']),
        riskReduction: zEnum(SEVERITIES as unknown as [string, ...string[]]),
      })
      .optional(),
    verificationMethod: z.string().optional(),
    standards: z.array(z.object({ framework: z.string(), version: z.string(), id: z.string() })),
    traceability: z.object({ requirements: z.array(z.string()), tests: z.array(z.string()) }),
    owner: z.string().nullable().optional(),
    targetFixDate: z.string().nullable().optional(),
  })
  // Contract-level echo of the core invariants (§I.4, §VII.2) so bad output is rejected at the boundary.
  .refine((f) => !(f.status === 'PASS' && !['AUTOMATICALLY_VERIFIED', 'AUTOMATICALLY_DETECTED'].includes(f.evidenceClass)), {
    message: 'PASS requires a verified evidence class (§VII.2).',
    path: ['status'],
  })
  .refine((f) => !(f.status === 'NOT_TESTED' && ['AUTOMATICALLY_VERIFIED', 'AUTOMATICALLY_DETECTED'].includes(f.evidenceClass)), {
    message: 'NOT_TESTED must not use a verified evidence class (§I.4).',
    path: ['status'],
  })
  .refine((f) => !(f.confidence === 'Confirmed' && f.evidence.length === 0), {
    message: "A 'Confirmed' finding must carry at least one evidence artifact (§VII.2).",
    path: ['confidence'],
  });

export const DimensionScoreSchema = z.object({
  dimension: zEnum(QUALITY_DIMENSIONS as unknown as [string, ...string[]]),
  score: z.number().min(0).max(100),
  confidence: zEnum(CONFIDENCE_LEVELS as unknown as [string, ...string[]]),
  coverage: z.number().min(0).max(1),
  weight: z.number().min(0).max(1),
  why: z.array(z.string()).min(1, 'Every score must answer "why?" (§VII.6).'),
  unknowns: z.array(z.string()),
});

export const SbomComponentSchema = z.object({
  name: z.string(),
  version: z.string(),
  type: z.enum(['library', 'framework', 'application']),
  purl: z.string().optional(),
  scope: z.enum(['required', 'optional']),
  vulnerabilityStatus: zEnum(STATUSES as unknown as [string, ...string[]]),
});

export const SbomSchema = z.object({
  format: z.literal('CycloneDX'),
  specVersion: z.literal('1.5'),
  generatedAt: z.string(),
  components: z.array(SbomComponentSchema),
  source: z.enum(['manifest', 'lockfile']),
  notes: z.array(z.string()),
});

export const ComplianceMatrixSchema = z.object({
  disclaimer: z.string(),
  frameworks: z.array(z.string()),
  controls: z.array(
    z.object({
      framework: z.string(),
      controlId: z.string(),
      title: z.string(),
      status: z.enum(['SATISFIED', 'GAPS', 'NOT_ASSESSED']),
      mappedRules: z.array(z.string()),
      gapFindings: z.array(z.string()),
      note: z.string(),
    }),
  ),
  summary: z.object({
    total: z.number().int(),
    assessed: z.number().int(),
    satisfied: z.number().int(),
    gaps: z.number().int(),
    notAssessed: z.number().int(),
  }),
});

export const ManifestSchema = z.object({
  scanId: z.string(),
  projectVersion: z.string().optional(),
  commit: z.string().optional(),
  environment: z.string(),
  mode: zEnum(EXECUTION_MODES as unknown as [string, ...string[]]),
  os: z.string(),
  runtimeVersions: z.record(z.string()),
  engineVersions: z.record(z.string()),
  rulesetVersion: z.string(),
  configHash: z.string(),
  startedAt: z.string(),
  completedAt: z.string().nullable(),
});

export const ScanResultSchema = z.object({
  schemaVersion: z.literal('2.0'),
  scan: z.object({
    id: z.string(),
    startedAt: z.string(),
    completedAt: z.string().nullable(),
    mode: zEnum(EXECUTION_MODES as unknown as [string, ...string[]]),
    manifest: ManifestSchema,
  }),
  projectProfile: z.object({
    languages: z.array(z.object({ name: z.string(), confidence: z.number() })),
    frameworks: z.array(z.object({ name: z.string(), confidence: z.number() })),
    packageManagers: z.array(z.string()),
    hasTests: z.boolean(),
    fileCount: z.number().int(),
    detectionConfidence: z.number().min(0).max(1),
    notes: z.array(z.string()),
  }),
  assumptions: z.array(z.object({ id: z.string(), statement: z.string(), impactIfWrong: z.string() })),
  authorization: z.object({
    confirmed: z.boolean(),
    scope: z.array(z.string()),
    excluded: z.array(z.string()),
  }),
  coverage: z.object({ byDimension: z.record(z.number()), overall: z.number() }),
  scores: z.array(DimensionScoreSchema),
  overall: z.object({
    score: z.number().nullable(),
    confidence: zEnum(CONFIDENCE_LEVELS as unknown as [string, ...string[]]),
    evidenceCoverage: z.number(),
    criticalBlockers: z.number().int(),
    highRiskFindings: z.number().int(),
    untestedAreas: z.array(z.string()),
    manualVerificationRequired: z.number().int(),
  }),
  findings: z.array(FindingSchema),
  releaseDecision: z.object({
    decision: zEnum(RELEASE_DECISIONS as unknown as [string, ...string[]]),
    conditions: z.array(z.string()),
    gatesEvaluated: z.array(
      z.object({ gate: z.string(), result: zEnum(STATUSES as unknown as [string, ...string[]]) }),
    ),
    rationale: z.string(),
  }),
  manualReviewQueue: z.array(z.object({ item: z.string(), reason: z.string() })),
  limitations: z.array(z.string()),
  sbom: SbomSchema.optional(),
  compliance: ComplianceMatrixSchema.optional(),
  seo: z
    .object({
      note: z.string(),
      findings: z.array(FindingSchema),
      summary: z.object({ pages: z.number().int(), issues: z.number().int() }),
    })
    .optional(),
});

export type ScanResultContract = z.infer<typeof ScanResultSchema>;

/** Validate an emitted result against the canonical contract. Throws with a readable message on failure. */
export function validateScanResult(value: unknown): ScanResultContract {
  return ScanResultSchema.parse(value);
}

export const SCHEMA_VERSION = '2.0' as const;
