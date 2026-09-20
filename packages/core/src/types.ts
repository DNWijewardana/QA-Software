/**
 * Canonical domain types shared across every tier (web/api/worker/engines).
 * Spec ref: §VII.1 (Finding record), §IX.4 (output contract), §VII.6 (scores), §IV.3/§VIII.6 (manifest).
 */

import type {
  Confidence,
  DetectionMethod,
  EvidenceClass,
  EvidenceType,
  ExecutionMode,
  QualityDimension,
  ReleaseDecision,
  Reproducibility,
  Severity,
  Status,
} from './vocabularies.js';
import type { ComplianceMatrix } from './compliance.js';
import type { SuppressedFinding } from './suppression.js';

/** A reference to a stored evidence artifact (blob lives in object storage — §04 doc). */
export interface EvidenceRef {
  type: EvidenceType;
  /** Stable artifact id, resolvable in the evidence store. */
  ref: string;
  /** True when secrets/PII were redacted before storage (§VIII.10 — always redact). */
  redacted: boolean;
  /** Optional human-readable snippet, ALREADY redacted. Never contains raw secrets. */
  snippet?: string;
}

/** CVSS vector (§VII.1, §IX.4). */
export interface Cvss {
  version: '3.1' | '4.0';
  vector: string;
  score: number;
}

export interface Remediation {
  summary: string;
  effort: 'S' | 'M' | 'L';
  riskReduction: Severity;
}

export interface RootCauseHypothesis {
  statement: string;
  confidence: Confidence;
  /** Concrete verification (e.g., "add boundary test quantity=0; expect 400"). §XII.3 */
  verification: string;
}

export interface StandardMapping {
  framework: string;
  version: string;
  id: string;
}

export interface Traceability {
  requirements: string[];
  tests: string[];
}

export interface FindingLocation {
  file?: string;
  url?: string;
  endpoint?: string;
  line?: number;
}

/**
 * The canonical Finding record (§VII.1 / §IX.4).
 * Every finding links BACK to a standard/requirement and FORWARD to remediation + verification.
 */
export interface Finding {
  id: string;
  ruleId: string;
  category: string;
  subcategory?: string;
  title: string;
  description: string;
  status: Status;
  evidenceClass: EvidenceClass;
  severity: Severity;
  risk: Severity;
  confidence: Confidence;
  reproducibility: Reproducibility;
  cwe: string[];
  cve: string[];
  cvss?: Cvss;
  exploitability?: { epss: number | null; kev: boolean };
  affectedComponent?: string;
  location: FindingLocation;
  detectionMethod: DetectionMethod;
  toolUsed?: string;
  evidence: EvidenceRef[];
  rootCauseHypothesis?: RootCauseHypothesis;
  remediation?: Remediation;
  verificationMethod?: string;
  standards: StandardMapping[];
  traceability: Traceability;
  owner?: string | null;
  targetFixDate?: string | null;
}

/** A per-dimension score. `why` is REQUIRED and must be non-empty (§VII.6). */
export interface DimensionScore {
  dimension: QualityDimension;
  score: number; // 0..100
  confidence: Confidence;
  coverage: number; // 0..1
  weight: number; // 0..1
  why: string[];
  unknowns: string[];
}

export interface OverallResult {
  score: number | null; // null => reported as INSUFFICIENT EVIDENCE (§VII.6)
  confidence: Confidence;
  evidenceCoverage: number;
  criticalBlockers: number;
  highRiskFindings: number;
  untestedAreas: string[];
  manualVerificationRequired: number;
}

/** Execution manifest for reproducibility (§VIII.6). */
export interface ExecutionManifest {
  scanId: string;
  projectVersion?: string;
  commit?: string;
  environment: string;
  mode: ExecutionMode;
  os: string;
  runtimeVersions: Record<string, string>;
  engineVersions: Record<string, string>;
  rulesetVersion: string;
  configHash: string;
  startedAt: string;
  completedAt: string | null;
}

export interface ProjectProfile {
  languages: Array<{ name: string; confidence: number }>;
  frameworks: Array<{ name: string; confidence: number }>;
  packageManagers: string[];
  hasTests: boolean;
  fileCount: number;
  /** Overall detection confidence 0..1 (§III.3 — never assume). */
  detectionConfidence: number;
  notes: string[];
}

export interface Assumption {
  id: string;
  statement: string;
  impactIfWrong: string;
}

export interface Authorization {
  confirmed: boolean;
  scope: string[];
  excluded: string[];
}

export interface GateResult {
  gate: string;
  result: Status;
}

export interface ReleaseDecisionResult {
  decision: ReleaseDecision;
  conditions: string[];
  gatesEvaluated: GateResult[];
  rationale: string;
}

export interface ManualReviewItem {
  item: string;
  reason: string;
}

/** A single SBOM component (§V.17 — SBOM generation, CycloneDX/SPDX). */
export interface SbomComponent {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'application';
  /** package URL, e.g. pkg:npm/express@4.18.0 */
  purl?: string;
  scope: 'required' | 'optional';
  /**
   * Vulnerability assessment status for this component. Offline builds cannot reach a CVE/OSV
   * database, so this is honestly NOT_TESTED / INSUFFICIENT_EVIDENCE rather than a false "clean".
   */
  vulnerabilityStatus: Status;
}

/** Software Bill of Materials (§V.17, §IX.3 CycloneDX/SPDX export). */
export interface Sbom {
  format: 'CycloneDX';
  specVersion: '1.5';
  generatedAt: string;
  components: SbomComponent[];
  /** how the component list was obtained (manifest only vs. resolved lockfile). */
  source: 'manifest' | 'lockfile';
  notes: string[];
}

/**
 * SEO report (§V.24). Reported SEPARATELY from software quality — SEO findings do NOT feed the quality
 * dimensions, the overall score, or the release decision.
 */
export interface SeoReport {
  note: string;
  findings: Finding[];
  summary: { pages: number; issues: number };
}

/** The full canonical scan result — mirrors §IX.4 exactly (sbom is a §2.0 extension field). */
export interface ScanResult {
  schemaVersion: '2.0';
  scan: {
    id: string;
    startedAt: string;
    completedAt: string | null;
    mode: ExecutionMode;
    manifest: ExecutionManifest;
  };
  projectProfile: ProjectProfile;
  assumptions: Assumption[];
  authorization: Authorization;
  coverage: { byDimension: Partial<Record<QualityDimension, number>>; overall: number };
  scores: DimensionScore[];
  overall: OverallResult;
  findings: Finding[];
  releaseDecision: ReleaseDecisionResult;
  manualReviewQueue: ManualReviewItem[];
  limitations: string[];
  /** Optional SBOM, present when a dependency/supply-chain engine ran (§V.17). */
  sbom?: Sbom;
  /** Optional compliance control-coverage matrix (§IV.3). Technical evidence only — not a certification. */
  compliance?: ComplianceMatrix;
  /** Optional SEO report (§V.24). Separate from software quality; does not affect scores or the release decision. */
  seo?: SeoReport;
  /** Findings suppressed by a scoped, auditable suppression (§VII.17). Recorded (never deleted) for audit. */
  suppressedFindings?: SuppressedFinding[];
}
