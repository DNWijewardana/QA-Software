/** UI-facing shapes mirroring the platform API responses (subset — the UI reads these fields). */

export interface ScanProgress {
  stage: string;
  completedStages: number;
  totalStages: number;
  pct: number;
}

export interface ScanSummary {
  scanId: string;
  projectId: string;
  state: string;
  progress: ScanProgress;
  createdAt: string;
  updatedAt: string;
  error?: string;
  summary?: {
    decision: string;
    criticalBlockers: number;
    links: { result: string; findings: string; report: string };
  };
}

export interface Finding {
  id: string;
  ruleId: string;
  category: string;
  title: string;
  description: string;
  status: string;
  severity: string;
  confidence: string;
  evidenceClass: string;
  cwe: string[];
  location: { file?: string; line?: number; url?: string; endpoint?: string };
  remediation?: { summary: string };
  evidence?: Array<{ snippet?: string }>;
}

export interface TargetRoot {
  root: string;
  projects: Array<{ name: string; path: string }>;
}

export interface DimensionScore {
  dimension: string;
  score: number;
  confidence: string;
  coverage: number;
  weight: number;
  why: string[];
  unknowns: string[];
}

export interface OverallResult {
  score: number | null;
  confidence: string;
  evidenceCoverage: number;
  criticalBlockers: number;
  highRiskFindings: number;
  untestedAreas: string[];
  manualVerificationRequired: number;
}

export interface ComplianceControl {
  framework: string;
  controlId: string;
  title: string;
  status: string;
  gapFindings: string[];
}

export interface ComplianceMatrix {
  disclaimer: string;
  frameworks: string[];
  controls: ComplianceControl[];
  summary: { total: number; assessed: number; satisfied: number; gaps: number; notAssessed: number };
}

export interface SbomComponent {
  name: string;
  version: string;
  type: string;
  purl?: string;
  scope: string;
  vulnerabilityStatus: string;
}

export interface Sbom {
  format: string;
  specVersion: string;
  source: string;
  components: SbomComponent[];
  notes: string[];
}

export interface SeoReport {
  note: string;
  findings: Finding[];
  summary: { pages: number; issues: number };
}

export interface ManualReviewItem {
  item: string;
  reason: string;
}

/** The subset of the full ScanResult the dashboard panels consume. */
export interface FullScanResult {
  scores: DimensionScore[];
  overall: OverallResult;
  compliance?: ComplianceMatrix;
  sbom?: Sbom;
  seo?: SeoReport;
  manualReviewQueue: ManualReviewItem[];
  limitations: string[];
}

export interface DiffFindingRef {
  id: string;
  ruleId: string;
  title: string;
  severity: string;
  file: string | null;
  line: number | null;
}

export interface DiffDimension {
  dimension: string;
  previous: number | null;
  current: number | null;
  delta: number | null;
  direction: 'improved' | 'regressed' | 'stable' | 'added' | 'removed';
}

/** Mirrors @qa/core ScanDiff (subset the UI renders). */
export interface ScanDiff {
  baselineScanId: string;
  currentScanId: string;
  findings: { added: DiffFindingRef[]; resolved: DiffFindingRef[]; unchanged: number };
  dimensions: DiffDimension[];
  overall: { previousScore: number | null; currentScore: number | null; scoreDelta: number | null; criticalBlockersDelta: number; highRiskFindingsDelta: number };
  decision: { previous: string; current: string; changed: boolean; worsened: boolean };
  regressionDetected: boolean;
}

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

export function isTerminal(state: string): boolean {
  return state === 'COMPLETED' || state === 'FAILED';
}
