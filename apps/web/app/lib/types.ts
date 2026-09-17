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

/** The subset of the full ScanResult the dashboard panels consume. */
export interface FullScanResult {
  scores: DimensionScore[];
  overall: OverallResult;
  compliance?: ComplianceMatrix;
}

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

export function isTerminal(state: string): boolean {
  return state === 'COMPLETED' || state === 'FAILED';
}
