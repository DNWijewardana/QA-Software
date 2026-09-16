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

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

export function isTerminal(state: string): boolean {
  return state === 'COMPLETED' || state === 'FAILED';
}
