/**
 * Job/scan domain types for the async delivery layer (§VI.6, §VI.7).
 */

import type { JobState, ScanPolicy, ScanResult, Suppression } from '@qa/core';
import { SCAN_STAGES, type ScanStage } from '@qa/orchestrator';

export interface ScanJobPayload {
  scanId: string;
  projectId: string;
  /** Local directory to scan. Mutually exclusive with sourceUrl (exactly one is set). */
  projectDir?: string;
  /** Public https git URL to shallow-clone and scan. Mutually exclusive with projectDir. */
  sourceUrl?: string;
  evidenceDir: string;
  /** Optional scoring/gate policy (§VII.11). Plain JSON so it survives queue serialization. */
  policy?: ScanPolicy;
  /** Optional scoped, auditable false-positive suppressions (§VII.17). Plain JSON. */
  suppressions?: Suppression[];
}

/** Honest, stage-based progress — derived from the ordinal of the current stage, never fabricated (§VI.6). */
export interface ScanProgress {
  stage: ScanStage | 'QUEUED';
  completedStages: number;
  totalStages: number;
  pct: number;
}

export interface ScanRecord {
  scanId: string;
  /** Owning organization/tenant (§VIII.8). Every record is scoped to exactly one org. */
  orgId: string;
  projectId: string;
  state: JobState;
  progress: ScanProgress;
  createdAt: string;
  updatedAt: string;
  /** Present only when state === COMPLETED. */
  result?: ScanResult;
  /** Present only when state === FAILED. */
  error?: string;
}

export const TOTAL_STAGES = SCAN_STAGES.length;

/** Map an orchestrator stage to a job state (both vocabularies are shared with @qa/core). */
export function stageToState(stage: ScanStage): JobState {
  return stage as JobState; // stage names are a subset of JOB_STATES by construction
}

/** Compute deterministic progress for a stage. */
export function progressForStage(stage: ScanStage): ScanProgress {
  const idx = SCAN_STAGES.indexOf(stage);
  const completed = idx + 1;
  return {
    stage,
    completedStages: completed,
    totalStages: TOTAL_STAGES,
    pct: Math.round((completed / TOTAL_STAGES) * 100),
  };
}

export const QUEUED_PROGRESS: ScanProgress = {
  stage: 'QUEUED',
  completedStages: 0,
  totalStages: TOTAL_STAGES,
  pct: 0,
};
