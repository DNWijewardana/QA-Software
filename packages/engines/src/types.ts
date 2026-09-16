/**
 * Engine plugin interfaces (§VI.2). No hard-coding around one tool — every analyzer implements
 * a stable interface, declares what it applies to, and emits findings + evidence artifacts.
 *
 * A missing external tool must degrade to UNABLE_TO_TEST / INSUFFICIENT_EVIDENCE — never a silent PASS.
 */

import type {
  EvidenceType,
  ExecutionMode,
  Finding,
  ProjectProfile,
  QualityDimension,
  Sbom,
} from '@qa/core';

/** A file the engine may read (relative path + lazy content loader). */
export interface ProjectFile {
  /** path relative to the project root (posix separators). */
  path: string;
  /** absolute path on disk. */
  absPath: string;
  /** file size in bytes. */
  size: number;
}

export interface ScanContext {
  scanId: string;
  projectDir: string;
  files: ProjectFile[];
  profile: ProjectProfile;
  mode: ExecutionMode;
  /** read a file's text content (utf-8). Bounded by size limits by the caller. */
  readText: (file: ProjectFile) => Promise<string>;
}

/** An evidence artifact produced by an engine — content is ALREADY redacted (§VIII.10). */
export interface EngineArtifact {
  id: string;
  type: EvidenceType;
  /** redacted content to persist in the evidence store. */
  content: string;
  contentHash: string;
  /** classes of secrets/PII that were redacted (never the values). */
  redactedClasses: Record<string, number>;
}

export interface EngineResult {
  engine: string;
  version: string;
  dimension: QualityDimension;
  /** how many checks this engine's plan intended to run (for coverage). */
  applicableChecks: number;
  /** how many actually executed (for coverage). */
  executedChecks: number;
  findings: Finding[];
  artifacts: EngineArtifact[];
  /** Optional SBOM produced by a dependency/supply-chain engine (§V.17). */
  sbom?: Sbom;
  /** true when the engine could not run (missing tool, unsupported stack) — degrades honestly. */
  degraded?: boolean;
  degradedReason?: string;
}

/** Base contract every static/dynamic analyzer implements. */
export interface Engine {
  readonly name: string;
  readonly version: string;
  readonly dimension: QualityDimension;
  /** Only run when applicable to the detected stack/mode (§VI.2, §VII.4). */
  appliesTo(ctx: ScanContext): boolean;
  run(ctx: ScanContext): Promise<EngineResult>;
}
