/**
 * Orchestrator — the SAFE_STATIC pipeline (§VI.1):
 *   Profiler → Static Analysis → Evidence Aggregator → Quality Engine → Report Generator
 *
 * This is the reusable platform core. It is driven by the CLI (apps/cli) and by the async job
 * worker (apps/worker) alike — the same code path, so results are identical regardless of entrypoint.
 *
 * Spec guarantees enforced here: evidence persisted with content hashes (§VIII.6), findings validated
 * against invariants (§I.4/§VII.2), scores explainable (§VII.6), dual output (§IX.4 + human).
 */

import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  assertFindings,
  computeDimensionScore,
  computeOverall,
  decideRelease,
  mapCompliance,
  type Assumption,
  type DimensionScore,
  type ExecutionManifest,
  type Finding,
  type ProjectProfile,
  type QualityDimension,
  type ScanResult,
  type Sbom,
} from '@qa/core';
import { validateScanResult } from '@qa/contracts';
import {
  defaultStaticEngines,
  profileProject,
  type Engine,
  type EngineArtifact,
  type ProjectFile,
  type ScanContext,
} from '@qa/engines';
import { sha256 } from './util.js';

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.pnpm-store']);
const MAX_FILE_BYTES = 2 * 1024 * 1024; // don't read huge/binary blobs into memory
const RULESET_VERSION = '2025.09-safe-static';

/** Ordered stages the scan emits — used for honest, stage-based progress (§VI.6, no fake %). */
export const SCAN_STAGES = [
  'PREPARING',
  'PROFILING',
  'STATIC_ANALYSIS',
  'AGGREGATING',
  'REPORTING',
  'COMPLETED',
] as const;
export type ScanStage = (typeof SCAN_STAGES)[number];

export interface OrchestratorOptions {
  projectDir: string;
  scanId: string;
  evidenceDir: string;
  engines?: Engine[];
  assumptions?: Assumption[];
  /** environment label recorded in the manifest (e.g. 'local-cli', 'worker'). */
  environment?: string;
  /** progress callback — real stage reporting, never faked (§VI.6). */
  onStage?: (stage: ScanStage) => void;
}

async function walk(dir: string, root: string, acc: ProjectFile[]): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.isDirectory()) {
      if (IGNORE_DIRS.has(e.name)) continue;
      await walk(path.join(dir, e.name), root, acc);
    } else if (e.isFile()) {
      const abs = path.join(dir, e.name);
      const stat = await fs.stat(abs);
      acc.push({
        path: path.relative(root, abs).split(path.sep).join('/'),
        absPath: abs,
        size: stat.size,
      });
    }
  }
}

async function persistArtifacts(evidenceDir: string, artifacts: EngineArtifact[]): Promise<void> {
  await fs.mkdir(evidenceDir, { recursive: true });
  for (const a of artifacts) {
    // Content is already redacted by the engine (§VIII.10). Verify hash integrity before storing.
    if (sha256(a.content) !== a.contentHash) {
      throw new Error(`Evidence integrity check failed for artifact ${a.id}`);
    }
    await fs.writeFile(path.join(evidenceDir, `${a.id}.txt`), a.content, 'utf8');
  }
}

export async function runScan(opts: OrchestratorOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const engines = opts.engines ?? defaultStaticEngines();
  const environment = opts.environment ?? 'local';
  const stage = (s: ScanStage) => opts.onStage?.(s);

  stage('PREPARING');
  const files: ProjectFile[] = [];
  await walk(opts.projectDir, opts.projectDir, files);
  // Deterministic order ⇒ reproducible finding ids/manifests across OSes (§VIII.6).
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const readText = async (file: ProjectFile): Promise<string> => {
    if (file.size > MAX_FILE_BYTES) throw new Error('file too large to read');
    return fs.readFile(file.absPath, 'utf8');
  };

  stage('PROFILING');
  const profile: ProjectProfile = await profileProject({ files, readText });

  const ctx: ScanContext = {
    scanId: opts.scanId,
    projectDir: opts.projectDir,
    files,
    profile,
    mode: 'SAFE_STATIC',
    readText,
  };

  stage('STATIC_ANALYSIS');
  const allFindings: Finding[] = [];
  const allArtifacts: EngineArtifact[] = [];
  const engineVersions: Record<string, string> = {};
  const ranEngines = new Set<string>();
  let sbom: Sbom | undefined;
  // Group coverage per dimension.
  const dimAgg = new Map<QualityDimension, { applicable: number; executed: number }>();

  for (const engine of engines) {
    engineVersions[engine.name] = engine.version;
    if (!engine.appliesTo(ctx)) continue;
    const result = await engine.run(ctx);
    // An engine counts as having "run" (for compliance assessment) only if it actually executed checks —
    // e.g. the OpenAPI engine applies to any JSON/YAML but does no work when no spec is present.
    if (result.executedChecks > 0) ranEngines.add(engine.name);
    allFindings.push(...result.findings);
    allArtifacts.push(...result.artifacts);
    if (result.sbom) sbom = result.sbom;
    const cur = dimAgg.get(result.dimension) ?? { applicable: 0, executed: 0 };
    cur.applicable += result.applicableChecks;
    cur.executed += result.executedChecks;
    dimAgg.set(result.dimension, cur);
  }

  stage('AGGREGATING');
  // Fail loud if any engine emitted a finding that violates Tier-1 invariants (§XIII).
  assertFindings(allFindings);
  await persistArtifacts(opts.evidenceDir, allArtifacts);

  // Score each dimension that was actually analyzed.
  const scores: DimensionScore[] = [];
  for (const [dimension, cov] of dimAgg.entries()) {
    const dimFindings = allFindings.filter((f) => engineDimension(f) === dimension);
    scores.push(
      computeDimensionScore({
        dimension,
        findings: dimFindings,
        applicableChecks: cov.applicable,
        executedChecks: cov.executed,
      }),
    );
  }

  // Compliance mapping (§IV.3): map findings → control-coverage matrix + a ComplianceReadiness score.
  const { matrix: compliance, score: complianceScore } = mapCompliance(allFindings, ranEngines);
  scores.push(complianceScore);

  const overall = computeOverall(scores, allFindings);
  const releaseDecision = decideRelease(overall, allFindings);

  const completedAt = new Date().toISOString();
  const manifest: ExecutionManifest = {
    scanId: opts.scanId,
    environment,
    mode: 'SAFE_STATIC',
    os: `${os.platform()} ${os.release()}`,
    runtimeVersions: { node: process.version },
    engineVersions,
    rulesetVersion: RULESET_VERSION,
    configHash: sha256(JSON.stringify({ engines: engineVersions, ruleset: RULESET_VERSION })),
    startedAt,
    completedAt,
  };

  const byDimension: Partial<Record<QualityDimension, number>> = {};
  for (const s of scores) byDimension[s.dimension] = s.coverage;

  stage('REPORTING');
  const result: ScanResult = {
    schemaVersion: '2.0',
    scan: { id: opts.scanId, startedAt, completedAt, mode: 'SAFE_STATIC', manifest },
    projectProfile: profile,
    assumptions:
      opts.assumptions ?? [
        {
          id: 'A-1',
          statement: 'SAFE_STATIC mode: only uploaded/local source was analyzed; nothing was executed.',
          impactIfWrong: 'Dynamic/runtime issues are out of scope and remain untested.',
        },
      ],
    authorization: { confirmed: true, scope: ['local static analysis of provided source'], excluded: ['any dynamic or network testing'] },
    coverage: { byDimension, overall: overall.evidenceCoverage },
    scores,
    overall,
    findings: allFindings,
    releaseDecision,
    manualReviewQueue: [
      { item: 'Subjective UX and architecture review', reason: 'Requires human judgment (§V.4/§V.10).' },
    ],
    limitations: [
      'Only static analysis was performed (SAFE_STATIC). No dynamic, security-runtime, performance, or accessibility testing was executed.',
      `Engines that ran: ${engines.map((e) => e.name).join(', ')}. Absence of other findings is NOT evidence of their absence (§XII.2).`,
      ...(sbom
        ? ['Dependency components were inventoried into an SBOM, but were NOT checked against a CVE/OSV/KEV database (offline). Component vulnerability status is NOT_TESTED (§V.17).']
        : []),
    ],
    ...(sbom ? { sbom } : {}),
    compliance,
  };

  // Validate against the canonical contract before returning (§X.4 — catch drift; fail loud).
  validateScanResult(result);
  stage('COMPLETED');
  return result;
}

/** Which dimension a finding belongs to, derived from its category (kept explicit & auditable). */
function engineDimension(f: Finding): QualityDimension {
  if (f.category === 'Security') return 'Security';
  if (f.category === 'API') return 'Security'; // API security findings score under Security
  if (f.category === 'Maintainability') return 'Maintainability';
  if (f.category === 'SupplyChain') return 'SupplyChainHealth';
  if (f.category === 'CloudIaC') return 'CloudIaCPosture';
  return 'Functional';
}
