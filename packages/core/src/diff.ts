/**
 * Differential / baseline analysis (§VII.10, §44, §84). Compares two scan results deterministically and
 * reports what CHANGED: findings introduced vs. resolved, per-dimension score movement, overall movement,
 * and release-decision change. This is what lets a project detect regressions against a baseline.
 *
 * Pure and deterministic (§0.2): no I/O, no clock, no AI. Findings are matched by a STABLE identity
 * (ruleId + affected component + file + line) so the same issue is recognized across scans even though the
 * per-run finding `id` (which carries an ordinal) differs.
 */

import type { Finding, ScanResult } from './types.js';
import type { ReleaseDecision, Severity } from './vocabularies.js';

const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
/** Release decisions ordered worst → best, so a movement can be classified as better/worse. */
const DECISION_RANK: Record<ReleaseDecision, number> = {
  NO_GO: 0,
  INSUFFICIENT_EVIDENCE: 1,
  GO_WITH_CONDITIONS: 2,
  GO: 3,
};

export interface FindingRef {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  affectedComponent: string;
  file: string | null;
  line: number | null;
}

export type DimensionDirection = 'improved' | 'regressed' | 'stable' | 'added' | 'removed';

export interface DimensionDelta {
  dimension: string;
  previous: number | null;
  current: number | null;
  delta: number | null;
  direction: DimensionDirection;
}

export interface ScanDiff {
  baselineScanId: string;
  currentScanId: string;
  findings: {
    added: FindingRef[];
    resolved: FindingRef[];
    unchanged: number;
  };
  bySeverity: {
    added: Record<Severity, number>;
    resolved: Record<Severity, number>;
  };
  dimensions: DimensionDelta[];
  overall: {
    previousScore: number | null;
    currentScore: number | null;
    scoreDelta: number | null;
    criticalBlockersDelta: number;
    highRiskFindingsDelta: number;
  };
  decision: {
    previous: ReleaseDecision;
    current: ReleaseDecision;
    changed: boolean;
    /** true when the decision moved to a worse tier (e.g. GO → NO_GO). */
    worsened: boolean;
  };
  /** true when the current scan is worse than the baseline in a way that should block/alert. */
  regressionDetected: boolean;
}

function findingKey(f: Finding): string {
  return [f.ruleId, f.affectedComponent, f.location?.file ?? '', f.location?.line ?? ''].join('|');
}

function toRef(f: Finding): FindingRef {
  return {
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    affectedComponent: f.affectedComponent ?? '',
    file: f.location?.file ?? null,
    line: f.location?.line ?? null,
  };
}

function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
}

/** Compare a baseline scan to the current scan and return a deterministic diff. */
export function diffScans(baseline: ScanResult, current: ScanResult): ScanDiff {
  const baseByKey = new Map<string, Finding>();
  for (const f of baseline.findings) if (!baseByKey.has(findingKey(f))) baseByKey.set(findingKey(f), f);
  const curByKey = new Map<string, Finding>();
  for (const f of current.findings) if (!curByKey.has(findingKey(f))) curByKey.set(findingKey(f), f);

  const added: FindingRef[] = [];
  const resolved: FindingRef[] = [];
  let unchanged = 0;
  const bySeverity = { added: emptySeverityCounts(), resolved: emptySeverityCounts() };

  for (const [key, f] of curByKey) {
    if (baseByKey.has(key)) unchanged++;
    else {
      added.push(toRef(f));
      bySeverity.added[f.severity]++;
    }
  }
  for (const [key, f] of baseByKey) {
    if (!curByKey.has(key)) {
      resolved.push(toRef(f));
      bySeverity.resolved[f.severity]++;
    }
  }
  const bySev = (r: FindingRef) => SEV_ORDER.indexOf(r.severity);
  added.sort((a, b) => bySev(a) - bySev(b) || a.ruleId.localeCompare(b.ruleId));
  resolved.sort((a, b) => bySev(a) - bySev(b) || a.ruleId.localeCompare(b.ruleId));

  // Per-dimension movement.
  const baseDim = new Map(baseline.scores.map((s) => [s.dimension, s.score] as const));
  const curDim = new Map(current.scores.map((s) => [s.dimension, s.score] as const));
  const dims = [...new Set([...baseDim.keys(), ...curDim.keys()])].sort();
  const dimensions: DimensionDelta[] = dims.map((dimension) => {
    const previous = baseDim.has(dimension) ? baseDim.get(dimension)! : null;
    const cur = curDim.has(dimension) ? curDim.get(dimension)! : null;
    let direction: DimensionDirection;
    let delta: number | null;
    if (previous === null && cur !== null) {
      direction = 'added';
      delta = null;
    } else if (previous !== null && cur === null) {
      direction = 'removed';
      delta = null;
    } else {
      delta = (cur ?? 0) - (previous ?? 0);
      direction = delta > 0 ? 'improved' : delta < 0 ? 'regressed' : 'stable';
    }
    return { dimension, previous, current: cur, delta, direction };
  });

  const prevScore = baseline.overall.score;
  const curScore = current.overall.score;
  const scoreDelta = prevScore !== null && curScore !== null ? curScore - prevScore : null;

  const prevDecision = baseline.releaseDecision.decision;
  const curDecision = current.releaseDecision.decision;
  const worsened = DECISION_RANK[curDecision] < DECISION_RANK[prevDecision];

  const regressionDetected =
    bySeverity.added.Critical > 0 ||
    bySeverity.added.High > 0 ||
    worsened ||
    dimensions.some((d) => d.direction === 'regressed' && (d.delta ?? 0) <= -5);

  return {
    baselineScanId: baseline.scan.id,
    currentScanId: current.scan.id,
    findings: { added, resolved, unchanged },
    bySeverity,
    dimensions,
    overall: {
      previousScore: prevScore,
      currentScore: curScore,
      scoreDelta,
      criticalBlockersDelta: current.overall.criticalBlockers - baseline.overall.criticalBlockers,
      highRiskFindingsDelta: current.overall.highRiskFindings - baseline.overall.highRiskFindings,
    },
    decision: { previous: prevDecision, current: curDecision, changed: prevDecision !== curDecision, worsened },
    regressionDetected,
  };
}

const ARROW: Record<DimensionDirection, string> = {
  improved: '↑ improved',
  regressed: '↓ regressed',
  stable: '→ stable',
  added: '＋ new dimension',
  removed: '－ no longer scored',
};

/** Render a human-readable differential report (§VII.10). */
export function renderScanDiff(diff: ScanDiff): string {
  const L: string[] = [];
  L.push('# Differential Analysis (§VII.10)');
  L.push('');
  L.push(`Baseline scan: \`${diff.baselineScanId}\` → Current scan: \`${diff.currentScanId}\``);
  L.push('');
  L.push(diff.regressionDetected ? '**⚠ Regression detected** (new Critical/High findings, a worsened release decision, or a dimension score drop ≥5).' : '**No regression detected.**');
  L.push('');

  const s = diff.overall.scoreDelta;
  const scoreStr = s === null ? 'n/a (insufficient evidence in one scan)' : `${s >= 0 ? '+' : ''}${s} (${diff.overall.previousScore} → ${diff.overall.currentScore})`;
  L.push('## Overall');
  L.push(`- Overall score change: ${scoreStr}`);
  L.push(`- Critical blockers change: ${fmtDelta(diff.overall.criticalBlockersDelta)}`);
  L.push(`- High-risk findings change: ${fmtDelta(diff.overall.highRiskFindingsDelta)}`);
  L.push(`- Release decision: ${diff.decision.previous} → ${diff.decision.current}${diff.decision.worsened ? ' (worsened)' : diff.decision.changed ? ' (changed)' : ' (unchanged)'}`);
  L.push('');

  L.push('## Findings');
  L.push(`- New: ${diff.findings.added.length} (${sevSummary(diff.bySeverity.added)})`);
  L.push(`- Resolved: ${diff.findings.resolved.length} (${sevSummary(diff.bySeverity.resolved)})`);
  L.push(`- Unchanged: ${diff.findings.unchanged}`);
  if (diff.findings.added.length) {
    L.push('');
    L.push('### New findings');
    for (const f of diff.findings.added) L.push(`- [${f.severity}] ${f.ruleId} — ${f.title} (${f.file ?? f.affectedComponent}${f.line ? `:${f.line}` : ''})`);
  }
  if (diff.findings.resolved.length) {
    L.push('');
    L.push('### Resolved findings');
    for (const f of diff.findings.resolved) L.push(`- [${f.severity}] ${f.ruleId} — ${f.title} (${f.file ?? f.affectedComponent}${f.line ? `:${f.line}` : ''})`);
  }

  L.push('');
  L.push('## Quality dimensions');
  for (const d of diff.dimensions) {
    const deltaStr = d.delta === null ? '' : ` (${d.delta >= 0 ? '+' : ''}${d.delta})`;
    const range = d.previous === null || d.current === null ? `${d.previous ?? '—'} → ${d.current ?? '—'}` : `${d.previous} → ${d.current}`;
    L.push(`- ${d.dimension}: ${ARROW[d.direction]}${deltaStr} [${range}]`);
  }
  return L.join('\n');
}

function fmtDelta(n: number): string {
  return n === 0 ? 'no change' : `${n > 0 ? '+' : ''}${n}`;
}

function sevSummary(counts: Record<Severity, number>): string {
  const parts = SEV_ORDER.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  return parts.length ? parts.join(', ') : 'none';
}
