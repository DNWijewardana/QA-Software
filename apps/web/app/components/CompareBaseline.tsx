'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ScanDiff, ScanSummary, DiffFindingRef } from '@/app/lib/types';
import { SeverityBadge } from './Badges';

const DIR_LABEL: Record<string, string> = {
  improved: '↑ improved',
  regressed: '↓ regressed',
  stable: '→ stable',
  added: '＋ new',
  removed: '－ removed',
};

function FindingList({ title, items }: { title: string; items: DiffFindingRef[] }) {
  if (!items.length) return null;
  return (
    <div>
      <h4>{title} ({items.length})</h4>
      <ul>
        {items.map((f) => (
          <li key={f.id}>
            <SeverityBadge severity={f.severity} /> {f.ruleId} — {f.title}
            {f.file ? <span className="muted"> ({f.file}{f.line ? `:${f.line}` : ''})</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Compare this scan against a previously-completed baseline scan (differential analysis §VII.10). */
export function CompareBaseline({ scanId }: { scanId: string }) {
  const [baselines, setBaselines] = useState<ScanSummary[]>([]);
  const [baselineId, setBaselineId] = useState<string>('');
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Load candidate baselines: other completed scans.
  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const res = await fetch('/api/scans', { cache: 'no-store' });
        if (!res.ok) return;
        const all = (await res.json()) as ScanSummary[];
        const candidates = all.filter((s) => s.state === 'COMPLETED' && s.scanId !== scanId);
        if (active) setBaselines(candidates);
      } catch {
        /* selector is optional — ignore */
      }
    })();
    return () => {
      active = false;
    };
  }, [scanId]);

  const compare = useCallback(async () => {
    if (!baselineId) return;
    setLoading(true);
    setError(null);
    setDiff(null);
    try {
      const res = await fetch(`/api/scans/${scanId}/diff?baseline=${encodeURIComponent(baselineId)}`, { cache: 'no-store' });
      if (!res.ok) {
        setError('Could not compute the diff for the selected baseline.');
        return;
      }
      setDiff((await res.json()) as ScanDiff);
    } catch {
      setError('Could not reach the API to compute the diff.');
    } finally {
      setLoading(false);
    }
  }, [scanId, baselineId]);

  return (
    <section aria-labelledby="compare-heading" className="panel" style={{ marginTop: '1rem' }}>
      <h3 id="compare-heading">Compare to a baseline scan</h3>
      {baselines.length === 0 ? (
        <p className="muted">No other completed scans to compare against yet.</p>
      ) : (
        <div className="row" style={{ alignItems: 'flex-end', gap: '0.75rem' }}>
          <div className="field" style={{ maxWidth: 420 }}>
            <label htmlFor="baseline-select">Baseline scan</label>
            <select id="baseline-select" value={baselineId} onChange={(e) => setBaselineId(e.target.value)}>
              <option value="">Select a baseline…</option>
              {baselines.map((b) => (
                <option key={b.scanId} value={b.scanId}>
                  {b.scanId} · {b.summary?.decision ?? b.state} · {b.updatedAt}
                </option>
              ))}
            </select>
          </div>
          <button type="button" onClick={() => void compare()} disabled={!baselineId || loading}>
            {loading ? 'Comparing…' : 'Compare'}
          </button>
        </div>
      )}

      {error ? <div className="notice" role="status">{error}</div> : null}

      {diff ? (
        <div style={{ marginTop: '0.75rem' }} aria-live="polite">
          <div className={`notice ${diff.regressionDetected ? 'error' : ''}`} role="status">
            {diff.regressionDetected
              ? '⚠ Regression detected — new Critical/High findings, a worsened release decision, or a dimension score drop.'
              : 'No regression detected.'}
          </div>

          <h4>Overall</h4>
          <ul>
            <li>
              Score: {diff.overall.previousScore ?? '—'} → {diff.overall.currentScore ?? '—'}
              {diff.overall.scoreDelta !== null ? ` (${diff.overall.scoreDelta >= 0 ? '+' : ''}${diff.overall.scoreDelta})` : ''}
            </li>
            <li>Critical blockers change: {diff.overall.criticalBlockersDelta >= 0 ? '+' : ''}{diff.overall.criticalBlockersDelta}</li>
            <li>High-risk change: {diff.overall.highRiskFindingsDelta >= 0 ? '+' : ''}{diff.overall.highRiskFindingsDelta}</li>
            <li>
              Release decision: {diff.decision.previous} → {diff.decision.current}
              {diff.decision.worsened ? ' (worsened)' : diff.decision.changed ? ' (changed)' : ' (unchanged)'}
            </li>
          </ul>

          <FindingList title="New findings" items={diff.findings.added} />
          <FindingList title="Resolved findings" items={diff.findings.resolved} />
          <p className="muted">Unchanged findings: {diff.findings.unchanged}</p>

          <h4>Quality dimensions</h4>
          <ul>
            {diff.dimensions.map((d) => (
              <li key={d.dimension}>
                {d.dimension}: {DIR_LABEL[d.direction] ?? d.direction}
                {d.delta !== null ? ` (${d.delta >= 0 ? '+' : ''}${d.delta})` : ''}
                <span className="muted"> [{d.previous ?? '—'} → {d.current ?? '—'}]</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
