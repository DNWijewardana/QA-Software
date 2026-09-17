'use client';

import { useCallback, useEffect, useState } from 'react';
import type { Finding, FullScanResult, ScanSummary } from '@/app/lib/types';
import { isTerminal, SEVERITY_ORDER } from '@/app/lib/types';
import { DecisionBadge } from './Badges';
import { FindingsTable } from './FindingsTable';
import { CompliancePanel, DimensionScores, LimitationsPanel, ManualReviewPanel, OverallPanel, SbomPanel, SeoPanel } from './QualityPanels';

const REPORT_FORMATS = ['human', 'json', 'sarif', 'junit', 'csv', 'cyclonedx', 'compliance', 'seo'] as const;

export function ScanLive({ scanId, initial }: { scanId: string; initial: ScanSummary | null }) {
  const [record, setRecord] = useState<ScanSummary | null>(initial);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [full, setFull] = useState<FullScanResult | null>(null);
  const [severity, setSeverity] = useState<string>('');
  const [loadError, setLoadError] = useState<string | null>(null);

  const state = record?.state ?? 'UNKNOWN';
  const terminal = isTerminal(state);

  // Poll status until the scan reaches a terminal state.
  useEffect(() => {
    if (terminal) return;
    let active = true;
    const tick = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`, { cache: 'no-store' });
        if (!res.ok) return;
        const body = (await res.json()) as ScanSummary;
        if (active) setRecord(body);
      } catch {
        /* transient — keep polling */
      }
    };
    const iv = setInterval(tick, 1000);
    void tick();
    return () => {
      active = false;
      clearInterval(iv);
    };
  }, [scanId, terminal]);

  const loadFindings = useCallback(async () => {
    try {
      const qs = severity ? `?severity=${encodeURIComponent(severity)}` : '';
      const res = await fetch(`/api/scans/${scanId}/findings${qs}`, { cache: 'no-store' });
      if (!res.ok) {
        setLoadError('Findings are not available yet.');
        return;
      }
      setLoadError(null);
      setFindings((await res.json()) as Finding[]);
    } catch {
      setLoadError('Could not load findings.');
    }
  }, [scanId, severity]);

  // Once completed, load findings (and reload when the severity filter changes).
  useEffect(() => {
    if (state === 'COMPLETED') void loadFindings();
  }, [state, loadFindings]);

  // Once completed, load the full result (scores, overall, compliance) for the dashboard panels.
  useEffect(() => {
    if (state !== 'COMPLETED') return;
    let active = true;
    void (async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}/report?format=json`, { cache: 'no-store' });
        if (!res.ok) return;
        const body = (await res.json()) as FullScanResult;
        if (active) setFull(body);
      } catch {
        /* panels are optional — ignore load errors */
      }
    })();
    return () => {
      active = false;
    };
  }, [scanId, state]);

  const pct = record?.progress.pct ?? 0;

  return (
    <div>
      <p aria-live="polite" style={{ margin: '0.25rem 0 0.75rem' }}>
        Status: <strong>{state}</strong>
        {record ? <span className="muted"> · stage {record.progress.stage}</span> : null}
      </p>

      {!terminal ? (
        <div
          className="progress-track"
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Scan progress"
        >
          <div className="progress-fill" style={{ width: `${pct}%` }} />
        </div>
      ) : null}

      {state === 'FAILED' ? (
        <div className="notice error" role="alert">
          Scan failed: {record?.error ?? 'unknown error'}
        </div>
      ) : null}

      {state === 'COMPLETED' && record?.summary ? (
        <section aria-labelledby="result-heading" style={{ marginTop: '1rem' }}>
          <h2 id="result-heading">Result</h2>
          <div className="row">
            <DecisionBadge decision={record.summary.decision} />
            <span className="muted">
              {record.summary.criticalBlockers} critical blocker(s)
            </span>
          </div>

          <div className="report-links">
            {REPORT_FORMATS.map((fmt) => (
              <a key={fmt} href={`/api/scans/${scanId}/report?format=${fmt}`} target="_blank" rel="noreferrer">
                {fmt.toUpperCase()}
                <span className="visually-hidden"> report (opens in a new tab)</span>
              </a>
            ))}
          </div>

          {full ? (
            <>
              <OverallPanel overall={full.overall} />
              <DimensionScores scores={full.scores} />
              {full.compliance ? <CompliancePanel compliance={full.compliance} /> : null}
              {full.sbom ? <SbomPanel sbom={full.sbom} /> : null}
              {full.seo ? <SeoPanel seo={full.seo} /> : null}
              <ManualReviewPanel items={full.manualReviewQueue ?? []} />
              <LimitationsPanel limitations={full.limitations ?? []} />
            </>
          ) : null}

          <h3>Findings</h3>
          <div className="field" style={{ maxWidth: 260 }}>
            <label htmlFor="sev-filter">Filter by severity</label>
            <select id="sev-filter" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          {loadError ? <div className="notice" role="status">{loadError}</div> : null}
          {findings ? <FindingsTable findings={findings} /> : <p className="muted">Loading findings…</p>}
        </section>
      ) : null}
    </div>
  );
}
