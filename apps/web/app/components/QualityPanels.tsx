import type { ComplianceMatrix, DimensionScore, OverallResult, Sbom, SeoReport } from '@/app/lib/types';
import { SeverityBadge } from './Badges';

/** Accessible score meter — the value is shown as text and via role="meter" (never color alone). */
function ScoreMeter({ label, value }: { label: string; value: number }) {
  const band = value >= 80 ? 'good' : value >= 50 ? 'warn' : 'bad';
  return (
    <div
      className={`meter-track ${band}`}
      role="meter"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`${label} score ${value} of 100`}
    >
      <div className="meter-fill" style={{ width: `${value}%` }} />
    </div>
  );
}

export function OverallPanel({ overall }: { overall: OverallResult }) {
  return (
    <section className="panel" aria-labelledby="overall-h">
      <h3 id="overall-h">Overall</h3>
      <div className="kpis">
        <div className="kpi">
          <div className="kpi-value">{overall.score === null ? 'N/A' : `${overall.score}/100`}</div>
          <div className="kpi-label">Overall score{overall.score === null ? ' (insufficient evidence)' : ''}</div>
        </div>
        <div className="kpi">
          <div className="kpi-value">{Math.round(overall.evidenceCoverage * 100)}%</div>
          <div className="kpi-label">Evidence coverage</div>
        </div>
        <div className="kpi">
          <div className="kpi-value">{overall.criticalBlockers}</div>
          <div className="kpi-label">Critical blockers</div>
        </div>
        <div className="kpi">
          <div className="kpi-value">{overall.highRiskFindings}</div>
          <div className="kpi-label">High-risk findings</div>
        </div>
        <div className="kpi">
          <div className="kpi-value">{overall.manualVerificationRequired}</div>
          <div className="kpi-label">Manual verification</div>
        </div>
      </div>
      <p className="muted">Confidence: {overall.confidence}</p>
    </section>
  );
}

export function DimensionScores({ scores }: { scores: DimensionScore[] }) {
  if (scores.length === 0) return null;
  return (
    <section className="panel" aria-labelledby="dims-h">
      <h3 id="dims-h">Quality dimensions</h3>
      <ul className="dim-list">
        {scores.map((s) => (
          <li key={s.dimension} className="dim">
            <div className="dim-head">
              <span className="dim-name">{s.dimension}</span>
              <span className="dim-score">
                {s.score}/100 <span className="muted">· {s.confidence} · {Math.round(s.coverage * 100)}% coverage</span>
              </span>
            </div>
            <ScoreMeter label={s.dimension} value={s.score} />
            {s.why.length > 0 ? <p className="muted dim-why">{s.why.join(' ')}</p> : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function SbomPanel({ sbom }: { sbom: Sbom }) {
  const notTested = sbom.components.filter((c) => c.vulnerabilityStatus === 'NOT_TESTED').length;
  return (
    <section className="panel" aria-labelledby="sbom-h">
      <h3 id="sbom-h">Supply chain (SBOM)</h3>
      <p className="muted">
        {sbom.format} {sbom.specVersion} · source: {sbom.source} · {sbom.components.length} component(s)
      </p>
      {notTested > 0 ? (
        <p className="notice" role="status">
          {notTested}/{sbom.components.length} components were NOT checked against a vulnerability database
          (offline). Reported as <strong>NOT_TESTED</strong> — not &ldquo;clean&rdquo;.
        </p>
      ) : null}
      <div className="table-wrap">
        <table>
          <caption>Declared dependencies</caption>
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Version</th>
              <th scope="col">Scope</th>
              <th scope="col">Vulnerability status</th>
            </tr>
          </thead>
          <tbody>
            {sbom.components.map((c) => (
              <tr key={c.purl ?? `${c.name}@${c.version}`}>
                <td>{c.name}</td>
                <td className="mono">{c.version}</td>
                <td>{c.scope}</td>
                <td>{c.vulnerabilityStatus.replace('_', ' ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function SeoPanel({ seo }: { seo: SeoReport }) {
  return (
    <section className="panel" aria-labelledby="seo-h">
      <h3 id="seo-h">SEO (separate from software quality)</h3>
      <p className="muted">{seo.note}</p>
      <p>
        <strong>{seo.summary.issues}</strong> issue(s) across {seo.summary.pages} page(s)
      </p>
      {seo.findings.length > 0 ? (
        <ul className="scan-list">
          {seo.findings.map((f) => (
            <li key={f.id}>
              <div className="row">
                <SeverityBadge severity={f.severity} />
                <span className="grow">{f.title}</span>
                <span className="mono muted">{f.ruleId}</span>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">No SEO issues detected.</p>
      )}
    </section>
  );
}

const STATUS_MARK: Record<string, string> = { SATISFIED: '✓', GAPS: '✗', NOT_ASSESSED: '–' };

export function CompliancePanel({ compliance }: { compliance: ComplianceMatrix }) {
  const s = compliance.summary;
  return (
    <section className="panel" aria-labelledby="comp-h">
      <h3 id="comp-h">Compliance (control-coverage matrix)</h3>
      <p className="muted">{compliance.disclaimer}</p>
      <p>
        <strong>{s.assessed}/{s.total}</strong> assessed · {s.satisfied} satisfied · {s.gaps} with gaps ·{' '}
        {s.notAssessed} not assessed
      </p>
      <div className="table-wrap">
        <table>
          <caption>Frameworks: {compliance.frameworks.join(', ')}</caption>
          <thead>
            <tr>
              <th scope="col">Status</th>
              <th scope="col">Framework</th>
              <th scope="col">Control</th>
              <th scope="col">Title</th>
            </tr>
          </thead>
          <tbody>
            {compliance.controls.map((c) => (
              <tr key={`${c.framework}-${c.controlId}`}>
                <td>
                  <span className={`ctrl ${c.status}`}>
                    <span aria-hidden="true">{STATUS_MARK[c.status] ?? ''} </span>
                    {c.status.replace('_', ' ')}
                  </span>
                </td>
                <td>{c.framework}</td>
                <td className="mono">{c.controlId}</td>
                <td>{c.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
