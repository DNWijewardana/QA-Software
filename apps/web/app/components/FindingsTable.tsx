import type { Finding } from '@/app/lib/types';
import { SEVERITY_ORDER } from '@/app/lib/types';
import { SeverityBadge } from './Badges';

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="muted">
        No findings match. (Absence of findings is not proof of absence — see the report&apos;s Limitations.)
      </p>
    );
  }
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity as (typeof SEVERITY_ORDER)[number]) -
      SEVERITY_ORDER.indexOf(b.severity as (typeof SEVERITY_ORDER)[number]),
  );

  return (
    <div className="table-wrap">
      <table>
        <caption>{findings.length} finding(s), most severe first. Evidence snippets are redacted.</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Finding</th>
            <th scope="col">Location</th>
            <th scope="col">Status</th>
            <th scope="col">CWE</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f) => {
            const loc = f.location.file
              ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
              : f.location.endpoint ?? f.location.url ?? '—';
            return (
              <tr key={f.id}>
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td>
                  <strong>{f.title}</strong>
                  <div className="muted">{f.description}</div>
                  {f.evidence?.[0]?.snippet ? (
                    <div className="mono" style={{ marginTop: '0.3rem' }}>
                      {f.evidence[0].snippet.replace(/\n/g, ' ')}
                    </div>
                  ) : null}
                  {f.remediation ? <div style={{ marginTop: '0.3rem' }}>Fix: {f.remediation.summary}</div> : null}
                </td>
                <td className="mono">{loc}</td>
                <td>
                  {f.status} <span className="muted">({f.confidence})</span>
                </td>
                <td className="mono">{f.cwe.join(', ') || '—'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
