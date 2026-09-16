import Link from 'next/link';
import { API_BASE } from './lib/api';
import type { ScanSummary, TargetRoot } from './lib/types';
import { SubmitForm } from './components/SubmitForm';
import { DecisionBadge } from './components/Badges';

export const dynamic = 'force-dynamic';

async function getJson<T>(pathname: string, fallback: T): Promise<{ data: T; ok: boolean }> {
  try {
    const res = await fetch(`${API_BASE}${pathname}`, { cache: 'no-store' });
    if (!res.ok) return { data: fallback, ok: false };
    return { data: (await res.json()) as T, ok: true };
  } catch {
    return { data: fallback, ok: false };
  }
}

export default async function HomePage() {
  const [targets, scans] = await Promise.all([
    getJson<TargetRoot[]>('/targets', []),
    getJson<ScanSummary[]>('/scans', []),
  ]);
  const apiUp = targets.ok || scans.ok;

  return (
    <>
      <h2>Start a scan</h2>
      {!apiUp ? (
        <div className="notice error" role="alert">
          The platform API is not reachable at <span className="mono">{API_BASE}</span>. Start it with{' '}
          <span className="mono">npm run api</span> (set <span className="mono">QA_API_URL</span> to point elsewhere).
        </div>
      ) : null}

      <div className="card">
        <SubmitForm targets={targets.data} />
      </div>

      <h2>Recent scans</h2>
      {scans.data.length === 0 ? (
        <p className="muted">No scans yet. Start one above.</p>
      ) : (
        <ul className="scan-list">
          {scans.data.map((s) => (
            <li key={s.scanId}>
              <div className="row">
                <Link className="grow mono" href={`/scans/${s.scanId}`}>
                  {s.scanId}
                </Link>
                <span>{s.state}</span>
                {s.summary ? <DecisionBadge decision={s.summary.decision} /> : null}
              </div>
              <div className="muted" style={{ fontSize: '0.85rem', marginTop: '0.2rem' }}>
                project {s.projectId} · {new Date(s.createdAt).toLocaleString()}
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
