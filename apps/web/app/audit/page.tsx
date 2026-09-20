import { API_BASE, authHeaders } from '../lib/api';
import type { AuditResponse } from '../lib/types';

export const dynamic = 'force-dynamic';

interface FetchState {
  data: AuditResponse | null;
  status: number;
  ok: boolean;
}

async function getAudit(): Promise<FetchState> {
  try {
    const res = await fetch(`${API_BASE}/audit`, { cache: 'no-store', headers: authHeaders() });
    if (!res.ok) return { data: null, status: res.status, ok: false };
    return { data: (await res.json()) as AuditResponse, status: res.status, ok: true };
  } catch {
    return { data: null, status: 0, ok: false };
  }
}

export default async function AuditPage() {
  const { data, status, ok } = await getAudit();

  return (
    <>
      <h2>Audit log</h2>
      <p className="muted">
        Append-only, hash-chained record of security-relevant actions (§VIII.7). Any mutation or deletion of an
        earlier event breaks the chain and is detected by the integrity check below.
      </p>

      {!ok ? (
        status === 403 ? (
          <div className="notice" role="status">
            Your role is not permitted to read the audit log. It is restricted to Owner / Admin / Auditor /
            Compliance Officer.
          </div>
        ) : status === 401 ? (
          <div className="notice" role="status">Authentication is required to read the audit log.</div>
        ) : (
          <div className="notice error" role="alert">
            The platform API is not reachable at <span className="mono">{API_BASE}</span>. Start it with{' '}
            <span className="mono">npm run api</span>.
          </div>
        )
      ) : null}

      {ok && data ? (
        <>
          <div className={`notice ${data.integrity.ok ? '' : 'error'}`} role="status">
            {data.integrity.ok
              ? `✓ Chain integrity verified — ${data.events.length} event(s), no tampering detected.`
              : `⚠ Chain integrity BROKEN at event ${data.integrity.brokenAt ?? '(unknown)'} — the audit log has been altered.`}
          </div>

          {data.events.length === 0 ? (
            <p className="muted">No audit events recorded yet.</p>
          ) : (
            <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col">Target</th>
                  <th scope="col">Hash</th>
                </tr>
              </thead>
              <tbody>
                {data.events.map((e) => (
                  <tr key={e.id}>
                    <td>{new Date(e.createdAt).toLocaleString()}</td>
                    <td className="mono">{e.actor}</td>
                    <td>{e.action}</td>
                    <td className="mono">{e.target}</td>
                    <td className="mono" title={e.hash}>{e.hash.slice(0, 12)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </>
      ) : null}
    </>
  );
}
