import Link from 'next/link';
import { API_BASE, authHeaders } from '@/app/lib/api';
import type { ScanSummary } from '@/app/lib/types';
import { ScanLive } from '@/app/components/ScanLive';

export const dynamic = 'force-dynamic';

async function getInitial(id: string): Promise<ScanSummary | null> {
  try {
    const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(id)}`, { cache: 'no-store', headers: authHeaders() });
    if (!res.ok) return null;
    return (await res.json()) as ScanSummary;
  } catch {
    return null;
  }
}

export default async function ScanPage({ params }: { params: { id: string } }) {
  const initial = await getInitial(params.id);

  return (
    <>
      <p style={{ margin: '0 0 0.5rem' }}>
        <Link href="/">← All scans</Link>
      </p>
      <h2 style={{ marginTop: 0 }}>
        Scan <span className="mono" style={{ fontSize: '0.7em' }}>{params.id}</span>
      </h2>
      {initial === null ? (
        <div className="notice" role="status">
          This scan was not found (or the API is unreachable). If you just submitted it, the API may have
          restarted — its in-memory store does not persist across restarts. Use the distributed (Postgres)
          deployment for durable history.
        </div>
      ) : null}
      <ScanLive scanId={params.id} initial={initial} />
    </>
  );
}
