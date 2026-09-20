import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

/** Proxy the differential-analysis endpoint (§VII.10), forwarding ?baseline= and ?format=. */
export function GET(req: Request, { params }: { params: { id: string } }): Promise<Response> {
  const qs = new URL(req.url).search; // includes leading '?'
  return proxy(`/scans/${encodeURIComponent(params.id)}/diff${qs}`);
}
