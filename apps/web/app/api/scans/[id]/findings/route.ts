import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

export function GET(req: Request, { params }: { params: { id: string } }): Promise<Response> {
  const qs = new URL(req.url).searchParams.toString();
  return proxy(`/scans/${encodeURIComponent(params.id)}/findings${qs ? `?${qs}` : ''}`);
}
