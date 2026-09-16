import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }): Promise<Response> {
  return proxy(`/scans/${encodeURIComponent(params.id)}`);
}
