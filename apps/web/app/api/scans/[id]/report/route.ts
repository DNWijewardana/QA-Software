import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

/** Proxy a report export in any format (human|html|json|sarif|junit|csv|cyclonedx). */
export function GET(req: Request, { params }: { params: { id: string } }): Promise<Response> {
  const format = new URL(req.url).searchParams.get('format') ?? 'human';
  return proxy(`/scans/${encodeURIComponent(params.id)}/report?format=${encodeURIComponent(format)}`);
}
