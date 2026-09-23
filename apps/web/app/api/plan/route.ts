import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

/** Proxy a scan-plan preview (§IX.9/§126) — read-only; the API runs no engines for a plan. */
export async function POST(req: Request): Promise<Response> {
  const body = await req.text();
  return proxy('/projects/web/plan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
}
