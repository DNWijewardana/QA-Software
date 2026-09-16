import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

export function GET(): Promise<Response> {
  return proxy('/scans');
}

export async function POST(req: Request): Promise<Response> {
  const body = await req.text();
  // The project id for web-submitted scans is 'web'; the API validates the projectDir against allowed roots.
  return proxy('/projects/web/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
}
