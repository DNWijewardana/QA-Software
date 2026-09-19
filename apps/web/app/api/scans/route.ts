import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

export function GET(): Promise<Response> {
  return proxy('/scans');
}

export async function POST(req: Request): Promise<Response> {
  const body = await req.text();
  // The project id for web-submitted scans is 'web'. Body carries either { projectDir } (validated by the
  // API against its allowed roots) or { sourceUrl } (a public https git URL, validated by the API's policy).
  return proxy('/projects/web/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
}
