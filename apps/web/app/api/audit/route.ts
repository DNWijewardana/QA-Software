import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

/** Proxy the tamper-evident audit log (§VIII.7). Org-scoped + role-gated by the API. */
export function GET(): Promise<Response> {
  return proxy('/audit');
}
