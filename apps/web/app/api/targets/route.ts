import { proxy } from '@/app/lib/api';

export const dynamic = 'force-dynamic';

export function GET(): Promise<Response> {
  return proxy('/targets');
}
