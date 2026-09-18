/**
 * The platform API base. The web app is a thin BFF: server components and route handlers proxy to
 * this API (default the local api on :4000). Set QA_API_URL to point at another deployment.
 */
export const API_BASE = process.env.QA_API_URL ?? 'http://localhost:4000';

/** Server-side API key (never exposed to the browser). Set when the API has auth enabled. */
const API_KEY = process.env.QA_API_KEY;

/** Auth headers for server-side calls to the API (empty when no key is configured). */
export function authHeaders(): Record<string, string> {
  return API_KEY ? { authorization: `Bearer ${API_KEY}` } : {};
}

/** Proxy a text response from the API, preserving status + content-type. Never throws. */
export async function proxy(pathname: string, init?: RequestInit): Promise<Response> {
  try {
    const headers = new Headers(init?.headers);
    if (API_KEY) headers.set('authorization', `Bearer ${API_KEY}`);
    const r = await fetch(`${API_BASE}${pathname}`, { cache: 'no-store', ...init, headers });
    const body = await r.text();
    return new Response(body, {
      status: r.status,
      headers: { 'content-type': r.headers.get('content-type') ?? 'application/json' },
    });
  } catch {
    return new Response(JSON.stringify({ error: 'api_unreachable', message: `Cannot reach API at ${API_BASE}` }), {
      status: 502,
      headers: { 'content-type': 'application/json' },
    });
  }
}
