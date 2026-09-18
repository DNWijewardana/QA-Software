/**
 * Audit log (§VIII.7 tamper-evident) and rate limiting (§VI.9) tests — unit + live API integration.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { InMemoryAuditStore } from '@qa/jobs';
import { RateLimiter } from '../apps/api/src/ratelimit.js';
import { createApiServer, type ApiHandle } from '../apps/api/src/server.js';
import type { ApiKeyConfig } from '../apps/api/src/auth.js';

describe('InMemoryAuditStore (§VIII.7)', () => {
  it('chains events and detects tampering', async () => {
    const store = new InMemoryAuditStore();
    await store.append({ orgId: 'o', actor: 'a', action: 'scan.submit', target: 's1' });
    await store.append({ orgId: 'o', actor: 'a', action: 'scan.submit', target: 's2' });
    expect((await store.verify()).ok).toBe(true);
    expect((await store.list('o')).map((e) => e.target)).toEqual(['s2', 's1']); // newest first

    // Tamper with an earlier event → chain breaks.
    store._raw()[0]!.target = 'HACKED';
    const v = await store.verify();
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(store._raw()[0]!.id);
  });
});

describe('RateLimiter (§VI.9)', () => {
  it('allows up to the limit, then blocks, then resets', () => {
    const rl = new RateLimiter(2, 1000);
    expect(rl.check('k', 0).allowed).toBe(true);
    expect(rl.check('k', 10).allowed).toBe(true);
    expect(rl.check('k', 20).allowed).toBe(false); // 3rd in window
    expect(rl.check('k', 1100).allowed).toBe(true); // window elapsed
  });
});

const fixturesRoot = fileURLToPath(new URL('../fixtures', import.meta.url));
const fixtureDir = path.join(fixturesRoot, 'vulnerable-sample');
const KEYS: ApiKeyConfig[] = [
  { key: 'admin-key', orgId: 'org-a', role: 'Admin', keyId: 'admin' },
  { key: 'dev-key', orgId: 'org-a', role: 'Developer', keyId: 'dev' },
];
const auth = (k: string) => ({ authorization: `Bearer ${k}` });

describe('audit + rate limiting over HTTP', () => {
  let handle: ApiHandle;
  let base: string;
  let tmp: string;
  beforeAll(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-audit-'));
    handle = createApiServer({ allowedRoots: [fixturesRoot], evidenceRoot: tmp, apiKeys: KEYS, rateLimit: { limit: 3, windowMs: 60_000 } });
    await new Promise<void>((r) => handle.server.listen(0, r));
    base = `http://127.0.0.1:${(handle.server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    await new Promise<void>((r) => handle.server.close(() => r()));
    if (tmp) await fs.rm(tmp, { recursive: true, force: true });
  });

  it('records scan.submit in the audit log, readable only by audit roles', async () => {
    const submit = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...auth('dev-key') },
      body: JSON.stringify({ projectDir: fixtureDir }),
    });
    expect(submit.status).toBe(202);

    // A Developer may not read the audit log.
    expect((await fetch(`${base}/audit`, { headers: auth('dev-key') })).status).toBe(403);

    // An Admin can; the log is chain-verified and contains the submit event.
    const res = await fetch(`${base}/audit`, { headers: auth('admin-key') });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { integrity: { ok: boolean }; events: Array<{ action: string }> };
    expect(body.integrity.ok).toBe(true);
    expect(body.events.some((e) => e.action === 'scan.submit')).toBe(true);
  });

  it('returns 429 once the per-key rate limit is exceeded', async () => {
    // A dedicated key path: burst many requests until one is rejected.
    let got429 = false;
    let retryAfter: string | null = null;
    for (let i = 0; i < 10; i++) {
      const r = await fetch(`${base}/scans`, { headers: auth('admin-key') });
      if (r.status === 429) {
        got429 = true;
        retryAfter = r.headers.get('retry-after');
        break;
      }
    }
    expect(got429).toBe(true);
    expect(Number(retryAfter)).toBeGreaterThan(0);
  });
});
