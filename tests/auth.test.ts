/**
 * Authentication, RBAC, and tenant-isolation tests (§VIII.8). Tenant isolation is a first-class security
 * control, so it is tested explicitly: org B must never see org A's scans.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { createApiServer, type ApiHandle } from '../apps/api/src/server.js';
import type { ApiKeyConfig } from '../apps/api/src/auth.js';

const fixturesRoot = fileURLToPath(new URL('../fixtures', import.meta.url));
const fixtureDir = path.join(fixturesRoot, 'vulnerable-sample');

const KEYS: ApiKeyConfig[] = [
  { key: 'key-org-a-dev', orgId: 'org-a', role: 'Developer', keyId: 'a-dev' },
  { key: 'key-org-b-dev', orgId: 'org-b', role: 'Developer', keyId: 'b-dev' },
  { key: 'key-org-a-viewer', orgId: 'org-a', role: 'Viewer', keyId: 'a-viewer' },
];

let handle: ApiHandle;
let base: string;
let tmp: string;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-auth-'));
  handle = createApiServer({ allowedRoots: [fixturesRoot], evidenceRoot: tmp, apiKeys: KEYS });
  await new Promise<void>((resolve) => handle.server.listen(0, resolve));
  const { port } = handle.server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => handle.server.close(() => resolve()));
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

const auth = (key: string) => ({ authorization: `Bearer ${key}` });
async function submit(key: string): Promise<{ status: number; scanId?: string }> {
  const r = await fetch(`${base}/projects/demo/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...auth(key) },
    body: JSON.stringify({ projectDir: fixtureDir }),
  });
  const body = (await r.json()) as { scanId?: string };
  return { status: r.status, scanId: body.scanId };
}

describe('auth + RBAC + tenant isolation (§VIII.8)', () => {
  it('rejects unauthenticated requests with 401', async () => {
    expect((await fetch(`${base}/scans`)).status).toBe(401);
    expect((await fetch(`${base}/targets`)).status).toBe(401);
    // health stays public
    expect((await fetch(`${base}/health`)).status).toBe(200);
  });

  it('rejects an invalid key with 401', async () => {
    expect((await fetch(`${base}/scans`, { headers: auth('not-a-real-key') })).status).toBe(401);
  });

  it('forbids a Viewer from submitting a scan (RBAC 403)', async () => {
    const r = await submit('key-org-a-viewer');
    expect(r.status).toBe(403);
  });

  it('isolates scans between orgs: org B cannot see org A’s scan (404)', async () => {
    const a = await submit('key-org-a-dev');
    expect(a.status).toBe(202);
    const scanId = a.scanId!;

    // Org A can read its own scan.
    expect((await fetch(`${base}/scans/${scanId}`, { headers: auth('key-org-a-dev') })).status).toBe(200);

    // Org B is told it does not exist (never disclosed), for the record and all sub-resources.
    expect((await fetch(`${base}/scans/${scanId}`, { headers: auth('key-org-b-dev') })).status).toBe(404);
    expect((await fetch(`${base}/scans/${scanId}/findings`, { headers: auth('key-org-b-dev') })).status).toBe(404);
    expect((await fetch(`${base}/scans/${scanId}/report?format=json`, { headers: auth('key-org-b-dev') })).status).toBe(404);

    // The list endpoint is org-scoped: org B's list does not include org A's scan.
    const bList = (await (await fetch(`${base}/scans`, { headers: auth('key-org-b-dev') })).json()) as Array<{ scanId: string }>;
    expect(bList.some((s) => s.scanId === scanId)).toBe(false);
  });
});
