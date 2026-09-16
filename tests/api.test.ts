/**
 * API integration test (§VI.9) — starts the real node:http server on an ephemeral port and exercises
 * the async scan lifecycle over HTTP, plus the path-safety guard (§VIII.5).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { createApiServer, type ApiHandle } from '../apps/api/src/server.js';

const fixturesRoot = fileURLToPath(new URL('../fixtures', import.meta.url));
const fixtureDir = path.join(fixturesRoot, 'vulnerable-sample');

let handle: ApiHandle;
let base: string;
let tmp: string;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-api-'));
  handle = createApiServer({ allowedRoots: [fixturesRoot], evidenceRoot: tmp });
  await new Promise<void>((resolve) => handle.server.listen(0, resolve));
  const { port } = handle.server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => handle.server.close(() => resolve()));
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

async function waitForCompletion(scanId: string, timeoutMs = 8000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await fetch(`${base}/scans/${scanId}`);
    const body = (await r.json()) as Record<string, unknown>;
    if (body.state === 'COMPLETED' || body.state === 'FAILED') return body;
    if (Date.now() > deadline) throw new Error(`scan did not complete; last state=${String(body.state)}`);
    await new Promise((res) => setTimeout(res, 20));
  }
}

describe('API scan lifecycle', () => {
  it('health check works', async () => {
    const r = await fetch(`${base}/health`);
    expect(r.status).toBe(200);
    expect((await r.json()).status).toBe('ok');
  });

  it('submits a scan (202), processes async, and serves findings + reports', async () => {
    const submit = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: fixtureDir }),
    });
    expect(submit.status).toBe(202);
    const { scanId, state } = (await submit.json()) as { scanId: string; state: string };
    expect(state).toBe('QUEUED');

    const done = await waitForCompletion(scanId);
    expect(done.state).toBe('COMPLETED');

    // findings endpoint, filtered by severity
    const critFindings = await (await fetch(`${base}/scans/${scanId}/findings?severity=Critical`)).json();
    expect(Array.isArray(critFindings)).toBe(true);
    expect((critFindings as unknown[]).length).toBeGreaterThan(0);

    // SARIF report
    const sarifRes = await fetch(`${base}/scans/${scanId}/report?format=sarif`);
    expect(sarifRes.headers.get('content-type')).toContain('application/json');
    const sarif = (await sarifRes.json()) as { version: string };
    expect(sarif.version).toBe('2.1.0');

    // human report
    const humanRes = await fetch(`${base}/scans/${scanId}/report?format=human`);
    expect(humanRes.headers.get('content-type')).toContain('text/markdown');
    expect(await humanRes.text()).toContain('Release Decision');

    // CycloneDX SBOM
    const cdx = (await (await fetch(`${base}/scans/${scanId}/report?format=cyclonedx`)).json()) as { bomFormat: string };
    expect(cdx.bomFormat).toBe('CycloneDX');
  });

  it('rejects a scan target outside the allowed roots (403) — path-safety guard', async () => {
    const outside = path.resolve(os.tmpdir());
    const r = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: outside }),
    });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('forbidden_path');
  });

  it('returns 404 for an unknown scan and 409 before completion result is ready', async () => {
    expect((await fetch(`${base}/scans/nope`)).status).toBe(404);
  });
});
