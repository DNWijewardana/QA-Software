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

    // HTML report
    const htmlRes = await fetch(`${base}/scans/${scanId}/report?format=html`);
    expect(htmlRes.headers.get('content-type')).toContain('text/html');
    expect(await htmlRes.text()).toContain('<!DOCTYPE html>');

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

  it('rejects a disallowed sourceUrl before enqueuing (400) — remote-source policy', async () => {
    // http (not https)
    const httpRes = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceUrl: 'http://github.com/o/r.git' }),
    });
    expect(httpRes.status).toBe(400);
    expect((await httpRes.json()).error).toBe('forbidden_source');

    // private/loopback host (SSRF)
    const ssrfRes = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceUrl: 'https://169.254.169.254/latest/meta-data' }),
    });
    expect(ssrfRes.status).toBe(400);
    expect((await ssrfRes.json()).error).toBe('forbidden_source');
  });

  it('rejects a submit that provides both or neither target (400)', async () => {
    const neither = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(neither.status).toBe(400);

    const both = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: fixtureDir, sourceUrl: 'https://github.com/o/r.git' }),
    });
    expect(both.status).toBe(400);
  });

  it('returns 404 for an unknown scan and 409 before completion result is ready', async () => {
    expect((await fetch(`${base}/scans/nope`)).status).toBe(404);
  });

  it('previews a scan plan without executing engines (§IX.9/§126)', async () => {
    const res = await fetch(`${base}/projects/demo/plan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: path.join(fixturesRoot, 'insecure-python'), tier: 'quick' }),
    });
    expect(res.status).toBe(200);
    const plan = (await res.json()) as {
      tier: string;
      fileCount: number;
      engines: Array<{ name: string; applicable: boolean }>;
      note: string;
    };
    expect(plan.tier).toBe('quick');
    expect(plan.fileCount).toBeGreaterThan(0);
    // QUICK omits python-scanner from the plan entirely.
    expect(plan.engines.some((e) => e.name === 'python-scanner')).toBe(false);
    expect(plan.engines.some((e) => e.name === 'secret-scanner')).toBe(true);
    expect(plan.note).toMatch(/never invented/i);

    // A git URL is not supported for the (synchronous) plan preview → 400.
    const remote = await fetch(`${base}/projects/demo/plan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sourceUrl: 'https://github.com/o/r.git' }),
    });
    expect(remote.status).toBe(400);

    // A path outside the allowed roots is rejected (§VIII.5).
    const outside = await fetch(`${base}/projects/demo/plan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: path.resolve(os.tmpdir()) }),
    });
    expect(outside.status).toBe(403);
  });

  it('applies a submit-time scan tier (§IX.9): QUICK runs a reduced engine set', async () => {
    const pyDir = path.join(fixturesRoot, 'insecure-python');

    // QUICK excludes the deep security engines → no PY-* findings, and discloses reduced coverage.
    const quick = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: pyDir, tier: 'quick' }),
    });
    const { scanId: quickId } = (await quick.json()) as { scanId: string };
    await waitForCompletion(quickId);
    const quickResult = (await (await fetch(`${base}/scans/${quickId}/result`)).json()) as {
      findings: Array<{ ruleId: string }>;
      limitations: string[];
    };
    expect(quickResult.findings.some((f) => f.ruleId.startsWith('PY-'))).toBe(false);
    expect(quickResult.limitations.some((l) => l.includes('QUICK scan profile'))).toBe(true);

    // An invalid tier is rejected.
    const bad = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: pyDir, tier: 'turbo' }),
    });
    expect(bad.status).toBe(400);
  });

  it('applies submit-time suppressions (§VII.17), recording them and never hiding a Critical', async () => {
    const rubyDir = path.join(fixturesRoot, 'insecure-ruby');

    // Suppress a specific Low rule → excluded from findings, recorded under suppressedFindings.
    const sub = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        projectDir: rubyDir,
        suppressions: [{ id: 'a1', ruleId: 'RB-WEAK-HASH-001', reason: 'accepted risk', createdBy: 'qa@example.com', createdAt: '2026-01-01' }],
      }),
    });
    const { scanId: subId } = (await sub.json()) as { scanId: string };
    await waitForCompletion(subId);
    const subResult = (await (await fetch(`${base}/scans/${subId}/result`)).json()) as {
      findings: Array<{ ruleId: string }>;
      suppressedFindings?: Array<{ finding: { ruleId: string } }>;
    };
    expect(subResult.findings.some((f) => f.ruleId === 'RB-WEAK-HASH-001')).toBe(false);
    expect(subResult.suppressedFindings?.some((s) => s.finding.ruleId === 'RB-WEAK-HASH-001')).toBe(true);

    // A suppression targeting a Critical rule can never hide it → still NO_GO.
    const critSub = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        projectDir: fixtureDir,
        suppressions: [{ id: 'a2', ruleId: 'SEC-SECRET-001', reason: 'trying to hide it', createdBy: 'x', createdAt: '2026-01-01' }],
      }),
    });
    const { scanId: critId } = (await critSub.json()) as { scanId: string };
    await waitForCompletion(critId);
    const critResult = (await (await fetch(`${base}/scans/${critId}/result`)).json()) as {
      releaseDecision: { decision: string };
      findings: Array<{ ruleId: string; severity: string }>;
    };
    expect(critResult.releaseDecision.decision).toBe('NO_GO');
    expect(critResult.findings.some((f) => f.ruleId === 'SEC-SECRET-001' && f.severity === 'Critical')).toBe(true);
  });

  it('applies a submit-time policy to the scan (§VII.11) and can never un-block a Critical', async () => {
    const rubyDir = path.join(fixturesRoot, 'insecure-ruby'); // High findings, no Critical

    // Default policy: High findings exceed the budget of 0 → GO_WITH_CONDITIONS.
    const def = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: rubyDir }),
    });
    const { scanId: defId } = (await def.json()) as { scanId: string };
    await waitForCompletion(defId);
    const defResult = (await (await fetch(`${base}/scans/${defId}/result`)).json()) as { releaseDecision: { decision: string } };
    expect(defResult.releaseDecision.decision).toBe('GO_WITH_CONDITIONS');

    // Raised High budget via policy → GO.
    const relaxed = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: rubyDir, policy: { gates: { maxHigh: 20 } } }),
    });
    const { scanId: relaxedId } = (await relaxed.json()) as { scanId: string };
    await waitForCompletion(relaxedId);
    const relaxedResult = (await (await fetch(`${base}/scans/${relaxedId}/result`)).json()) as { releaseDecision: { decision: string } };
    expect(relaxedResult.releaseDecision.decision).toBe('GO');

    // Honesty guard: even a permissive policy cannot un-block a Critical (vulnerable-sample) → NO_GO.
    const permissive = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: fixtureDir, policy: { weights: { Security: 0 }, gates: { maxHigh: 9999 } } }),
    });
    const { scanId: critId } = (await permissive.json()) as { scanId: string };
    await waitForCompletion(critId);
    const critResult = (await (await fetch(`${base}/scans/${critId}/result`)).json()) as { releaseDecision: { decision: string } };
    expect(critResult.releaseDecision.decision).toBe('NO_GO');
  });

  it('differential analysis: compares two scans and reports a regression (§VII.10)', async () => {
    // Baseline: the architecture fixture (no Critical). Current: the vulnerable sample (seeded Critical).
    const baseSubmit = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: path.join(fixturesRoot, 'bad-architecture') }),
    });
    const { scanId: baselineId } = (await baseSubmit.json()) as { scanId: string };
    await waitForCompletion(baselineId);

    const curSubmit = await fetch(`${base}/projects/demo/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projectDir: fixtureDir }),
    });
    const { scanId: currentId } = (await curSubmit.json()) as { scanId: string };
    await waitForCompletion(currentId);

    // Missing baseline param → 400.
    expect((await fetch(`${base}/scans/${currentId}/diff`)).status).toBe(400);

    // JSON diff shows the introduced Critical and a worsened decision.
    const diffRes = await fetch(`${base}/scans/${currentId}/diff?baseline=${baselineId}`);
    expect(diffRes.status).toBe(200);
    const diff = (await diffRes.json()) as {
      regressionDetected: boolean;
      decision: { current: string };
      bySeverity: { added: Record<string, number> };
      findings: { added: Array<{ ruleId: string }> };
    };
    expect(diff.regressionDetected).toBe(true);
    expect(diff.decision.current).toBe('NO_GO');
    expect(diff.bySeverity.added.Critical).toBeGreaterThan(0);
    expect(diff.findings.added.some((f) => f.ruleId === 'SEC-SECRET-001')).toBe(true);

    // Human diff renders.
    const humanDiff = await fetch(`${base}/scans/${currentId}/diff?baseline=${baselineId}&format=human`);
    expect(humanDiff.headers.get('content-type')).toContain('text/markdown');
    expect(await humanDiff.text()).toContain('Differential Analysis');
  });
});
