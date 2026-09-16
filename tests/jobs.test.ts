/**
 * Job delivery core tests (§VI.6/§VI.7): in-memory queue semantics, store, and the scan processor
 * driving the shared orchestrator end-to-end against the fixture.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  InMemoryJobQueue,
  InMemoryScanStore,
  ScanService,
  startWorker,
  type ScanJobPayload,
} from '@qa/jobs';

const fixtureDir = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url));
const tmpDirs: string[] = [];
afterAll(async () => {
  for (const d of tmpDirs) await fs.rm(d, { recursive: true, force: true });
});

describe('InMemoryJobQueue (§VI.7)', () => {
  it('processes enqueued messages and resolves onIdle', async () => {
    const q = new InMemoryJobQueue<{ n: number }>();
    const seen: number[] = [];
    q.process(async (m) => {
      seen.push(m.payload.n);
    });
    await q.enqueue({ n: 1 });
    await q.enqueue({ n: 2 });
    await q.onIdle();
    expect(seen).toEqual([1, 2]);
    expect(await q.size()).toBe(0);
  });

  it('dead-letters a message after exhausting attempts', async () => {
    const q = new InMemoryJobQueue<{ x: string }>({ maxAttempts: 2 });
    let calls = 0;
    q.process(async () => {
      calls++;
      throw new Error('boom');
    });
    await q.enqueue({ x: 'a' });
    await q.onIdle();
    expect(calls).toBe(2); // initial + 1 retry
    expect(q.deadLetters()).toHaveLength(1);
  });
});

describe('InMemoryScanStore', () => {
  it('creates, updates, and lists newest-first', async () => {
    const store = new InMemoryScanStore();
    const base = { progress: { stage: 'QUEUED' as const, completedStages: 0, totalStages: 6, pct: 0 } };
    await store.create({ scanId: 's1', projectId: 'p', state: 'QUEUED', createdAt: '2020-01-01', updatedAt: '2020-01-01', ...base });
    await store.create({ scanId: 's2', projectId: 'p', state: 'QUEUED', createdAt: '2020-01-02', updatedAt: '2020-01-02', ...base });
    const updated = await store.update('s1', { state: 'COMPLETED' });
    expect(updated.state).toBe('COMPLETED');
    const list = await store.list('p');
    expect(list.map((r) => r.scanId)).toEqual(['s2', 's1']); // newest first
  });
});

describe('ScanService + worker end-to-end (§VI.6)', () => {
  it('submits a scan, processes it async, and reaches COMPLETED with a NO_GO decision', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-jobs-'));
    tmpDirs.push(tmp);
    const store = new InMemoryScanStore();
    const queue = new InMemoryJobQueue<ScanJobPayload>();
    const service = new ScanService(store, queue);
    startWorker(store, queue, { environment: 'test-worker' });

    const rec = await service.submit({ projectId: 'demo', projectDir: fixtureDir, evidenceRoot: tmp });
    // Immediately after submit, it is QUEUED (async — not blocking).
    const immediate = await store.get(rec.scanId);
    expect(immediate?.state).toBe('QUEUED');

    await queue.onIdle();

    const done = await store.get(rec.scanId);
    expect(done?.state).toBe('COMPLETED');
    expect(done?.progress.pct).toBe(100);
    expect(done?.result?.releaseDecision.decision).toBe('NO_GO');
    expect(done?.result?.findings.some((f) => f.ruleId === 'SEC-SECRET-001')).toBe(true);
  });
});
