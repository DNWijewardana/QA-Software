/**
 * Job delivery core tests (§VI.6/§VI.7): in-memory queue semantics, store, and the scan processor
 * driving the shared orchestrator end-to-end against the fixture.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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

function git(cwd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const c = spawn('git', args, { cwd, shell: false, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
    let err = '';
    c.stderr?.on('data', (d) => (err += String(d)));
    c.on('error', reject);
    c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`git ${args.join(' ')}: ${err}`))));
  });
}

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
    await store.create({ scanId: 's1', orgId: 'default', projectId: 'p', state: 'QUEUED', createdAt: '2020-01-01', updatedAt: '2020-01-01', ...base });
    await store.create({ scanId: 's2', orgId: 'default', projectId: 'p', state: 'QUEUED', createdAt: '2020-01-02', updatedAt: '2020-01-02', ...base });
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

  it('submits a scan from a git URL: clones, scans, completes, and cleans up the temp clone', async () => {
    // Build a local git repo (a stand-in for a remote) with one committed, flaggable file.
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-jobs-git-'));
    tmpDirs.push(tmp);
    const origin = path.join(tmp, 'origin');
    await fs.mkdir(origin, { recursive: true });
    await fs.writeFile(path.join(origin, 'server.js'), 'const apiKey = "AKIA1234567890ABCDEF";\n', 'utf8');
    await git(origin, ['init', '-q', '-b', 'main']);
    await git(origin, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'add', 'server.js']);
    await git(origin, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init']);
    const url = pathToFileURL(origin).href;

    const store = new InMemoryScanStore();
    const queue = new InMemoryJobQueue<ScanJobPayload>();
    const service = new ScanService(store, queue);
    // Dedicated clone root so the cleanup assertion is isolated from other (parallel) test files.
    const cloneRoot = path.join(tmp, 'clones');
    await fs.mkdir(cloneRoot, { recursive: true });
    // Policy disabled so the hermetic file:// URL is accepted (production defaults to https-only).
    startWorker(store, queue, { environment: 'test-worker', enforceRemotePolicy: false, tmpRoot: cloneRoot });

    const rec = await service.submit({ projectId: 'git', sourceUrl: url, evidenceRoot: path.join(tmp, 'ev') });
    await queue.onIdle();

    const done = await store.get(rec.scanId);
    expect(done?.state).toBe('COMPLETED');
    expect(done?.result?.findings.some((f) => f.category === 'Security')).toBe(true);
    // The temp clone must be gone (cleanup ran) — its dedicated parent is now empty.
    expect(await fs.readdir(cloneRoot)).toEqual([]);
  });

  it('rejects a submit with neither projectDir nor sourceUrl', async () => {
    const store = new InMemoryScanStore();
    const queue = new InMemoryJobQueue<ScanJobPayload>();
    const service = new ScanService(store, queue);
    await expect(service.submit({ projectId: 'x', evidenceRoot: os.tmpdir() })).rejects.toThrow(/exactly one/i);
  });
});
