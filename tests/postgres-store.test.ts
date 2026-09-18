/**
 * PostgresScanStore test — executes the REAL SQL/DDL against pg-mem (an in-memory PostgreSQL),
 * so the adapter's schema and queries are genuinely verified without a running server (§X.2).
 */

import { describe, it, expect } from 'vitest';
import { newDb } from 'pg-mem';
import { PostgresScanStore, type PgPool } from '@qa/jobs/adapters';
import type { ScanRecord } from '@qa/jobs';

function makeStore(): PostgresScanStore {
  const db = newDb();
  const pg = db.adapters.createPg();
  const pool = new pg.Pool();
  return new PostgresScanStore(pool as unknown as PgPool);
}

function record(id: string, createdAt: string): ScanRecord {
  return {
    scanId: id,
    orgId: 'default',
    projectId: 'p1',
    state: 'QUEUED',
    progress: { stage: 'QUEUED', completedStages: 0, totalStages: 6, pct: 0 },
    createdAt,
    updatedAt: createdAt,
  };
}

describe('PostgresScanStore (real SQL via pg-mem)', () => {
  it('migrates, creates, and reads back a record', async () => {
    const store = makeStore();
    await store.migrate();
    await store.create(record('s1', '2026-01-01T00:00:00.000Z'));
    const got = await store.get('s1');
    expect(got?.scanId).toBe('s1');
    expect(got?.state).toBe('QUEUED');
    expect(got?.progress.pct).toBe(0);
  });

  it('applies partial updates (progress then result) without clobbering', async () => {
    const store = makeStore();
    await store.migrate();
    await store.create(record('s2', '2026-01-01T00:00:00.000Z'));

    await store.update('s2', {
      state: 'STATIC_ANALYSIS',
      progress: { stage: 'STATIC_ANALYSIS', completedStages: 3, totalStages: 6, pct: 50 },
    });
    let got = await store.get('s2');
    expect(got?.state).toBe('STATIC_ANALYSIS');
    expect(got?.progress.pct).toBe(50);
    expect(got?.projectId).toBe('p1'); // untouched

    const fakeResult = { schemaVersion: '2.0', findings: [] } as unknown as ScanRecord['result'];
    await store.update('s2', {
      state: 'COMPLETED',
      result: fakeResult,
      progress: { stage: 'COMPLETED', completedStages: 6, totalStages: 6, pct: 100 },
    });
    got = await store.get('s2');
    expect(got?.state).toBe('COMPLETED');
    expect(got?.progress.pct).toBe(100);
    expect(got?.result).toBeDefined();
  });

  it('lists newest-first, filtered by project', async () => {
    const store = makeStore();
    await store.migrate();
    await store.create(record('a', '2026-01-01T00:00:00.000Z'));
    await store.create(record('b', '2026-01-02T00:00:00.000Z'));
    const list = await store.list('p1');
    expect(list.map((r) => r.scanId)).toEqual(['b', 'a']);
  });

  it('throws when updating a missing scan', async () => {
    const store = makeStore();
    await store.migrate();
    await expect(store.update('missing', { state: 'FAILED', error: 'x' })).rejects.toThrow();
  });
});
