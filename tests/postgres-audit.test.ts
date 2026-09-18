/**
 * PostgresAuditStore test — executes the REAL append-only audit SQL against pg-mem, verifying the
 * hash chain, org-scoped listing, and tamper detection (§VIII.7) without a running server.
 */

import { describe, it, expect } from 'vitest';
import { newDb } from 'pg-mem';
import { PostgresAuditStore, type PgPool } from '@qa/jobs/adapters';

function makeStore(): { store: PostgresAuditStore; pool: PgPool } {
  const db = newDb();
  const pg = db.adapters.createPg();
  const pool = new pg.Pool() as unknown as PgPool;
  return { store: new PostgresAuditStore(pool), pool };
}

describe('PostgresAuditStore (real SQL via pg-mem)', () => {
  it('appends a verifiable hash chain and lists newest-first per org', async () => {
    const { store } = makeStore();
    await store.migrate();
    await store.append({ orgId: 'org-a', actor: 'k1', action: 'scan.submit', target: 's1' });
    await store.append({ orgId: 'org-a', actor: 'k1', action: 'scan.submit', target: 's2' });
    await store.append({ orgId: 'org-b', actor: 'k2', action: 'scan.submit', target: 's3' });

    expect((await store.verify()).ok).toBe(true);

    const a = await store.list('org-a');
    expect(a.map((e) => e.target)).toEqual(['s2', 's1']); // newest first
    // org isolation on the audit log
    const b = await store.list('org-b');
    expect(b.map((e) => e.target)).toEqual(['s3']);
  });

  it('detects tampering with a stored event', async () => {
    const { store, pool } = makeStore();
    await store.migrate();
    await store.append({ orgId: 'org-a', actor: 'k1', action: 'scan.submit', target: 's1' });
    await store.append({ orgId: 'org-a', actor: 'k1', action: 'scan.submit', target: 's2' });
    expect((await store.verify()).ok).toBe(true);

    // Simulate a malicious edit (in production, UPDATE/DELETE would be revoked on the table).
    await pool.query("UPDATE audit_event SET target = 'HACKED' WHERE target = 's1'");
    const v = await store.verify();
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBeTruthy();
  });
});
