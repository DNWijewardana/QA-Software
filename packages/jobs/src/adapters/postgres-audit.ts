/**
 * PostgresAuditStore — durable, append-only, tamper-evident audit log (§VIII.7).
 * Implements the same AuditStore interface as InMemoryAuditStore.
 *
 * Append-only by design: this adapter only ever INSERTs. In production, revoke UPDATE/DELETE on the table
 * from the app role so the hash chain cannot be silently rewritten. A monotonic `seq` orders the chain.
 *
 * Concurrency note: append() reads the current head then inserts (two statements). For a strictly correct
 * chain under concurrent writers, run a single audit writer or wrap append in a transaction with an advisory
 * lock. verify() recomputes the whole chain and detects any inconsistency regardless.
 */

import { randomUUID } from 'node:crypto';
import { auditHash, AUDIT_GENESIS, type AuditEvent, type AuditInput, type AuditStore } from '../audit.js';
import type { PgPool } from './postgres-store.js';

export const AUDIT_DDL = `
CREATE TABLE IF NOT EXISTS audit_event (
  seq         BIGSERIAL PRIMARY KEY,
  id          TEXT UNIQUE NOT NULL,
  org_id      TEXT NOT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target      TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_event_org_idx ON audit_event (org_id, seq DESC);
`;

function toIso(v: unknown): string {
  return v instanceof Date ? v.toISOString() : String(v);
}
function rowToEvent(row: Record<string, unknown>): AuditEvent {
  return {
    id: String(row.id),
    orgId: String(row.org_id),
    actor: String(row.actor),
    action: String(row.action),
    target: String(row.target),
    createdAt: toIso(row.created_at),
    prevHash: String(row.prev_hash),
    hash: String(row.hash),
  };
}

export class PostgresAuditStore implements AuditStore {
  constructor(private readonly pool: PgPool) {}

  async migrate(): Promise<void> {
    await this.pool.query(AUDIT_DDL);
  }

  async append(input: AuditInput): Promise<AuditEvent> {
    const head = await this.pool.query('SELECT hash FROM audit_event ORDER BY seq DESC LIMIT 1');
    const prevHash = head.rows[0] ? String(head.rows[0].hash) : AUDIT_GENESIS;
    const base = {
      id: randomUUID(),
      orgId: input.orgId,
      actor: input.actor,
      action: input.action,
      target: input.target,
      createdAt: new Date().toISOString(),
    };
    const event: AuditEvent = { ...base, prevHash, hash: auditHash(prevHash, base) };
    await this.pool.query(
      `INSERT INTO audit_event (id, org_id, actor, action, target, created_at, prev_hash, hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [event.id, event.orgId, event.actor, event.action, event.target, event.createdAt, event.prevHash, event.hash],
    );
    return event;
  }

  async list(orgId: string, limit = 100): Promise<AuditEvent[]> {
    const r = await this.pool.query('SELECT * FROM audit_event WHERE org_id = $1 ORDER BY seq DESC LIMIT $2', [orgId, limit]);
    return r.rows.map(rowToEvent);
  }

  async verify(): Promise<{ ok: boolean; brokenAt?: string }> {
    const r = await this.pool.query('SELECT * FROM audit_event ORDER BY seq ASC');
    let prev = AUDIT_GENESIS;
    for (const row of r.rows) {
      const e = rowToEvent(row);
      if (e.prevHash !== prev || e.hash !== auditHash(prev, e)) {
        return { ok: false, brokenAt: e.id };
      }
      prev = e.hash;
    }
    return { ok: true };
  }
}
