/**
 * Tamper-evident audit log (§VIII.7). Append-only, hash-chained: each event's hash covers the previous
 * hash, so any mutation or deletion of an earlier event breaks the chain and is detectable via verify().
 *
 * InMemoryAuditStore is the dev/test adapter; an append-only PostgreSQL adapter implements the same
 * interface for production (writes only, no UPDATE/DELETE).
 */

import { createHash, randomUUID } from 'node:crypto';

export interface AuditEvent {
  id: string;
  orgId: string;
  /** non-secret actor id (e.g. an API keyId), never the raw key. */
  actor: string;
  action: string;
  target: string;
  createdAt: string;
  prevHash: string;
  hash: string;
}

export type AuditInput = Pick<AuditEvent, 'orgId' | 'actor' | 'action' | 'target'>;

/** Canonical hash of an event's content chained to the previous hash. */
export function auditHash(prevHash: string, e: Omit<AuditEvent, 'hash' | 'prevHash'>): string {
  const canonical = JSON.stringify({ id: e.id, orgId: e.orgId, actor: e.actor, action: e.action, target: e.target, createdAt: e.createdAt });
  return createHash('sha256').update(`${prevHash}\n${canonical}`).digest('hex');
}

export interface AuditStore {
  append(input: AuditInput): Promise<AuditEvent>;
  /** newest-first, scoped to one org. */
  list(orgId: string, limit?: number): Promise<AuditEvent[]>;
  /** recompute the chain and report the first broken link, if any. */
  verify(): Promise<{ ok: boolean; brokenAt?: string }>;
}

export const AUDIT_GENESIS = '0'.repeat(64);
const GENESIS = AUDIT_GENESIS;

export class InMemoryAuditStore implements AuditStore {
  private readonly events: AuditEvent[] = [];

  async append(input: AuditInput): Promise<AuditEvent> {
    const prevHash = this.events.length > 0 ? this.events[this.events.length - 1]!.hash : GENESIS;
    const base = {
      id: randomUUID(),
      orgId: input.orgId,
      actor: input.actor,
      action: input.action,
      target: input.target,
      createdAt: new Date().toISOString(),
    };
    const event: AuditEvent = { ...base, prevHash, hash: auditHash(prevHash, base) };
    this.events.push(event);
    return { ...event };
  }

  async list(orgId: string, limit = 100): Promise<AuditEvent[]> {
    return this.events
      .filter((e) => e.orgId === orgId)
      .slice(-limit)
      .reverse()
      .map((e) => ({ ...e }));
  }

  async verify(): Promise<{ ok: boolean; brokenAt?: string }> {
    let prev = GENESIS;
    for (const e of this.events) {
      const expected = auditHash(prev, e);
      if (e.prevHash !== prev || e.hash !== expected) {
        return { ok: false, brokenAt: e.id };
      }
      prev = e.hash;
    }
    return { ok: true };
  }

  /** Test-only: expose the raw chain for tamper simulation. */
  _raw(): AuditEvent[] {
    return this.events;
  }
}
