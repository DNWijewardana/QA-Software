/**
 * ScanStore — persistence abstraction for scan/job records (§VI.8 adapter).
 * InMemoryScanStore is the dev/test implementation; a PostgreSQL adapter implements the same
 * interface in production (spec VI.5 — traceability data belongs in the relational store).
 */

import type { ScanRecord } from './types.js';

export interface ScanStore {
  create(rec: ScanRecord): Promise<void>;
  get(scanId: string): Promise<ScanRecord | null>;
  update(scanId: string, patch: Partial<ScanRecord>): Promise<ScanRecord>;
  list(projectId?: string): Promise<ScanRecord[]>;
}

export class ScanNotFoundError extends Error {
  constructor(scanId: string) {
    super(`Scan not found: ${scanId}`);
    this.name = 'ScanNotFoundError';
  }
}

export class InMemoryScanStore implements ScanStore {
  private readonly records = new Map<string, ScanRecord>();

  async create(rec: ScanRecord): Promise<void> {
    this.records.set(rec.scanId, { ...rec });
  }

  async get(scanId: string): Promise<ScanRecord | null> {
    const r = this.records.get(scanId);
    return r ? { ...r } : null;
  }

  async update(scanId: string, patch: Partial<ScanRecord>): Promise<ScanRecord> {
    const cur = this.records.get(scanId);
    if (!cur) throw new ScanNotFoundError(scanId);
    const next: ScanRecord = { ...cur, ...patch, updatedAt: new Date().toISOString() };
    this.records.set(scanId, next);
    return { ...next };
  }

  async list(projectId?: string): Promise<ScanRecord[]> {
    const all = [...this.records.values()].map((r) => ({ ...r }));
    const filtered = projectId ? all.filter((r) => r.projectId === projectId) : all;
    return filtered.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)); // newest first
  }
}
