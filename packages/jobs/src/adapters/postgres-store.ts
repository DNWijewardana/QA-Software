/**
 * PostgresScanStore — the production `ScanStore` adapter (§VI.5/§VI.8: traceability data → relational DB).
 * Implements the exact same interface as InMemoryScanStore, so the API/worker are agnostic to the backend.
 *
 * Decoupled from a specific driver via the minimal `PgPool` surface — satisfied by node-postgres `Pool`
 * and by pg-mem's Pool (used in tests to execute the REAL SQL without a server).
 */

import type { JobState, ScanResult } from '@qa/core';
import { ScanNotFoundError, type ScanStore } from '../store.js';
import type { ScanProgress, ScanRecord } from '../types.js';
import { SCAN_TABLE_DDL } from './postgres-schema.js';

export interface PgQueryResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}
export interface PgPool {
  query(text: string, params?: unknown[]): Promise<PgQueryResult>;
  end?(): Promise<void>;
}

function toIso(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

function rowToRecord(row: Record<string, unknown>): ScanRecord {
  const progress: ScanProgress = {
    stage: row.stage as ScanProgress['stage'],
    completedStages: Number(row.completed_stages),
    totalStages: Number(row.total_stages),
    pct: Number(row.pct),
  };
  const rec: ScanRecord = {
    scanId: String(row.scan_id),
    orgId: String(row.org_id ?? 'default'),
    projectId: String(row.project_id),
    state: row.state as JobState,
    progress,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
  if (row.result != null) rec.result = row.result as ScanResult;
  if (row.error != null) rec.error = String(row.error);
  return rec;
}

export class PostgresScanStore implements ScanStore {
  constructor(private readonly pool: PgPool) {}

  /** Create the schema if it does not exist. Idempotent. */
  async migrate(): Promise<void> {
    await this.pool.query(SCAN_TABLE_DDL);
  }

  async create(rec: ScanRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO scan_job
         (scan_id, org_id, project_id, state, stage, completed_stages, total_stages, pct, result, error, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        rec.scanId,
        rec.orgId,
        rec.projectId,
        rec.state,
        rec.progress.stage,
        rec.progress.completedStages,
        rec.progress.totalStages,
        rec.progress.pct,
        rec.result ? JSON.stringify(rec.result) : null,
        rec.error ?? null,
        rec.createdAt,
        rec.updatedAt,
      ],
    );
  }

  async get(scanId: string): Promise<ScanRecord | null> {
    const r = await this.pool.query(`SELECT * FROM scan_job WHERE scan_id = $1`, [scanId]);
    return r.rows[0] ? rowToRecord(r.rows[0]) : null;
  }

  async update(scanId: string, patch: Partial<ScanRecord>): Promise<ScanRecord> {
    // Build a targeted SET clause so concurrent progress writes don't clobber unrelated columns.
    const sets: string[] = [];
    const params: unknown[] = [];
    const push = (col: string, val: unknown) => {
      params.push(val);
      sets.push(`${col} = $${params.length}`);
    };

    if (patch.state !== undefined) push('state', patch.state);
    if (patch.progress !== undefined) {
      push('stage', patch.progress.stage);
      push('completed_stages', patch.progress.completedStages);
      push('total_stages', patch.progress.totalStages);
      push('pct', patch.progress.pct);
    }
    if (patch.result !== undefined) push('result', JSON.stringify(patch.result));
    if (patch.error !== undefined) push('error', patch.error);
    push('updated_at', new Date().toISOString());

    params.push(scanId);
    const r = await this.pool.query(
      `UPDATE scan_job SET ${sets.join(', ')} WHERE scan_id = $${params.length} RETURNING *`,
      params,
    );
    if (!r.rows[0]) throw new ScanNotFoundError(scanId);
    return rowToRecord(r.rows[0]);
  }

  async list(projectId?: string): Promise<ScanRecord[]> {
    const r = projectId
      ? await this.pool.query(
          `SELECT * FROM scan_job WHERE project_id = $1 ORDER BY created_at DESC`,
          [projectId],
        )
      : await this.pool.query(`SELECT * FROM scan_job ORDER BY created_at DESC`);
    return r.rows.map(rowToRecord);
  }
}
