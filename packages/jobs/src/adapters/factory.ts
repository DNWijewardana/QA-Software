/**
 * Adapter factories — construct the production stores/queues from connection strings.
 * Kept separate so importing the adapter classes never eagerly connects.
 */

import { Pool } from 'pg';
import { PostgresScanStore, type PgPool } from './postgres-store.js';
import { PostgresAuditStore } from './postgres-audit.js';

export interface PostgresHandle {
  store: PostgresScanStore;
  close: () => Promise<void>;
}

/** Create a Postgres-backed scan store, run migrations, and return it with a close() for shutdown. */
export async function createPostgresStore(connectionString: string): Promise<PostgresHandle> {
  const pool = new Pool({ connectionString });
  const store = new PostgresScanStore(pool as unknown as PgPool);
  await store.migrate();
  return { store, close: () => pool.end() };
}

export interface PostgresBackends {
  store: PostgresScanStore;
  auditStore: PostgresAuditStore;
  close: () => Promise<void>;
}

/** Create the scan store AND the audit store on a single shared pool (used by the API). */
export async function createPostgresBackends(connectionString: string): Promise<PostgresBackends> {
  const pool = new Pool({ connectionString });
  const store = new PostgresScanStore(pool as unknown as PgPool);
  const auditStore = new PostgresAuditStore(pool as unknown as PgPool);
  await store.migrate();
  await auditStore.migrate();
  return { store, auditStore, close: () => pool.end() };
}
