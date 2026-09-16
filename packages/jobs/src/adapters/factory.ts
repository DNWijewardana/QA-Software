/**
 * Adapter factories — construct the production stores/queues from connection strings.
 * Kept separate so importing the adapter classes never eagerly connects.
 */

import { Pool } from 'pg';
import { PostgresScanStore, type PgPool } from './postgres-store.js';

export interface PostgresHandle {
  store: PostgresScanStore;
  close: () => Promise<void>;
}

/** Create a Postgres-backed store, run migrations, and return it with a close() for shutdown. */
export async function createPostgresStore(connectionString: string): Promise<PostgresHandle> {
  const pool = new Pool({ connectionString });
  const store = new PostgresScanStore(pool as unknown as PgPool);
  await store.migrate();
  return { store, close: () => pool.end() };
}
