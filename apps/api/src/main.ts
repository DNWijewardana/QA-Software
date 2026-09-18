/**
 * API bootstrap.
 *
 * Deployment is chosen by environment:
 *  - QA_REDIS_URL + QA_DATABASE_URL set → DISTRIBUTED: Postgres store + BullMQ queue. The API is a
 *    pure producer; the worker runs as a separate process (apps/worker) consuming the shared broker.
 *  - otherwise → SINGLE-PROCESS: in-memory store + queue with an embedded worker (zero infra).
 *
 * SAFE_STATIC: scan targets are restricted to allowed roots (default: the repo's `fixtures/` dir).
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuditStore, JobQueue, ScanJobPayload, ScanStore } from '@qa/jobs';
import { createApiServer } from './server.js';
import { parseApiKeys } from './auth.js';

const repoRoot = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const port = Number(process.env.QA_PORT ?? 4000);
const evidenceRoot = process.env.QA_DATA_DIR
  ? path.resolve(process.env.QA_DATA_DIR)
  : path.join(repoRoot, 'data', 'api');

const extraRoots = (process.env.QA_ALLOWED_ROOTS ?? '')
  .split(path.delimiter)
  .map((s) => s.trim())
  .filter(Boolean)
  .map((p) => path.resolve(p));
const allowedRoots = [path.join(repoRoot, 'fixtures'), ...extraRoots];

async function main(): Promise<void> {
  const redisUrl = process.env.QA_REDIS_URL;
  const dbUrl = process.env.QA_DATABASE_URL;

  let store: ScanStore | undefined;
  let queue: JobQueue<ScanJobPayload> | undefined;
  let auditStore: AuditStore | undefined;
  let mode = 'single-process (in-memory)';

  if (redisUrl && dbUrl) {
    const { BullMqJobQueue, createPostgresBackends } = await import('@qa/jobs/adapters');
    const pg = await createPostgresBackends(dbUrl);
    store = pg.store;
    auditStore = pg.auditStore;
    queue = new BullMqJobQueue<ScanJobPayload>({ redisUrl, queueName: 'qa-scans' });
    mode = 'distributed (Postgres + BullMQ; worker is a separate process)';
  }

  const apiKeys = parseApiKeys(process.env.QA_API_KEYS);
  const { server } = createApiServer({ allowedRoots, evidenceRoot, store, queue, auditStore, apiKeys });

  server.listen(port, () => {
    console.error(`[qa-api] listening on http://localhost:${port} (SAFE_STATIC)`);
    console.error(`[qa-api] deployment: ${mode}`);
    console.error(
      apiKeys.length > 0
        ? `[qa-api] auth: ENABLED (${apiKeys.length} key(s), multi-tenant)`
        : '[qa-api] auth: DISABLED (open single-tenant dev mode; set QA_API_KEYS to enable)',
    );
    console.error(`[qa-api] allowed scan roots: ${allowedRoots.join(', ')}`);
    console.error(`[qa-api] evidence root: ${evidenceRoot}`);
  });

  const shutdown = () => {
    console.error('[qa-api] shutting down');
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('[qa-api] FATAL:', err instanceof Error ? err.stack : err);
  process.exit(1);
});
