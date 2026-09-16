/**
 * Worker — processes queued scan jobs (§VI.6/§VI.7).
 *
 * Two modes, chosen by environment:
 *  - QA_REDIS_URL + QA_DATABASE_URL set → DISTRIBUTED: a long-lived consumer connected to the shared
 *    Redis broker + Postgres store. Run it as a separate process from the API. This is the real
 *    multi-process deployment.
 *  - otherwise → DEMO: a self-contained in-memory run that submits one scan (from argv) and exits —
 *    a runnable demonstration of the async path without infra.
 *
 * Usage: npm run worker -- [projectDir]     (demo mode)
 *        QA_REDIS_URL=... QA_DATABASE_URL=... npm run worker   (distributed consumer)
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  InMemoryJobQueue,
  InMemoryScanStore,
  ScanService,
  startWorker,
  type ScanJobPayload,
} from '@qa/jobs';

const repoRoot = path.resolve(fileURLToPath(new URL('../../..', import.meta.url)));

async function runDistributed(redisUrl: string, dbUrl: string): Promise<void> {
  const { BullMqJobQueue, createPostgresStore } = await import('@qa/jobs/adapters');
  const pg = await createPostgresStore(dbUrl);
  const queue = new BullMqJobQueue<ScanJobPayload>({ redisUrl, queueName: 'qa-scans' });
  startWorker(pg.store, queue, { environment: 'worker-distributed' });
  console.error('[qa-worker] distributed consumer started (Postgres + BullMQ). Waiting for jobs. Ctrl-C to stop.');

  const shutdown = async () => {
    console.error('[qa-worker] shutting down');
    await queue.close();
    await pg.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
}

async function runDemo(): Promise<void> {
  const target = process.argv[2] ?? path.join(repoRoot, 'fixtures', 'vulnerable-sample');
  const projectDir = path.resolve(target);
  const evidenceRoot = path.join(repoRoot, 'data', 'worker');

  const store = new InMemoryScanStore();
  const queue = new InMemoryJobQueue<ScanJobPayload>({ concurrency: 1, maxAttempts: 1 });
  const service = new ScanService(store, queue);
  startWorker(store, queue, { environment: 'worker-standalone' });

  console.error(`[qa-worker] (demo) submitting scan for ${projectDir}`);
  const submitted = await service.submit({ projectId: 'cli-worker', projectDir, evidenceRoot });

  const poll = setInterval(async () => {
    const rec = await store.get(submitted.scanId);
    if (rec) console.error(`[qa-worker] ${rec.state} (${rec.progress.pct}%)`);
  }, 15);
  await queue.onIdle();
  clearInterval(poll);

  const rec = await store.get(submitted.scanId);
  if (!rec || rec.state === 'FAILED') {
    console.error(`[qa-worker] FAILED: ${rec?.error ?? 'no record'}`);
    process.exit(1);
  }
  const decision = rec.result?.releaseDecision.decision ?? 'UNKNOWN';
  const critical = rec.result?.overall.criticalBlockers ?? 0;
  console.error(`[qa-worker] COMPLETED — decision=${decision} criticalBlockers=${critical} findings=${rec.result?.findings.length ?? 0}`);
  console.error(`[qa-worker] failed=${await queue.failedCount()}`);
  process.exit(decision === 'NO_GO' ? 1 : 0);
}

async function main(): Promise<void> {
  const redisUrl = process.env.QA_REDIS_URL;
  const dbUrl = process.env.QA_DATABASE_URL;
  if (redisUrl && dbUrl) return runDistributed(redisUrl, dbUrl);
  return runDemo();
}

main().catch((err) => {
  console.error('[qa-worker] FATAL:', err instanceof Error ? err.stack : err);
  process.exit(1);
});
