/**
 * BullMQ queue integration test — GATED on a reachable Redis (QA_REDIS_URL). It is skipped when no
 * broker is configured (e.g. local dev without Redis), and runs in CI where a Redis service is present.
 * We never fake Redis; this exercises the real BullMqJobQueue end-to-end.
 */

import { describe, it, expect, afterAll } from 'vitest';

const redisUrl = process.env.QA_REDIS_URL;
const hasRedis = Boolean(redisUrl);

// Only import/construct the adapter when Redis is actually configured.
let cleanup: (() => Promise<void>) | null = null;
afterAll(async () => {
  if (cleanup) await cleanup();
});

describe.skipIf(!hasRedis)('BullMqJobQueue (live Redis)', () => {
  it('enqueues and processes a job end-to-end', async () => {
    const { BullMqJobQueue } = await import('@qa/jobs/adapters');
    const queue = new BullMqJobQueue<{ n: number }>({
      redisUrl: redisUrl!,
      queueName: `qa-test-${Date.now()}`,
      concurrency: 1,
      maxAttempts: 1,
    });
    cleanup = () => queue.close();

    const seen: number[] = [];
    queue.process(async (m) => {
      seen.push(m.payload.n);
    });
    await queue.enqueue({ n: 41 });
    await queue.enqueue({ n: 42 });
    await queue.onIdle();

    expect(seen.sort()).toEqual([41, 42]);
    expect(await queue.failedCount()).toBe(0);
  });
});
