/**
 * BullMqJobQueue — the production `JobQueue` adapter over BullMQ + Redis (§VI.7 distributed jobs).
 * Same interface as InMemoryJobQueue, so the API (producer) and worker (consumer) can run as SEPARATE
 * processes sharing one Redis broker.
 *
 * This is a real integration (no stub). It only connects when constructed, so importing this module
 * without Redis is safe. Live coverage is exercised by the Redis-gated integration test.
 */

import { Redis } from 'ioredis';
import { Queue, Worker, type Job } from 'bullmq';
import type { JobProcessor, JobQueue, QueuedMessage } from '../queue.js';

export interface BullMqQueueOptions {
  redisUrl: string;
  queueName?: string;
  concurrency?: number;
  maxAttempts?: number;
}

export class BullMqJobQueue<T> implements JobQueue<T> {
  private readonly name: string;
  private readonly concurrency: number;
  private readonly maxAttempts: number;
  private readonly redisUrl: string;
  private readonly producerConn: Redis;
  private readonly queue: Queue<T, unknown, string>;
  private worker: Worker<T, unknown, string> | null = null;
  private workerConn: Redis | null = null;

  constructor(opts: BullMqQueueOptions) {
    this.name = opts.queueName ?? 'qa-scans';
    this.concurrency = Math.max(1, opts.concurrency ?? 2);
    this.maxAttempts = Math.max(1, opts.maxAttempts ?? 1);
    this.redisUrl = opts.redisUrl;
    // BullMQ requires maxRetriesPerRequest = null on its blocking connections.
    this.producerConn = new Redis(this.redisUrl, { maxRetriesPerRequest: null });
    this.queue = new Queue<T, unknown, string>(this.name, {
      connection: this.producerConn,
      defaultJobOptions: { attempts: this.maxAttempts, removeOnComplete: true, removeOnFail: false },
    });
  }

  async enqueue(payload: T): Promise<{ id: string }> {
    // BullMQ's `add` arg types are conditionals over the (generic) data type; cast at this boundary.
    const jobName = 'scan' as Parameters<typeof this.queue.add>[0];
    const data = payload as Parameters<typeof this.queue.add>[1];
    const job = await this.queue.add(jobName, data);
    return { id: String(job.id) };
  }

  process(processor: JobProcessor<T>): void {
    if (this.worker) return; // idempotent
    const conn = new Redis(this.redisUrl, { maxRetriesPerRequest: null });
    this.workerConn = conn;
    this.worker = new Worker<T, unknown, string>(
      this.name,
      async (job: Job<T, unknown, string>) => {
        const msg: QueuedMessage<T> = {
          id: String(job.id),
          payload: job.data,
          enqueuedAt: new Date(job.timestamp).toISOString(),
          attempts: job.attemptsMade + 1,
        };
        await processor(msg); // throwing lets BullMQ apply its retry/failed policy
      },
      { connection: conn, concurrency: this.concurrency },
    );
  }

  async size(): Promise<number> {
    return this.queue.getWaitingCount();
  }

  async failedCount(): Promise<number> {
    return this.queue.getFailedCount();
  }

  async onIdle(): Promise<void> {
    for (;;) {
      const [waiting, active, delayed] = await Promise.all([
        this.queue.getWaitingCount(),
        this.queue.getActiveCount(),
        this.queue.getDelayedCount(),
      ]);
      if (waiting + active + delayed === 0) return;
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  async close(): Promise<void> {
    if (this.worker) await this.worker.close();
    await this.queue.close();
    if (this.workerConn) await this.workerConn.quit();
    await this.producerConn.quit();
  }
}
