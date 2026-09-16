/**
 * JobQueue — the async job abstraction (§VI.7). Enqueue is non-blocking; a registered processor
 * drains the queue in the background. Supports concurrency, bounded retries, and a dead-letter list.
 *
 * InMemoryJobQueue is the dev/test adapter (no infra). A BullMQ/Redis adapter implements the same
 * interface for the distributed, multi-process deployment (roadmap 2.5). We ship ONLY the real
 * in-memory adapter here — no fake BullMQ stub (§XIII rule 27: never create fake integrations).
 */

import { randomUUID } from 'node:crypto';

export interface QueuedMessage<T> {
  id: string;
  payload: T;
  enqueuedAt: string;
  attempts: number;
}

export type JobProcessor<T> = (msg: QueuedMessage<T>) => Promise<void>;

export interface JobQueue<T> {
  enqueue(payload: T): Promise<{ id: string }>;
  process(processor: JobProcessor<T>): void;
  /** number of messages waiting (not counting in-flight). Async: distributed backends query the broker. */
  size(): Promise<number>;
  /** resolves when the queue is drained and nothing is in flight (useful for tests/shutdown). */
  onIdle(): Promise<void>;
  /** number of jobs that exhausted retries (dead-letter / failed set). */
  failedCount(): Promise<number>;
  /** release backend resources (connections). No-op for in-memory. */
  close(): Promise<void>;
}

export interface InMemoryQueueOptions {
  concurrency?: number;
  maxAttempts?: number;
}

export class InMemoryJobQueue<T> implements JobQueue<T> {
  private readonly waiting: QueuedMessage<T>[] = [];
  private readonly dead: QueuedMessage<T>[] = [];
  private processor: JobProcessor<T> | null = null;
  private inFlight = 0;
  private readonly concurrency: number;
  private readonly maxAttempts: number;
  private idleResolvers: Array<() => void> = [];

  constructor(opts: InMemoryQueueOptions = {}) {
    this.concurrency = Math.max(1, opts.concurrency ?? 1);
    this.maxAttempts = Math.max(1, opts.maxAttempts ?? 1);
  }

  async enqueue(payload: T): Promise<{ id: string }> {
    const msg: QueuedMessage<T> = {
      id: randomUUID(),
      payload,
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
    };
    this.waiting.push(msg);
    this.schedule();
    return { id: msg.id };
  }

  process(processor: JobProcessor<T>): void {
    this.processor = processor;
    this.schedule();
  }

  async size(): Promise<number> {
    return this.waiting.length;
  }

  async failedCount(): Promise<number> {
    return this.dead.length;
  }

  /** Sync access to dead-lettered messages — convenience for in-memory tests only. */
  deadLetters(): QueuedMessage<T>[] {
    return [...this.dead];
  }

  async close(): Promise<void> {
    /* no external resources to release */
  }

  onIdle(): Promise<void> {
    if (this.isIdle()) return Promise.resolve();
    return new Promise((resolve) => this.idleResolvers.push(resolve));
  }

  private isIdle(): boolean {
    return this.inFlight === 0 && this.waiting.length === 0;
  }

  private schedule(): void {
    if (!this.processor) return;
    while (this.inFlight < this.concurrency && this.waiting.length > 0) {
      const msg = this.waiting.shift()!;
      this.inFlight++;
      // Run on the next tick so enqueue() stays non-blocking (§VI.7).
      setImmediate(() => void this.runOne(msg));
    }
  }

  private async runOne(msg: QueuedMessage<T>): Promise<void> {
    const processor = this.processor!;
    msg.attempts++;
    try {
      await processor(msg);
    } catch {
      if (msg.attempts < this.maxAttempts) {
        this.waiting.push(msg); // retry
      } else {
        this.dead.push(msg); // dead-letter (§VI.7)
      }
    } finally {
      this.inFlight--;
      this.schedule();
      if (this.isIdle()) {
        const resolvers = this.idleResolvers;
        this.idleResolvers = [];
        for (const r of resolvers) r();
      }
    }
  }
}
