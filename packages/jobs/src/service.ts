/**
 * ScanService — the reusable delivery core shared by apps/api and apps/worker.
 * Submitting a scan is non-blocking: it records a QUEUED job and enqueues it; a worker processes it.
 */

import path from 'node:path';
import type { ScanPolicy } from '@qa/core';
import { newScanId } from '@qa/orchestrator';
import type { JobQueue } from './queue.js';
import { createScanProcessor, type ScanProcessorOptions } from './processor.js';
import type { ScanStore } from './store.js';
import { QUEUED_PROGRESS, type ScanJobPayload, type ScanRecord } from './types.js';

export interface SubmitScanInput {
  projectId: string;
  /** Local directory to scan. Provide exactly one of projectDir / sourceUrl. */
  projectDir?: string;
  /** Public https git URL to clone and scan. Provide exactly one of projectDir / sourceUrl. */
  sourceUrl?: string;
  /** base directory under which per-scan evidence is written. */
  evidenceRoot: string;
  /** owning org/tenant (§VIII.8). Defaults to 'default' when auth is not enabled. */
  orgId?: string;
  /** optional scoring/gate policy (§VII.11) applied to this scan. */
  policy?: ScanPolicy;
}

export class ScanService {
  constructor(
    private readonly store: ScanStore,
    private readonly queue: JobQueue<ScanJobPayload>,
  ) {}

  async submit(input: SubmitScanInput): Promise<ScanRecord> {
    if (!input.projectDir === !input.sourceUrl) {
      throw new Error('submit requires exactly one of projectDir or sourceUrl');
    }
    const scanId = newScanId();
    const now = new Date().toISOString();
    const record: ScanRecord = {
      scanId,
      orgId: input.orgId ?? 'default',
      projectId: input.projectId,
      state: 'QUEUED',
      progress: QUEUED_PROGRESS,
      createdAt: now,
      updatedAt: now,
    };
    await this.store.create(record);
    await this.queue.enqueue({
      scanId,
      projectId: input.projectId,
      projectDir: input.projectDir,
      sourceUrl: input.sourceUrl,
      evidenceDir: path.join(input.evidenceRoot, scanId, 'evidence'),
      policy: input.policy,
    });
    return record;
  }

  get(scanId: string) {
    return this.store.get(scanId);
  }

  list(projectId?: string) {
    return this.store.list(projectId);
  }
}

/** Register the scan processor against a queue — this is what a worker process does. */
export function startWorker(
  store: ScanStore,
  queue: JobQueue<ScanJobPayload>,
  opts: ScanProcessorOptions = {},
): void {
  queue.process(createScanProcessor(store, opts));
}
