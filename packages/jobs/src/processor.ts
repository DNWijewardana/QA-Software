/**
 * Scan processor — the unit of work a worker runs for each queued scan job.
 * It drives the shared orchestrator and streams honest, stage-based progress into the ScanStore.
 *
 * On success → state COMPLETED with the full result. On error → state FAILED with a message, and
 * the error is rethrown so the queue can apply retry / dead-letter policy (§VI.7).
 */

import { runScan } from '@qa/orchestrator';
import type { JobProcessor, QueuedMessage } from './queue.js';
import type { ScanStore } from './store.js';
import { progressForStage, stageToState, type ScanJobPayload } from './types.js';

export interface ScanProcessorOptions {
  environment?: string;
}

export function createScanProcessor(
  store: ScanStore,
  opts: ScanProcessorOptions = {},
): JobProcessor<ScanJobPayload> {
  return async (msg: QueuedMessage<ScanJobPayload>): Promise<void> => {
    const { scanId, projectDir, evidenceDir } = msg.payload;
    try {
      const result = await runScan({
        scanId,
        projectDir,
        evidenceDir,
        environment: opts.environment ?? 'worker',
        onStage: (stage) => {
          // In-memory store updates resolve synchronously; fire-and-forget keeps onStage sync.
          void store.update(scanId, { state: stageToState(stage), progress: progressForStage(stage) });
        },
      });
      await store.update(scanId, {
        state: 'COMPLETED',
        result,
        progress: progressForStage('COMPLETED'),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await store.update(scanId, { state: 'FAILED', error: message });
      throw err; // let the queue decide retry / dead-letter
    }
  };
}
