/**
 * Scan processor — the unit of work a worker runs for each queued scan job.
 * It drives the shared orchestrator and streams honest, stage-based progress into the ScanStore.
 *
 * On success → state COMPLETED with the full result. On error → state FAILED with a message, and
 * the error is rethrown so the queue can apply retry / dead-letter policy (§VI.7).
 */

import { prepareSource, runScan } from '@qa/orchestrator';
import type { JobProcessor, QueuedMessage } from './queue.js';
import type { ScanStore } from './store.js';
import { progressForStage, stageToState, type ScanJobPayload } from './types.js';

export interface ScanProcessorOptions {
  environment?: string;
  /**
   * Enforce the remote-source policy (https-only, no creds, no private hosts) when a job carries a
   * sourceUrl. Defaults to true; tests may disable it to clone a local file:// fixture.
   */
  enforceRemotePolicy?: boolean;
  /** Parent directory for temporary clones of remote sources. Defaults to the OS temp dir. */
  tmpRoot?: string;
}

export function createScanProcessor(
  store: ScanStore,
  opts: ScanProcessorOptions = {},
): JobProcessor<ScanJobPayload> {
  return async (msg: QueuedMessage<ScanJobPayload>): Promise<void> => {
    const { scanId, projectDir, sourceUrl, evidenceDir } = msg.payload;
    // Resolve the job's target into a readable directory — cloning a remote repo if needed.
    // The clone happens INSIDE the try so any failure is recorded as FAILED (never silently lost),
    // and cleanup runs in finally so a temp clone is always removed.
    let cleanup: () => Promise<void> = async () => {};
    try {
      const target = sourceUrl ?? projectDir;
      if (!target) throw new Error('job payload has neither projectDir nor sourceUrl');
      const source = await prepareSource(target, {
        enforceRemotePolicy: opts.enforceRemotePolicy,
        tmpRoot: opts.tmpRoot,
      });
      cleanup = source.cleanup;

      const result = await runScan({
        scanId,
        projectDir: source.dir,
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
    } finally {
      await cleanup(); // remove any temp clone
    }
  };
}
