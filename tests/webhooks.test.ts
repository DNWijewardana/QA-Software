/**
 * Webhooks / notifications test (§VI.10, §111). Verifies HMAC signing, bounded retry, event derivation, and
 * end-to-end delivery of signed scan events through the scan processor to an in-process HTTP sink.
 */

import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import {
  HttpWebhookEmitter,
  InMemoryJobQueue,
  InMemoryScanStore,
  ScanService,
  signPayload,
  startWorker,
  type ScanJobPayload,
} from '@qa/jobs';

const fixtureDir = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url)); // Critical → NO_GO

interface Received {
  type: string | undefined;
  delivery: string | undefined;
  signature: string | undefined;
  body: string;
}

/** A tiny sink that records deliveries; the first `failN` requests return 500 (to exercise retry). */
function makeSink(failN = 0): { server: http.Server; received: Received[]; url: () => string } {
  const received: Received[] = [];
  let failsLeft = failN;
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c as Buffer));
    req.on('end', () => {
      if (failsLeft > 0) {
        failsLeft--;
        res.writeHead(500).end('boom');
        return;
      }
      received.push({
        type: req.headers['x-qa-event'] as string | undefined,
        delivery: req.headers['x-qa-delivery'] as string | undefined,
        signature: req.headers['x-qa-signature'] as string | undefined,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200).end('ok');
    });
  });
  return { server, received, url: () => `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

describe('webhooks (§VI.10, §111)', () => {
  it('signPayload produces a verifiable HMAC-SHA256 (and empty without a secret)', () => {
    expect(signPayload(undefined, 'x')).toBe('');
    const body = '{"a":1}';
    const expected = `sha256=${createHmac('sha256', 's3cr3t').update(body).digest('hex')}`;
    expect(signPayload('s3cr3t', body)).toBe(expected);
  });

  it('retries a failed delivery and eventually succeeds with a valid signature', async () => {
    const sink = makeSink(1); // fail once, then succeed
    await new Promise<void>((r) => sink.server.listen(0, r));
    try {
      const emitter = new HttpWebhookEmitter({ url: sink.url(), secret: 'shh', maxAttempts: 3, timeoutMs: 2000 });
      await emitter.emit([{ id: 'evt-1', type: 'scan.completed', scanId: 's1', orgId: 'default', at: '2026-01-01', data: { decision: 'GO' } }]);
      expect(sink.received).toHaveLength(1);
      const got = sink.received[0]!;
      expect(got.type).toBe('scan.completed');
      expect(got.signature).toBe(signPayload('shh', got.body));
    } finally {
      await new Promise<void>((r) => sink.server.close(() => r()));
    }
  });

  it('delivers scan.completed + critical.finding + quality-gate.failed for a NO_GO scan, signed', async () => {
    const sink = makeSink(0);
    await new Promise<void>((r) => sink.server.listen(0, r));
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-wh-'));
    try {
      const store = new InMemoryScanStore();
      const queue = new InMemoryJobQueue<ScanJobPayload>({ concurrency: 1, maxAttempts: 1 });
      const service = new ScanService(store, queue);
      const emitter = new HttpWebhookEmitter({ url: sink.url(), secret: 'k', maxAttempts: 2, timeoutMs: 3000 });
      startWorker(store, queue, { environment: 'test', webhook: emitter });

      await service.submit({ projectId: 'p', projectDir: fixtureDir, evidenceRoot: tmp });
      await queue.onIdle();
      // Give the fire-after-complete delivery a beat to arrive.
      await new Promise((r) => setTimeout(r, 200));

      const types = sink.received.map((r) => r.type).sort();
      expect(types).toContain('scan.completed');
      expect(types).toContain('critical.finding'); // vulnerable-sample seeds a Critical secret
      expect(types).toContain('quality-gate.failed'); // decision NO_GO
      // Every delivery is signed and the signature matches its body.
      for (const r of sink.received) expect(r.signature).toBe(signPayload('k', r.body));
    } finally {
      await new Promise<void>((r) => sink.server.close(() => r()));
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });
});
