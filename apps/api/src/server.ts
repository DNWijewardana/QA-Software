/**
 * Platform HTTP API (§VI.9, §IX.5) — dependency-light node:http server.
 *
 * DESIGN NOTE (deviation from doc 02's NestJS choice, per spec XI.1 "no replacement without justification"):
 * the whole workspace is ESM/NodeNext; NestJS is CommonJS-first and its ESM story is brittle. To keep the
 * delivery layer verifiable with ZERO infra and no framework friction, the API is a thin, structured
 * node:http layer implementing the same REST contract (doc 07). A NestJS migration remains an option once
 * the Postgres/BullMQ adapters land; the ScanService/JobQueue/ScanStore abstractions are framework-agnostic.
 *
 * Endpoints:
 *   GET  /health
 *   GET  /scans                          list (optional ?projectId=)
 *   POST /projects/:projectId/scans      { projectDir } -> 202 { scanId }
 *   GET  /scans/:scanId                   job status + honest stage progress (no fake %)
 *   GET  /scans/:scanId/result            full canonical ScanResult (when COMPLETED)
 *   GET  /scans/:scanId/findings          filter ?severity=&status=
 *   GET  /scans/:scanId/report?format=human|json|sarif|junit|csv|cyclonedx
 */

import http from 'node:http';
import { renderHumanReport } from '@qa/orchestrator';
import { toCsv, toCycloneDx, toJUnit, toSarif } from '@qa/reporters';
import {
  InMemoryJobQueue,
  InMemoryScanStore,
  ScanService,
  startWorker,
  type JobQueue,
  type ScanJobPayload,
  type ScanStore,
} from '@qa/jobs';
import { resolveWithinAllowedRoots } from './security.js';

export interface ApiConfig {
  /** absolute directories a scan target must live under (§VIII.5). */
  allowedRoots: string[];
  /** where per-scan evidence is written. */
  evidenceRoot: string;
  /** injected store (default in-memory). Provide a PostgresScanStore for the distributed deployment. */
  store?: ScanStore;
  /** injected queue (default in-memory). Provide a BullMqJobQueue for the distributed deployment. */
  queue?: JobQueue<ScanJobPayload>;
  /**
   * Whether the API process also runs the worker. Defaults to true for the in-memory single-process
   * deployment, and false when a queue is injected (the worker runs as a separate process — apps/worker).
   */
  embedWorker?: boolean;
}

export interface ApiHandle {
  server: http.Server;
  service: ScanService;
  store: ScanStore;
  queue: JobQueue<ScanJobPayload>;
}

function send(res: http.ServerResponse, status: number, body: string, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'cache-control': 'no-store' });
  res.end(body);
}
const json = (res: http.ServerResponse, status: number, obj: unknown) =>
  send(res, status, JSON.stringify(obj, null, 2), 'application/json');

async function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 1_000_000) throw new Error('request body too large'); // basic DoS guard (§VIII.5)
    chunks.push(c as Buffer);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
}

export function createApiServer(config: ApiConfig): ApiHandle {
  const store = config.store ?? new InMemoryScanStore();
  const queue = config.queue ?? new InMemoryJobQueue<ScanJobPayload>({ concurrency: 2, maxAttempts: 1 });
  const service = new ScanService(store, queue);
  // Embed the worker only in the single-process (in-memory) deployment. When a distributed queue is
  // injected, the worker runs as a SEPARATE process (apps/worker) consuming the shared Redis broker.
  const embedWorker = config.embedWorker ?? config.queue === undefined;
  if (embedWorker) startWorker(store, queue, { environment: 'api-embedded-worker' });

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      json(res, 500, { error: 'internal_error', message: err instanceof Error ? err.message : String(err) });
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const parts = url.pathname.split('/').filter(Boolean);
    const method = req.method ?? 'GET';

    // GET /health
    if (method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { status: 'ok', mode: 'SAFE_STATIC', queueDepth: await queue.size() });
    }

    // GET /scans  (list)
    if (method === 'GET' && parts.length === 1 && parts[0] === 'scans') {
      const projectId = url.searchParams.get('projectId') ?? undefined;
      const records = await service.list(projectId);
      return json(res, 200, records.map(summarize));
    }

    // POST /projects/:projectId/scans
    if (method === 'POST' && parts.length === 3 && parts[0] === 'projects' && parts[2] === 'scans') {
      const projectId = decodeURIComponent(parts[1]!);
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (e) {
        return json(res, 400, { error: 'bad_request', message: e instanceof Error ? e.message : 'invalid body' });
      }
      const projectDir = typeof body.projectDir === 'string' ? body.projectDir : '';
      if (!projectDir) return json(res, 400, { error: 'bad_request', message: 'projectDir is required' });

      const check = resolveWithinAllowedRoots(projectDir, config.allowedRoots);
      if (!check.ok) return json(res, 403, { error: 'forbidden_path', message: check.reason });

      const record = await service.submit({
        projectId,
        projectDir: check.resolved,
        evidenceRoot: config.evidenceRoot,
      });
      res.setHeader('location', `/scans/${record.scanId}`);
      return json(res, 202, summarize(record));
    }

    // /scans/:scanId ...
    if (parts.length >= 2 && parts[0] === 'scans') {
      const scanId = decodeURIComponent(parts[1]!);
      const record = await service.get(scanId);
      if (!record) return json(res, 404, { error: 'not_found', message: `scan ${scanId} not found` });

      // GET /scans/:scanId
      if (method === 'GET' && parts.length === 2) return json(res, 200, summarize(record));

      // GET /scans/:scanId/result
      if (method === 'GET' && parts.length === 3 && parts[2] === 'result') {
        if (record.state !== 'COMPLETED' || !record.result) {
          return json(res, 409, { error: 'not_ready', state: record.state, progress: record.progress });
        }
        return json(res, 200, record.result);
      }

      // GET /scans/:scanId/findings?severity=&status=
      if (method === 'GET' && parts.length === 3 && parts[2] === 'findings') {
        if (record.state !== 'COMPLETED' || !record.result) {
          return json(res, 409, { error: 'not_ready', state: record.state, progress: record.progress });
        }
        const sev = url.searchParams.get('severity');
        const status = url.searchParams.get('status');
        let findings = record.result.findings;
        if (sev) findings = findings.filter((f) => f.severity === sev);
        if (status) findings = findings.filter((f) => f.status === status);
        return json(res, 200, findings);
      }

      // GET /scans/:scanId/report?format=...
      if (method === 'GET' && parts.length === 3 && parts[2] === 'report') {
        if (record.state !== 'COMPLETED' || !record.result) {
          return json(res, 409, { error: 'not_ready', state: record.state, progress: record.progress });
        }
        const format = (url.searchParams.get('format') ?? 'json').toLowerCase();
        const result = record.result;
        switch (format) {
          case 'json':
            return json(res, 200, result);
          case 'human':
            return send(res, 200, renderHumanReport(result), 'text/markdown; charset=utf-8');
          case 'sarif':
            return send(res, 200, toSarif(result), 'application/json');
          case 'junit':
            return send(res, 200, toJUnit(result), 'application/xml; charset=utf-8');
          case 'csv':
            return send(res, 200, toCsv(result), 'text/csv; charset=utf-8');
          case 'cyclonedx':
            if (!result.sbom) return json(res, 404, { error: 'no_sbom', message: 'scan produced no SBOM' });
            return send(res, 200, toCycloneDx(result.sbom, result.scan.id), 'application/json');
          default:
            return json(res, 400, { error: 'bad_format', message: `unknown format '${format}'` });
        }
      }
    }

    return json(res, 404, { error: 'not_found', message: `no route for ${method} ${url.pathname}` });
  }

  return { server, service, store, queue };
}

/** Summarize a record for status endpoints (omits the heavy result payload). */
function summarize(r: {
  scanId: string;
  projectId: string;
  state: string;
  progress: unknown;
  createdAt: string;
  updatedAt: string;
  error?: string;
  result?: { releaseDecision: { decision: string }; overall: { criticalBlockers: number } };
}) {
  return {
    scanId: r.scanId,
    projectId: r.projectId,
    state: r.state,
    progress: r.progress,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    ...(r.error ? { error: r.error } : {}),
    ...(r.result
      ? {
          summary: {
            decision: r.result.releaseDecision.decision,
            criticalBlockers: r.result.overall.criticalBlockers,
            links: {
              result: `/scans/${r.scanId}/result`,
              findings: `/scans/${r.scanId}/findings`,
              report: `/scans/${r.scanId}/report?format=human`,
            },
          },
        }
      : {}),
  };
}
