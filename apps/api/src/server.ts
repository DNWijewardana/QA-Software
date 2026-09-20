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
 *   POST /projects/:projectId/scans      { projectDir | sourceUrl, policy?, suppressions? } -> 202 { scanId }
 *   GET  /scans/:scanId                   job status + honest stage progress (no fake %)
 *   GET  /scans/:scanId/result            full canonical ScanResult (when COMPLETED)
 *   GET  /scans/:scanId/findings          filter ?severity=&status=
 *   GET  /scans/:scanId/report?format=human|html|json|sarif|junit|csv|cyclonedx
 *   GET  /scans/:scanId/diff?baseline=<scanId>&format=json|human   differential analysis (§VII.10)
 */

import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { assertAllowedRemote, isRemoteTarget, renderHumanReport } from '@qa/orchestrator';
import { toCsv, toCycloneDx, toHtml, toJUnit, toSarif } from '@qa/reporters';
import { diffScans, renderScanDiff, type ScanPolicy, type Suppression } from '@qa/core';
import {
  InMemoryAuditStore,
  InMemoryJobQueue,
  InMemoryScanStore,
  ScanService,
  startWorker,
  type AuditStore,
  type JobQueue,
  type ScanJobPayload,
  type ScanStore,
} from '@qa/jobs';
import { resolveWithinAllowedRoots } from './security.js';
import { authenticate, canSubmitScan, type ApiKeyConfig, type Principal, type Role } from './auth.js';
import { RateLimiter } from './ratelimit.js';

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
  /**
   * API keys for authentication + multi-tenancy (§VIII.8). When non-empty, auth is ENFORCED and every
   * request must present a valid key; records are isolated per org. When empty/undefined the API runs open
   * (single-tenant dev mode) and all records use org 'default'.
   */
  apiKeys?: ApiKeyConfig[];
  /** injected tamper-evident audit store (default in-memory) — §VIII.7. */
  auditStore?: AuditStore;
  /** per-key request budget (§VI.9). Default 300 requests / 60s. */
  rateLimit?: { limit: number; windowMs: number };
}

export interface ApiHandle {
  server: http.Server;
  service: ScanService;
  store: ScanStore;
  queue: JobQueue<ScanJobPayload>;
  auditStore: AuditStore;
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

  const apiKeys = config.apiKeys ?? [];
  const authEnabled = apiKeys.length > 0;
  const OPEN_PRINCIPAL: Principal = { orgId: 'default', role: 'Owner', keyId: 'open' };
  const audit = config.auditStore ?? new InMemoryAuditStore();
  const limiter = new RateLimiter(config.rateLimit?.limit ?? 300, config.rateLimit?.windowMs ?? 60_000);
  const AUDIT_ROLES = new Set<Role>(['Owner', 'Admin', 'Auditor', 'ComplianceOfficer']);

  /** Resolve the caller's principal, or null (caller unauthenticated when auth is enabled). */
  const resolvePrincipal = (req: http.IncomingMessage): Principal | null => {
    if (!authEnabled) return OPEN_PRINCIPAL;
    return authenticate(req, apiKeys);
  };
  const clientIp = (req: http.IncomingMessage): string => req.socket.remoteAddress ?? 'unknown';

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      json(res, 500, { error: 'internal_error', message: err instanceof Error ? err.message : String(err) });
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const parts = url.pathname.split('/').filter(Boolean);
    const method = req.method ?? 'GET';

    // GET /health — public (no auth) so load balancers can probe it.
    if (method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { status: 'ok', mode: 'SAFE_STATIC', authEnabled, queueDepth: await queue.size() });
    }

    const principal = resolvePrincipal(req);

    // Rate limiting (§VI.9): per key when authenticated, else per client IP.
    const rl = limiter.check(principal ? principal.keyId : `ip:${clientIp(req)}`);
    res.setHeader('x-ratelimit-limit', String(rl.limit));
    res.setHeader('x-ratelimit-remaining', String(rl.remaining));
    if (!rl.allowed) {
      res.setHeader('retry-after', String(Math.ceil(rl.resetMs / 1000)));
      return json(res, 429, { error: 'rate_limited', message: 'Rate limit exceeded; retry later.' });
    }

    // All other routes require authentication when auth is enabled (§VIII.8).
    if (!principal) {
      await audit.append({ orgId: 'unknown', actor: `ip:${clientIp(req)}`, action: 'auth.denied', target: url.pathname });
      res.setHeader('www-authenticate', 'Bearer');
      return json(res, 401, { error: 'unauthorized', message: 'A valid API key is required (Authorization: Bearer <key>).' });
    }

    // GET /targets  (candidate scan projects = immediate subdirs of each allowed root)
    if (method === 'GET' && url.pathname === '/targets') {
      const roots = await Promise.all(
        config.allowedRoots.map(async (root) => {
          let projects: Array<{ name: string; path: string }> = [];
          try {
            const entries = await fs.readdir(root, { withFileTypes: true });
            projects = entries
              .filter((e) => e.isDirectory())
              .map((e) => ({ name: e.name, path: path.join(root, e.name) }))
              .sort((a, b) => a.name.localeCompare(b.name));
          } catch {
            /* root missing/unreadable — return no projects for it */
          }
          return { root, projects };
        }),
      );
      return json(res, 200, roots);
    }

    // GET /audit  (tamper-evident audit log, org-scoped, role-gated — §VIII.7)
    if (method === 'GET' && url.pathname === '/audit') {
      if (!AUDIT_ROLES.has(principal.role)) {
        return json(res, 403, { error: 'forbidden', message: `Role '${principal.role}' may not read the audit log.` });
      }
      const events = await audit.list(principal.orgId, 200);
      const integrity = await audit.verify();
      return json(res, 200, { integrity, events });
    }

    // GET /scans  (list — scoped to the caller's org)
    if (method === 'GET' && parts.length === 1 && parts[0] === 'scans') {
      const projectId = url.searchParams.get('projectId') ?? undefined;
      const records = await service.list(projectId);
      const scoped = records.filter((r) => r.orgId === principal.orgId);
      return json(res, 200, scoped.map(summarize));
    }

    // POST /projects/:projectId/scans  (write — RBAC gated)
    if (method === 'POST' && parts.length === 3 && parts[0] === 'projects' && parts[2] === 'scans') {
      if (!canSubmitScan(principal.role)) {
        return json(res, 403, { error: 'forbidden', message: `Role '${principal.role}' may not submit scans.` });
      }
      const projectId = decodeURIComponent(parts[1]!);
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (e) {
        return json(res, 400, { error: 'bad_request', message: e instanceof Error ? e.message : 'invalid body' });
      }
      const projectDir = typeof body.projectDir === 'string' ? body.projectDir.trim() : '';
      const sourceUrl = typeof body.sourceUrl === 'string' ? body.sourceUrl.trim() : '';
      if (!projectDir === !sourceUrl) {
        return json(res, 400, { error: 'bad_request', message: 'provide exactly one of projectDir or sourceUrl' });
      }

      const submitInput: { projectId: string; projectDir?: string; sourceUrl?: string; evidenceRoot: string; orgId: string; policy?: ScanPolicy; suppressions?: Suppression[] } = {
        projectId,
        evidenceRoot: config.evidenceRoot,
        orgId: principal.orgId,
      };
      // Optional scoring/gate policy (§VII.11). Untrusted values are clamped/ignored by resolvePolicy;
      // a policy can never un-block a Critical finding.
      if (body.policy && typeof body.policy === 'object' && !Array.isArray(body.policy)) {
        submitInput.policy = body.policy as ScanPolicy;
      }
      // Optional false-positive suppressions (§VII.17). Invalid entries are validated/ignored by the
      // orchestrator; a suppression can never hide a Critical finding.
      if (Array.isArray(body.suppressions)) {
        submitInput.suppressions = body.suppressions as Suppression[];
      }
      let auditTarget: string;

      if (sourceUrl) {
        // Remote target: enforce the https-only / no-creds / no-private-host policy before enqueuing.
        if (!isRemoteTarget(sourceUrl)) {
          return json(res, 400, { error: 'bad_request', message: 'sourceUrl is not a URL' });
        }
        let normalized: string;
        try {
          normalized = assertAllowedRemote(sourceUrl);
        } catch (e) {
          return json(res, 400, { error: 'forbidden_source', message: e instanceof Error ? e.message : 'disallowed source URL' });
        }
        submitInput.sourceUrl = normalized;
        auditTarget = normalized;
      } else {
        // Local target: constrain to the API's configured allowed roots (§VIII.5 path guard).
        const check = resolveWithinAllowedRoots(projectDir, config.allowedRoots);
        if (!check.ok) return json(res, 403, { error: 'forbidden_path', message: check.reason });
        submitInput.projectDir = check.resolved;
        auditTarget = check.resolved;
      }

      const record = await service.submit(submitInput);
      await audit.append({ orgId: principal.orgId, actor: principal.keyId, action: 'scan.submit', target: `${record.scanId} (${auditTarget})` });
      res.setHeader('location', `/scans/${record.scanId}`);
      return json(res, 202, summarize(record));
    }

    // /scans/:scanId ...
    if (parts.length >= 2 && parts[0] === 'scans') {
      const scanId = decodeURIComponent(parts[1]!);
      const record = await service.get(scanId);
      // Tenant isolation (§VIII.8): a record in another org is reported as not-found, never disclosed.
      if (!record || record.orgId !== principal.orgId) {
        if (record && record.orgId !== principal.orgId) {
          // A cross-org access attempt is a security-relevant event — audit it.
          await audit.append({ orgId: principal.orgId, actor: principal.keyId, action: 'scan.access.denied', target: scanId });
        }
        return json(res, 404, { error: 'not_found', message: `scan ${scanId} not found` });
      }

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
          case 'html':
            return send(res, 200, toHtml(result), 'text/html; charset=utf-8');
          case 'sarif':
            return send(res, 200, toSarif(result), 'application/json');
          case 'junit':
            return send(res, 200, toJUnit(result), 'application/xml; charset=utf-8');
          case 'csv':
            return send(res, 200, toCsv(result), 'text/csv; charset=utf-8');
          case 'cyclonedx':
            if (!result.sbom) return json(res, 404, { error: 'no_sbom', message: 'scan produced no SBOM' });
            return send(res, 200, toCycloneDx(result.sbom, result.scan.id), 'application/json');
          case 'compliance':
            if (!result.compliance) return json(res, 404, { error: 'no_compliance', message: 'scan produced no compliance matrix' });
            return json(res, 200, result.compliance);
          case 'seo':
            if (!result.seo) return json(res, 404, { error: 'no_seo', message: 'scan analysed no HTML pages' });
            return json(res, 200, result.seo);
          default:
            return json(res, 400, { error: 'bad_format', message: `unknown format '${format}'` });
        }
      }

      // GET /scans/:scanId/diff?baseline=<scanId>&format=json|human  (differential analysis §VII.10)
      if (method === 'GET' && parts.length === 3 && parts[2] === 'diff') {
        if (record.state !== 'COMPLETED' || !record.result) {
          return json(res, 409, { error: 'not_ready', state: record.state, progress: record.progress });
        }
        const baselineId = url.searchParams.get('baseline');
        if (!baselineId) {
          return json(res, 400, { error: 'missing_baseline', message: 'query param ?baseline=<scanId> is required' });
        }
        const baseline = await service.get(baselineId);
        // Tenant isolation (§VIII.8): a baseline in another org is reported as not-found, never disclosed.
        if (!baseline || baseline.orgId !== principal.orgId) {
          if (baseline && baseline.orgId !== principal.orgId) {
            await audit.append({ orgId: principal.orgId, actor: principal.keyId, action: 'scan.access.denied', target: baselineId });
          }
          return json(res, 404, { error: 'not_found', message: `scan ${baselineId} not found` });
        }
        if (baseline.state !== 'COMPLETED' || !baseline.result) {
          return json(res, 409, { error: 'baseline_not_ready', state: baseline.state, progress: baseline.progress });
        }
        const diff = diffScans(baseline.result, record.result);
        const format = (url.searchParams.get('format') ?? 'json').toLowerCase();
        if (format === 'human') return send(res, 200, renderScanDiff(diff), 'text/markdown; charset=utf-8');
        if (format === 'json') return json(res, 200, diff);
        return json(res, 400, { error: 'bad_format', message: `unknown format '${format}'` });
      }
    }

    return json(res, 404, { error: 'not_found', message: `no route for ${method} ${url.pathname}` });
  }

  return { server, service, store, queue, auditStore: audit };
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
