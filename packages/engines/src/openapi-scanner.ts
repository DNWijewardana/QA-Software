/**
 * OpenApiScanner — OpenAPI/Swagger specification quality & security checks (Security dimension).
 * Spec ref: §V.6 (API quality — analyze OpenAPI specs), OWASP API Security Top 10 (2023).
 *
 * Deterministic (§0.2.2): analyses the SPEC itself (no source route extraction). Detects missing
 * authentication, unprotected operations, cleartext servers, API keys in query strings, missing error
 * responses, and missing operationIds. Only files that declare `openapi`/`swagger` + `paths` are analysed,
 * so ordinary JSON/YAML (package.json, k8s, compose, CI configs) is never touched.
 */

import { parseDocument } from 'yaml';
import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
const CHECK_CATEGORIES = 6;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const rec = (v: unknown): Record<string, unknown> => (isRecord(v) ? v : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function isSpecCandidate(f: ProjectFile): boolean {
  return /\.(ya?ml|json)$/i.test(f.path);
}

function parse(content: string, path: string): unknown {
  if (/\.json$/i.test(path)) {
    try {
      return JSON.parse(content);
    } catch {
      return null;
    }
  }
  try {
    return parseDocument(content).toJS({ maxAliasCount: 200 });
  } catch {
    return null;
  }
}

function isOpenApi(doc: Record<string, unknown>): boolean {
  const openapi = str(doc.openapi);
  const swagger = str(doc.swagger);
  return ((openapi?.startsWith('3') ?? false) || swagger === '2.0') && isRecord(doc.paths);
}

export class OpenApiScanner implements Engine {
  readonly name = 'openapi-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isSpecCandidate);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;
    let specCount = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of ctx.files.filter(isSpecCandidate)) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const doc = rec(parse(content, file.path));
      if (!isOpenApi(doc)) continue;
      specCount++;

      const isV2 = str(doc.swagger) === '2.0';
      const schemes = isV2 ? rec(doc.securityDefinitions) : rec(rec(doc.components).securitySchemes);
      const schemesExist = Object.keys(schemes).length > 0;
      const globalSecurity = arr(doc.security);

      const push = (rule: string, title: string, severity: Finding['severity'], status: Finding['status'], loc: Finding['location'], desc: string, art: string, fix: string, owaspId: string, cwe: string[]) =>
        findings.push(this.mk(findingId(rule, ordinal++), rule, title, severity, status, loc, desc, art, fix, owaspId, cwe));

      // Spec-level: no authentication defined at all.
      if (!schemesExist) {
        const art = addArtifact(`${file.path}:noauth`, `File: ${file.path}\nNo securitySchemes/securityDefinitions defined.`);
        push('API-SPEC-NOAUTH-001', 'No authentication scheme defined', 'High', 'FAIL', { file: file.path },
          'The API specification defines no security schemes, so no authentication is described for any endpoint (OWASP API2: Broken Authentication).',
          art, 'Define securitySchemes (OAuth2/OIDC/API key) and apply security to protected operations.', 'API2:2023', ['CWE-306']);
      }

      // Server transport: cleartext http.
      const serverUrls: string[] = [];
      if (isV2) {
        for (const s of arr(doc.schemes)) if (str(s) === 'http') serverUrls.push('http://(schemes)');
      } else {
        for (const s of arr(doc.servers)) {
          const u = str(rec(s).url);
          if (u) serverUrls.push(u);
        }
      }
      for (const url of serverUrls) {
        if (/^http:\/\//i.test(url) || url === 'http://(schemes)') {
          const art = addArtifact(`${file.path}:http:${url}`, `File: ${file.path}\nServer uses cleartext HTTP: ${url}`);
          push('API-SPEC-HTTP-001', 'API server uses cleartext HTTP', 'Medium', 'FAIL', { file: file.path },
            `A server is declared over cleartext HTTP (\`${url}\`). Traffic — including credentials and tokens — can be intercepted.`,
            art, 'Serve the API only over HTTPS/TLS.', 'API8:2023', ['CWE-319']);
        }
      }

      // API keys carried in the query string.
      for (const [schemeName, schemeUnknown] of Object.entries(schemes)) {
        const scheme = rec(schemeUnknown);
        if (str(scheme.type) === 'apiKey' && str(scheme.in) === 'query') {
          const art = addArtifact(`${file.path}:apikeyquery:${schemeName}`, `File: ${file.path}\nsecurityScheme ${schemeName}: apiKey in query`);
          push('API-SPEC-APIKEY-QUERY-001', `API key passed in query string: ${schemeName}`, 'Medium', 'FAIL', { file: file.path },
            `Security scheme \`${schemeName}\` carries an API key in the URL query string, which leaks into server logs, proxies, and browser history.`,
            art, 'Send API keys in a header (or use OAuth2), never in the query string.', 'API8:2023', ['CWE-598']);
        }
      }

      // Per-operation checks.
      const paths = rec(doc.paths);
      for (const [route, pathItemUnknown] of Object.entries(paths)) {
        const pathItem = rec(pathItemUnknown);
        for (const method of METHODS) {
          if (!isRecord(pathItem[method])) continue;
          const op = rec(pathItem[method]);
          const endpoint = `${method.toUpperCase()} ${route}`;
          const loc: Finding['location'] = { file: file.path, endpoint };

          const effectiveSecurity = op.security !== undefined ? arr(op.security) : globalSecurity;
          const isProtected = effectiveSecurity.length > 0;
          if (schemesExist && !isProtected) {
            const art = addArtifact(`${file.path}:opnoauth:${endpoint}`, `File: ${file.path}\n${endpoint}\nNo effective security requirement.`);
            push('API-SPEC-OP-NOAUTH-001', `Operation lacks authentication: ${endpoint}`, 'High', 'FAIL', loc,
              `Security schemes are defined but \`${endpoint}\` has no effective security requirement (no operation-level or global security). It is exposed without authentication (OWASP API5/API2).`,
              art, 'Add a `security` requirement to this operation, or a global `security` block.', 'API2:2023', ['CWE-306']);
          }

          const responses = rec(op.responses);
          const hasError = Object.keys(responses).some((code) => code.startsWith('4') || code.startsWith('5') || code === 'default');
          if (Object.keys(responses).length > 0 && !hasError) {
            const art = addArtifact(`${file.path}:noerr:${endpoint}`, `File: ${file.path}\n${endpoint}\nresponses: ${Object.keys(responses).join(', ')}`);
            push('API-SPEC-NO-ERRORS-001', `No error responses documented: ${endpoint}`, 'Low', 'WARNING', loc,
              `\`${endpoint}\` documents no 4xx/5xx (or default) responses, so clients cannot handle error contracts reliably.`,
              art, 'Document at least one 4xx and a 5xx (or a default) response.', 'API8:2023', []);
          }

          if (str(op.operationId) === undefined) {
            const art = addArtifact(`${file.path}:noopid:${endpoint}`, `File: ${file.path}\n${endpoint}\nMissing operationId.`);
            push('API-SPEC-NO-OPID-001', `Operation missing operationId: ${endpoint}`, 'Informational', 'WARNING', loc,
              `\`${endpoint}\` has no operationId, which hurts codegen, testing, and traceability.`,
              art, 'Add a unique operationId to each operation.', 'API9:2023', []);
          }
        }
      }
    }

    // When no OpenAPI/Swagger spec is present, the engine did no work — 0 checks, so it is NOT counted
    // as having assessed any control (honest NOT_ASSESSED, not a false "satisfied").
    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: specCount * CHECK_CATEGORIES,
      executedChecks: specCount * CHECK_CATEGORIES,
      findings,
      artifacts,
      degraded: specCount === 0,
      degradedReason: specCount === 0 ? 'no OpenAPI/Swagger specification found' : undefined,
    };
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    status: Finding['status'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    remediation: string,
    owaspId: string,
    cwe: string[],
  ): Finding {
    return {
      id,
      ruleId,
      category: 'API',
      subcategory: 'OpenAPI',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Highly likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.endpoint ?? location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: false }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : severity === 'Medium' ? 'Medium' : 'Low' },
      verificationMethod: 'Re-scan the specification after remediation.',
      standards: [
        { framework: 'OWASP API Security Top 10', version: '2023', id: owaspId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
