/**
 * OpenApiScanner test (§V.6, OWASP API Security Top 10 2023). Scans the intentionally-weak OpenAPI
 * fixture (a YAML spec with schemes + a JSON spec with none) and confirms each seeded issue is detected,
 * the API-auth compliance control shows a gap, and the Security dimension is scored. Isolated fixture.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-openapi', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('OpenApiScanner (OpenAPI spec quality/security)', () => {
  it('detects every seeded specification weakness', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-oas-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_oas', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'API-SPEC-NOAUTH-001', // from api-no-auth.json (no schemes)
      'API-SPEC-HTTP-001', // openapi.yaml http server
      'API-SPEC-APIKEY-QUERY-001', // apiKey in query
      'API-SPEC-OP-NOAUTH-001', // unprotected operation while schemes exist
      'API-SPEC-NO-ERRORS-001', // /users has no error responses
      'API-SPEC-NO-OPID-001', // /users has no operationId
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    // API findings score under the Security dimension.
    expect(result.scores.some((s) => s.dimension === 'Security')).toBe(true);

    // The OWASP API2 (authentication) compliance control is assessed and shows a gap.
    const ctrl = result.compliance?.controls.find((c) => c.controlId === 'API2');
    expect(ctrl?.status).toBe('GAPS');

    // No Critical here → not a hard block, but conditions apply (High findings present).
    expect(result.overall.highRiskFindings).toBeGreaterThan(0);
    expect(result.releaseDecision.decision).toBe('GO_WITH_CONDITIONS');
  });

  it('ignores non-spec JSON/YAML (no false positives)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-oas-plain-'));
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }), 'utf8');
    await fs.writeFile(path.join(dir, 'settings.yaml'), 'foo: bar\nlist:\n  - a\n', 'utf8');
    const result = await runScan({ projectDir: dir, scanId: 'scan_plain_oas', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('API-SPEC-'))).toBe(false);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
