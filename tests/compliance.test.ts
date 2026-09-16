/**
 * Compliance mapper tests (§IV.3). Verifies control statuses (SATISFIED/GAPS/NOT_ASSESSED), the honesty
 * disclaimer, the ComplianceReadiness score, and the end-to-end matrix on a real scan.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapCompliance, type Finding } from '@qa/core';
import { runScan } from '@qa/orchestrator';

function finding(ruleId: string, status: Finding['status']): Finding {
  return {
    id: `${ruleId}-x`,
    ruleId,
    category: 'Security',
    title: ruleId,
    description: 'd',
    status,
    evidenceClass: status === 'FAIL' ? 'AUTOMATICALLY_DETECTED' : 'AUTOMATICALLY_DETECTED',
    severity: 'High',
    risk: 'High',
    confidence: 'Highly likely',
    reproducibility: 'Always',
    cwe: [],
    cve: [],
    location: {},
    detectionMethod: 'static',
    evidence: [{ type: 'source-code', ref: 'e', redacted: true }],
    standards: [],
    traceability: { requirements: [], tests: [] },
  };
}

describe('mapCompliance (§IV.3)', () => {
  it('marks a violated control as GAPS and an un-run check as NOT_ASSESSED', () => {
    const { matrix, score } = mapCompliance([finding('SEC-SECRET-001', 'FAIL')], new Set(['secret-scanner']));

    const cc61 = matrix.controls.find((c) => c.controlId === 'CC6.1');
    expect(cc61?.status).toBe('GAPS');
    expect(cc61?.gapFindings).toContain('SEC-SECRET-001-x');

    // Docker/K8s checks did not run → their controls are NOT_ASSESSED (never silently satisfied).
    const dockerControl = matrix.controls.find((c) => c.framework === 'CIS Docker Benchmark');
    expect(dockerControl?.status).toBe('NOT_ASSESSED');

    expect(matrix.disclaimer.toLowerCase()).toContain('not a certification');
    expect(score.dimension).toBe('ComplianceReadiness');
    expect(score.why.length).toBeGreaterThan(0);
  });

  it('marks a check that ran with no violation as SATISFIED', () => {
    const { matrix } = mapCompliance([], new Set(['dependency-scanner']));
    const cc71 = matrix.controls.find((c) => c.controlId === 'CC7.1');
    expect(cc71?.status).toBe('SATISFIED');
    // A control whose engine did not run stays NOT_ASSESSED.
    const secret = matrix.controls.find((c) => c.controlId === 'CC6.1');
    expect(secret?.status).toBe('NOT_ASSESSED');
  });
});

describe('compliance end-to-end', () => {
  let tmp: string;
  afterAll(async () => {
    if (tmp) await fs.rm(tmp, { recursive: true, force: true });
  });

  it('attaches a compliance matrix and ComplianceReadiness score to a real scan', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-comp-'));
    const fixture = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url));
    const result = await runScan({ projectDir: fixture, scanId: 'scan_comp', evidenceDir: path.join(tmp, 'ev') });

    expect(result.compliance).toBeDefined();
    expect(result.compliance!.frameworks.length).toBeGreaterThan(0);
    // secret + dependency checks ran on this fixture; docker/k8s did not.
    expect(result.compliance!.summary.assessed).toBe(4);
    expect(result.compliance!.summary.notAssessed).toBe(7);
    expect(result.compliance!.summary.gaps).toBeGreaterThan(0);
    expect(result.scores.some((s) => s.dimension === 'ComplianceReadiness')).toBe(true);
  });
});
