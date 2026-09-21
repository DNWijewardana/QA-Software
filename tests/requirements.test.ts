/**
 * RequirementsScanner test (§V.1). Scans the weak-requirements fixture and confirms each requirement-quality
 * defect is detected, that a well-formed requirement is NOT flagged, and that the findings feed the
 * Functional dimension. Also checks the Markdown parsing path on a temp project.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/weak-requirements', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('RequirementsScanner (§V.1)', () => {
  it('detects requirement-quality defects and feeds the Functional dimension', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-req-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_req', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    for (const expected of [
      'REQ-AMBIGUOUS-001',
      'REQ-NOT-TESTABLE-001',
      'REQ-NO-ACCEPTANCE-001',
      'REQ-NOT-ATOMIC-001',
      'REQ-MISSING-ID-001',
      'REQ-MISSING-PRIORITY-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }
    // The well-formed REQ-004 must not inflate counts: exactly one ambiguous + one not-atomic finding.
    expect(rules.filter((r) => r === 'REQ-AMBIGUOUS-001')).toHaveLength(1);
    expect(rules.filter((r) => r === 'REQ-NOT-ATOMIC-001')).toHaveLength(1);
    // Requirements quality scores under the Functional dimension (§V.1 → functional suitability).
    expect(result.scores.some((s) => s.dimension === 'Functional')).toBe(true);
  });

  it('builds a requirement→test traceability matrix (§VII.13)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-trace-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_trace', evidenceDir: path.join(dir, 'ev') });
    const t = result.traceability;
    expect(t).toBeDefined();
    // REQ-001/002/004 have ids (traceable); REQ-003 has none (untraceable).
    expect(t!.summary.totalRequirements).toBe(3);
    expect(t!.untraceableRequirements).toBe(1);
    // The test file references REQ-001 and REQ-002 → covered; REQ-004 has no test → uncovered.
    expect(t!.summary.covered).toBe(2);
    expect(t!.summary.uncovered).toBe(1);
    expect(t!.requirements.find((r) => r.id === 'REQ-004')?.covered).toBe(false);
    expect(t!.requirements.find((r) => r.id === 'REQ-001')?.covered).toBe(true);
    // REQ-999 in the test file is not a real requirement → a dangling reference.
    expect(t!.danglingReferences.some((d) => d.ids.includes('REQ-999'))).toBe(true);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('parses Markdown requirements and does not flag a well-formed one', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-req-md-'));
    await fs.writeFile(
      path.join(dir, 'requirements.md'),
      [
        '# Requirements',
        '- REQ-100: The service shall return HTTP 200 within 500ms for a valid request.',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runScan({ projectDir: dir, scanId: 'scan_req_md', evidenceDir: path.join(dir, 'ev') });
    const reqFindings = result.findings.filter((f) => f.ruleId.startsWith('REQ-'));
    // A measurable, atomic, identified requirement → no quality defects. (Markdown has no acceptance/priority
    // FIELDS, so those checks are intentionally skipped for the Markdown path.)
    expect(reqFindings).toHaveLength(0);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
