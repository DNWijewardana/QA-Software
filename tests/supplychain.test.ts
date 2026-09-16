/**
 * Supply-chain engine + SBOM + exporters tests (§V.17, §IX.3).
 * Runs one real scan of the fixture, then asserts dependency findings, SBOM, and every export format.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanResult } from '@qa/core';
import { runScan } from '@qa/orchestrator';
import { toCsv, toCycloneDx, toJUnit, toSarif } from '@qa/reporters';

const fixtureDir = fileURLToPath(new URL('../fixtures/vulnerable-sample', import.meta.url));
let tmp: string;
let result: ScanResult;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-supply-'));
  result = await runScan({ projectDir: fixtureDir, scanId: 'scan_supply', evidenceDir: path.join(tmp, 'ev') });
});
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('dependency scanner (§V.17)', () => {
  it('flags missing lockfile and unpinned versions', () => {
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('SUP-LOCK-001'); // no lockfile in fixture
    expect(ruleIds).toContain('SUP-PIN-001'); // left-pad: "*"
  });

  it('reports vulnerability scan as NOT_TESTED (offline) — never a false clean', () => {
    const vuln = result.findings.find((f) => f.ruleId === 'SUP-VULN-000');
    expect(vuln?.status).toBe('NOT_TESTED');
    expect(vuln?.evidenceClass).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('produces an SBOM inventorying declared dependencies', () => {
    expect(result.sbom).toBeDefined();
    const names = result.sbom!.components.map((c) => c.name);
    expect(names).toEqual(expect.arrayContaining(['express', 'react', 'left-pad', 'jest']));
    // every component honestly NOT_TESTED for vulnerabilities offline
    expect(result.sbom!.components.every((c) => c.vulnerabilityStatus === 'NOT_TESTED')).toBe(true);
  });
});

describe('exporters (§IX.3)', () => {
  it('SARIF is valid 2.1.0 with rules and results', () => {
    const sarif = JSON.parse(toSarif(result));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('qa-engineering-platform');
    expect(sarif.runs[0].results.length).toBe(result.findings.length);
    // a Critical finding maps to SARIF level "error"
    expect(sarif.runs[0].results.some((r: { level: string }) => r.level === 'error')).toBe(true);
  });

  it('CycloneDX SBOM is well-formed', () => {
    const cdx = JSON.parse(toCycloneDx(result.sbom!, 'scan_supply'));
    expect(cdx.bomFormat).toBe('CycloneDX');
    expect(cdx.specVersion).toBe('1.5');
    expect(cdx.components.length).toBe(result.sbom!.components.length);
    expect(cdx.components[0].purl).toMatch(/^pkg:npm\//);
  });

  it('JUnit XML has failures for FAIL findings', () => {
    const xml = toJUnit(result);
    expect(xml).toMatch(/<testsuites /);
    expect(xml).toContain('<failure');
    const failCount = result.findings.filter((f) => f.status === 'FAIL').length;
    expect(xml).toContain(`failures="${failCount}"`);
  });

  it('CSV has a header and one row per finding, and never leaks a raw secret', () => {
    const csv = toCsv(result);
    const lines = csv.trim().split('\n');
    expect(lines[0]).toContain('id,ruleId,category');
    expect(lines.length).toBe(result.findings.length + 1);
    expect(csv).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(csv).not.toContain('SuperSecretP@ssw0rd123');
  });
});
