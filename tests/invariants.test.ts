import { describe, it, expect } from 'vitest';
import {
  checkCriticalVisibility,
  checkFindingInvariants,
  checkScoreInvariants,
  transitionStatus,
  type DimensionScore,
  type Finding,
} from '@qa/core';

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'X-001-0001',
    ruleId: 'X-001',
    category: 'Security',
    title: 't',
    description: 'd',
    status: 'FAIL',
    evidenceClass: 'AUTOMATICALLY_DETECTED',
    severity: 'High',
    risk: 'High',
    confidence: 'Highly likely',
    reproducibility: 'Always',
    cwe: [],
    cve: [],
    location: { file: 'a.ts' },
    detectionMethod: 'static',
    evidence: [{ type: 'source-code', ref: 'ev1', redacted: true }],
    standards: [],
    traceability: { requirements: [], tests: [] },
    ...overrides,
  };
}

describe('Tier-1 integrity invariants (§I.4, §VII.2)', () => {
  it('NOT_TESTED can never transition to PASS (§I.4)', () => {
    expect(() => transitionStatus('NOT_TESTED', 'PASS')).toThrow(/cannot transition to 'PASS'/);
    // legal transitions still work
    expect(transitionStatus('NOT_TESTED', 'FAIL')).toBe('FAIL');
    expect(transitionStatus('WARNING', 'PASS')).toBe('PASS');
  });

  it('PASS requires a verified evidence class', () => {
    const bad = baseFinding({ status: 'PASS', evidenceClass: 'SUSPECTED' });
    const v = checkFindingInvariants(bad);
    expect(v.map((x) => x.code)).toContain('PASS_WITHOUT_VERIFICATION');
  });

  it('NOT_TESTED must not use a verified evidence class', () => {
    const bad = baseFinding({ status: 'NOT_TESTED', evidenceClass: 'AUTOMATICALLY_VERIFIED' });
    const v = checkFindingInvariants(bad);
    expect(v.map((x) => x.code)).toContain('NOT_TESTED_DISHONEST_CLASS');
  });

  it("a 'Confirmed' finding must carry evidence", () => {
    const bad = baseFinding({ confidence: 'Confirmed', evidence: [] });
    const v = checkFindingInvariants(bad);
    expect(v.map((x) => x.code)).toContain('CONFIRMED_WITHOUT_EVIDENCE');
  });

  it('a clean finding produces no violations', () => {
    expect(checkFindingInvariants(baseFinding())).toEqual([]);
  });
});

describe('anti score-gaming invariants (§VII.8)', () => {
  const score = (o: Partial<DimensionScore> = {}): DimensionScore => ({
    dimension: 'Security',
    score: 90,
    confidence: 'Likely',
    coverage: 0.8,
    weight: 0.2,
    why: ['because'],
    unknowns: [],
    ...o,
  });

  it('a score must explain itself (non-empty why)', () => {
    expect(checkScoreInvariants(score({ why: [] })).map((x) => x.code)).toContain('SCORE_WITHOUT_WHY');
  });

  it('low coverage cannot present as high-confidence green', () => {
    const v = checkScoreInvariants(score({ coverage: 0.1, confidence: 'Highly likely' }));
    expect(v.map((x) => x.code)).toContain('GREEN_WITH_LOW_COVERAGE');
  });

  it('an aggregate cannot hide a Critical finding', () => {
    const findings = [baseFinding({ severity: 'Critical', status: 'FAIL' })];
    // Overall claims 0 critical blockers while a Critical FAIL exists → violation.
    const v = checkCriticalVisibility(findings, 0);
    expect(v.map((x) => x.code)).toContain('CRITICAL_HIDDEN_BY_AGGREGATE');
    // Correctly surfaced → no violation.
    expect(checkCriticalVisibility(findings, 1)).toEqual([]);
  });
});
