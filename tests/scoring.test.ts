import { describe, it, expect } from 'vitest';
import {
  computeDimensionScore,
  computeOverall,
  decideRelease,
  type Finding,
} from '@qa/core';

function f(severity: Finding['severity'], status: Finding['status'] = 'FAIL'): Finding {
  return {
    id: `X-${severity}-${Math.random()}`,
    ruleId: 'X',
    category: 'Security',
    title: 't',
    description: 'd',
    status,
    evidenceClass: 'AUTOMATICALLY_DETECTED',
    severity,
    risk: severity,
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

describe('ScoreEngine (§VII.6)', () => {
  it('deducts by severity and always explains why', () => {
    const s = computeDimensionScore({
      dimension: 'Security',
      findings: [f('High'), f('Low')],
      applicableChecks: 10,
      executedChecks: 8,
    });
    expect(s.score).toBe(100 - 20 - 3);
    expect(s.why.length).toBeGreaterThan(0);
    expect(s.coverage).toBeCloseTo(0.8);
  });

  it('a clean dimension scores 100 and says so', () => {
    const s = computeDimensionScore({ dimension: 'Maintainability', findings: [], applicableChecks: 5, executedChecks: 5 });
    expect(s.score).toBe(100);
    expect(s.why.join(' ')).toMatch(/No active/i);
  });
});

describe('overall + release decision (§VII.9)', () => {
  it('a Critical finding forces NO_GO regardless of score', () => {
    const findings = [f('Critical')];
    const scores = [
      computeDimensionScore({ dimension: 'Security', findings, applicableChecks: 10, executedChecks: 9 }),
    ];
    const overall = computeOverall(scores, findings);
    expect(overall.criticalBlockers).toBe(1);
    const decision = decideRelease(overall, findings);
    expect(decision.decision).toBe('NO_GO');
  });

  it('insufficient coverage yields INSUFFICIENT_EVIDENCE, not a fake number', () => {
    const findings: Finding[] = [];
    const scores = [
      computeDimensionScore({ dimension: 'Security', findings, applicableChecks: 100, executedChecks: 1 }),
    ];
    const overall = computeOverall(scores, findings);
    expect(overall.score).toBeNull();
    expect(decideRelease(overall, findings).decision).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('clean + covered project can GO', () => {
    const findings: Finding[] = [];
    const scores = [
      computeDimensionScore({ dimension: 'Security', findings, applicableChecks: 10, executedChecks: 10 }),
    ];
    const overall = computeOverall(scores, findings);
    expect(decideRelease(overall, findings).decision).toBe('GO');
  });
});
