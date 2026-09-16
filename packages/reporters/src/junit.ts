/**
 * JUnit XML exporter (§IX.3 — JUnit XML for CI test-result surfacing).
 * Each finding becomes a testcase; FAIL findings become <failure>, NOT_TESTED become <skipped>.
 * This lets CI systems display QA findings alongside normal test results.
 */

import type { ScanResult } from '@qa/core';
import { xmlEscape } from './xml.js';

export function toJUnit(result: ScanResult): string {
  const findings = result.findings;
  const failures = findings.filter((f) => f.status === 'FAIL').length;
  const skipped = findings.filter((f) => f.status === 'NOT_TESTED' || f.status === 'BLOCKED').length;

  const cases = findings
    .map((f) => {
      const name = xmlEscape(`${f.id} ${f.title}`);
      const classname = xmlEscape(`${f.category}.${f.ruleId}`);
      const loc = f.location.file
        ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
        : f.location.endpoint ?? f.location.url ?? '';
      if (f.status === 'FAIL') {
        return (
          `    <testcase classname="${classname}" name="${name}">\n` +
          `      <failure type="${xmlEscape(f.severity)}" message="${xmlEscape(f.title)}">` +
          `${xmlEscape(`${f.description}\nLocation: ${loc}\nFix: ${f.remediation?.summary ?? 'n/a'}`)}` +
          `</failure>\n    </testcase>`
        );
      }
      if (f.status === 'NOT_TESTED' || f.status === 'BLOCKED') {
        return (
          `    <testcase classname="${classname}" name="${name}">\n` +
          `      <skipped message="${xmlEscape(f.status)}"/>\n    </testcase>`
        );
      }
      return `    <testcase classname="${classname}" name="${name}"/>`;
    })
    .join('\n');

  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<testsuites name="qa-engineering-platform" tests="${findings.length}" failures="${failures}" skipped="${skipped}">\n` +
    `  <testsuite name="quality-findings" tests="${findings.length}" failures="${failures}" skipped="${skipped}" timestamp="${xmlEscape(result.scan.startedAt)}">\n` +
    `${cases}\n` +
    `  </testsuite>\n` +
    `</testsuites>\n`
  );
}
