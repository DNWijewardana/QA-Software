/**
 * CSV exporter (§IX.3) — a flat findings table for spreadsheets / quick triage.
 * RFC-4180 style quoting.
 */

import type { ScanResult } from '@qa/core';

function cell(v: string | number | undefined | null): string {
  const s = v === undefined || v === null ? '' : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(result: ScanResult): string {
  const header = [
    'id',
    'ruleId',
    'category',
    'severity',
    'status',
    'confidence',
    'evidenceClass',
    'file',
    'line',
    'cwe',
    'title',
    'remediation',
  ];
  const rows = result.findings.map((f) =>
    [
      f.id,
      f.ruleId,
      f.category,
      f.severity,
      f.status,
      f.confidence,
      f.evidenceClass,
      f.location.file ?? '',
      f.location.line ?? '',
      f.cwe.join('|'),
      f.title,
      f.remediation?.summary ?? '',
    ]
      .map(cell)
      .join(','),
  );
  return [header.join(','), ...rows].join('\n') + '\n';
}
