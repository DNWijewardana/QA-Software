/**
 * @qa/reporters — export the canonical ScanResult into interchange formats (§IX.3).
 * PDF/HTML are rendered by the web/report tier; these are the machine formats for CI & tooling.
 */

export * from './sarif.js';
export * from './cyclonedx.js';
export * from './junit.js';
export * from './csv.js';

export type ExportFormat = 'sarif' | 'cyclonedx' | 'junit' | 'csv';
