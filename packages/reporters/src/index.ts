/**
 * @qa/reporters — export the canonical ScanResult into interchange formats (§IX.3):
 * machine formats for CI & tooling (SARIF/CycloneDX/JUnit/CSV) plus a self-contained,
 * printable HTML report ("Print to PDF" covers the PDF export format).
 */

export * from './sarif.js';
export * from './cyclonedx.js';
export * from './junit.js';
export * from './csv.js';
export * from './html.js';

export type ExportFormat = 'sarif' | 'cyclonedx' | 'junit' | 'csv' | 'html';
