/**
 * @qa/engines — pluggable analysis engines behind stable interfaces (§VI.2).
 */

export * from './types.js';
export * from './profiler.js';
export * from './secret-scanner.js';
export * from './code-quality.js';
export * from './dependency-scanner.js';

import type { Engine } from './types.js';
import { SecretScanner } from './secret-scanner.js';
import { CodeQualityAnalyzer } from './code-quality.js';
import { DependencyScanner } from './dependency-scanner.js';

/** The engines available in the SAFE_STATIC scan. Extended per roadmap Phase 2+. */
export function defaultStaticEngines(): Engine[] {
  return [new SecretScanner(), new CodeQualityAnalyzer(), new DependencyScanner()];
}
