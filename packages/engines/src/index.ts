/**
 * @qa/engines — pluggable analysis engines behind stable interfaces (§VI.2).
 */

export * from './types.js';
export * from './profiler.js';
export * from './secret-scanner.js';
export * from './code-quality.js';
export * from './dependency-scanner.js';
export * from './dockerfile-scanner.js';
export * from './kubernetes-scanner.js';
export * from './compose-scanner.js';
export * from './openapi-scanner.js';
export * from './html-a11y-scanner.js';
export * from './performance-scanner.js';
export * from './seo-scanner.js';
export * from './logging-scanner.js';

import type { Engine } from './types.js';
import { SecretScanner } from './secret-scanner.js';
import { CodeQualityAnalyzer } from './code-quality.js';
import { DependencyScanner } from './dependency-scanner.js';
import { DockerfileScanner } from './dockerfile-scanner.js';
import { KubernetesScanner } from './kubernetes-scanner.js';
import { ComposeScanner } from './compose-scanner.js';
import { OpenApiScanner } from './openapi-scanner.js';
import { HtmlAccessibilityScanner } from './html-a11y-scanner.js';
import { PerformanceScanner } from './performance-scanner.js';
import { LoggingScanner } from './logging-scanner.js';

/** The engines available in the SAFE_STATIC scan. Extended per roadmap Phase 2+. */
export function defaultStaticEngines(): Engine[] {
  return [
    new SecretScanner(),
    new CodeQualityAnalyzer(),
    new DependencyScanner(),
    new DockerfileScanner(),
    new KubernetesScanner(),
    new ComposeScanner(),
    new OpenApiScanner(),
    new HtmlAccessibilityScanner(),
    new PerformanceScanner(),
    new LoggingScanner(),
  ];
}
