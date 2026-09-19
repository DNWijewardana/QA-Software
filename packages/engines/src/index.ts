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
export * from './error-handling-scanner.js';
export * from './privacy-scanner.js';
export * from './cicd-scanner.js';
export * from './sql-migration-scanner.js';
export * from './config-docs-scanner.js';
export * from './terraform-scanner.js';
export * from './cloudformation-scanner.js';
export * from './license-scanner.js';
export * from './python-scanner.js';
export * from './go-scanner.js';
export * from './java-scanner.js';
export * from './php-scanner.js';

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
import { ErrorHandlingScanner } from './error-handling-scanner.js';
import { PrivacyScanner } from './privacy-scanner.js';
import { CicdScanner } from './cicd-scanner.js';
import { SqlMigrationScanner } from './sql-migration-scanner.js';
import { ConfigDocsScanner } from './config-docs-scanner.js';
import { TerraformScanner } from './terraform-scanner.js';
import { CloudFormationScanner } from './cloudformation-scanner.js';
import { LicenseScanner } from './license-scanner.js';
import { PythonScanner } from './python-scanner.js';
import { GoScanner } from './go-scanner.js';
import { JavaScanner } from './java-scanner.js';
import { PhpScanner } from './php-scanner.js';

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
    new ErrorHandlingScanner(),
    new PrivacyScanner(),
    new CicdScanner(),
    new SqlMigrationScanner(),
    new ConfigDocsScanner(),
    new TerraformScanner(),
    new CloudFormationScanner(),
    new LicenseScanner(),
    new PythonScanner(),
    new GoScanner(),
    new JavaScanner(),
    new PhpScanner(),
  ];
}
