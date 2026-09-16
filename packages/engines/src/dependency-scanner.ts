/**
 * DependencyAnalyzer — supply-chain inventory + SBOM generation (SupplyChainHealth dimension).
 * Spec ref: §V.17 (dependency/supply-chain security), §IX.1 Supply-Chain Report, §IV.2 (CycloneDX/SPDX).
 *
 * HONESTY (§V.17 "classify: ... unavailable evidence"): this engine runs fully offline. It builds a
 * dependency inventory + SBOM and flags CONFIG-level supply-chain smells it can prove statically
 * (missing lockfile, unpinned/wildcard versions). It does NOT have a CVE/OSV database, so per-package
 * vulnerability status is honestly NOT_TESTED — never a false "no known vulnerabilities".
 */

import type { Finding, Sbom, SbomComponent } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const UNPINNED = /^(\*|latest|x|\d+\.x|\d+\.\d+\.x)$/i;

interface PkgJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export class DependencyScanner implements Engine {
  readonly name = 'dependency-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'SupplyChainHealth' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some((f) => f.path === 'package.json');
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const pkgFile = ctx.files.find((f) => f.path === 'package.json');

    if (!pkgFile) {
      return this.degraded('No package.json found for the JS/TS ecosystem.');
    }

    let pkg: PkgJson;
    try {
      pkg = JSON.parse(await ctx.readText(pkgFile)) as PkgJson;
    } catch {
      return this.degraded('package.json present but could not be parsed.');
    }

    const hasLockfile = ctx.files.some((f) =>
      ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'npm-shrinkwrap.json'].includes(f.path),
    );

    const runtime = pkg.dependencies ?? {};
    const dev = pkg.devDependencies ?? {};
    const components: SbomComponent[] = [];
    let ordinal = 1;

    const addComponent = (name: string, range: string, scope: 'required' | 'optional'): void => {
      const version = range.replace(/^[\^~>=<\s]+/, '').trim() || range;
      components.push({
        name,
        version,
        type: 'library',
        purl: `pkg:npm/${name}@${version}`,
        scope,
        // Offline: we cannot check a vuln DB. Be honest (§V.17).
        vulnerabilityStatus: 'NOT_TESTED',
      });
    };

    for (const [name, range] of Object.entries(runtime)) addComponent(name, range, 'required');
    for (const [name, range] of Object.entries(dev)) addComponent(name, range, 'optional');

    let executedChecks = 0;

    // CHECK 1: lockfile integrity (§V.17 lockfile integrity).
    executedChecks++;
    if (!hasLockfile && components.length > 0) {
      const art = this.artifact(artifacts, `${pkgFile.path}:nolock`, `No lockfile alongside package.json (${components.length} declared dependencies).`);
      findings.push(
        this.mk(findingId('SUP-LOCK-001', ordinal++), 'SUP-LOCK-001', 'Missing dependency lockfile', 'Medium', {
          file: 'package.json',
        }, 'No lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) was found. Without a lockfile, installs are not reproducible and transitive dependencies are not integrity-pinned, widening the supply-chain attack surface.', art, 'Commit a lockfile and enable `npm ci` / frozen-lockfile installs in CI.', ['CWE-1104'], 'AUTOMATICALLY_DETECTED'),
      );
    }

    // CHECK 2: unpinned / wildcard version ranges (§V.17 version mismatch / dependency-confusion surface).
    executedChecks++;
    for (const [name, range] of [...Object.entries(runtime), ...Object.entries(dev)]) {
      if (UNPINNED.test(range.trim())) {
        const art = this.artifact(artifacts, `${pkgFile.path}:${name}:unpinned`, `Dependency "${name}" uses unpinned range "${range}".`);
        findings.push(
          this.mk(findingId('SUP-PIN-001', ordinal++), 'SUP-PIN-001', `Unpinned dependency version: ${name}`, 'Medium', {
            file: 'package.json',
          }, `Dependency \`${name}\` uses the unpinned range \`${range}\`. Wildcard/floating ranges can pull in unreviewed or malicious versions on the next install.`, art, `Pin \`${name}\` to a specific version (or a caret range on a reviewed baseline) and rely on a lockfile.`, ['CWE-1357'], 'AUTOMATICALLY_DETECTED'),
        );
      }
    }

    // CHECK 3: vulnerability scan — explicitly NOT performed offline (honest NOT_TESTED, not a pass).
    executedChecks++;
    findings.push(
      this.mk(findingId('SUP-VULN-000', ordinal++), 'SUP-VULN-000', 'Dependency vulnerability scan not performed (offline)', 'Informational', {
        file: 'package.json',
      }, `A vulnerability database (CVE/OSV/KEV) was not available in this environment, so the ${components.length} components were NOT checked for known vulnerabilities. This is reported as NOT_TESTED, not as "no vulnerabilities".`, undefined, 'Run this scan with OSV/registry access, or integrate an offline advisory mirror, to obtain CVE/EPSS/KEV results.', [], 'INSUFFICIENT_EVIDENCE', 'NOT_TESTED'),
    );

    // Persist the SBOM component inventory as evidence.
    const sbom: Sbom = {
      format: 'CycloneDX',
      specVersion: '1.5',
      generatedAt: new Date().toISOString(),
      components,
      source: hasLockfile ? 'lockfile' : 'manifest',
      notes: hasLockfile
        ? ['Component versions derived from package.json declared ranges; lockfile present but not fully resolved in this build.']
        : ['No lockfile; component versions are the declared ranges (not resolved installs).'],
    };
    this.artifact(artifacts, `${pkgFile.path}:sbom`, JSON.stringify({ components: components.length, source: sbom.source }));

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: 3,
      executedChecks,
      findings,
      artifacts,
      sbom,
    };
  }

  private degraded(reason: string): EngineResult {
    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: 3,
      executedChecks: 0,
      findings: [],
      artifacts: [],
      degraded: true,
      degradedReason: reason,
    };
  }

  private artifact(sink: EngineArtifact[], key: string, content: string): string {
    const id = `ev-${sha256(key).slice(0, 16)}`;
    sink.push({ id, type: 'dependency-record', content, contentHash: sha256(content), redactedClasses: {} });
    return id;
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    location: Finding['location'],
    description: string,
    artifactId: string | undefined,
    remediation: string,
    cwe: string[],
    evidenceClass: Finding['evidenceClass'],
    status: Finding['status'] = 'FAIL',
  ): Finding {
    return {
      id,
      ruleId,
      category: 'SupplyChain',
      subcategory: 'Dependencies',
      title,
      description,
      status,
      evidenceClass,
      severity,
      risk: severity,
      confidence: evidenceClass === 'AUTOMATICALLY_DETECTED' ? 'Highly likely' : 'Needs human verification',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'dependency',
      toolUsed: `${this.name}@${this.version}`,
      evidence: artifactId ? [{ type: 'dependency-record', ref: artifactId, redacted: false }] : [],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'Informational' ? 'Low' : 'Medium' },
      verificationMethod: 'Re-run the dependency scan after remediation.',
      standards: [
        { framework: 'OWASP Top 10', version: '2025', id: 'A06-Vulnerable-and-Outdated-Components' },
        { framework: 'CycloneDX', version: '1.5', id: 'SBOM' },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
