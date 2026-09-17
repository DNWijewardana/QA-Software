/**
 * LicenseScanner — license/legal technical checks (SupplyChainHealth dimension).
 * Spec ref: §V.30 (license/legal technical checks — "Report technical evidence only; do not provide legal
 * advice"), §V.17 (license risks as supply-chain governance).
 *
 * Deterministic (§0.2.2): inspects declared license metadata in package.json files. It reports FACTS (no
 * license field, a non-SPDX identifier, an UNLICENSED-but-publishable package, a declared strong-copyleft
 * license) and never draws legal conclusions or claims license compatibility.
 */

import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 3;
const SPDX = new Set([
  'MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'Unlicense', 'CC0-1.0', 'MPL-2.0',
  'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0-only', 'AGPL-3.0-or-later', 'EPL-2.0', 'EUPL-1.2', 'Artistic-2.0', 'Zlib', 'BSL-1.0', 'WTFPL',
]);
const COPYLEFT = /\b(A?GPL-[23]\.0)/i;

function isPackageJson(f: ProjectFile): boolean {
  return (f.path.split('/').pop() ?? '') === 'package.json';
}

export class LicenseScanner implements Engine {
  readonly name = 'license-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'SupplyChainHealth' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isPackageJson);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const pkgs = ctx.files.filter(isPackageJson);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'dependency-record', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], file: string, desc: string, evidence: string, fix: string) => {
      const art = addArtifact(`${file}:${rule}`, `File: ${file}\n${evidence}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, { file }, desc, art, fix));
    };

    for (const file of pkgs) {
      let pkg: Record<string, unknown>;
      try {
        pkg = JSON.parse(await ctx.readText(file)) as Record<string, unknown>;
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      const license = pkg.license;
      const isPrivate = pkg.private === true;

      if (license === undefined && pkg.licenses === undefined) {
        emit('LIC-MISSING-001', 'No license declared in package.json', 'Informational', file.path,
          'The package declares no `license` field, so its usage/redistribution terms are undefined for consumers and tooling.',
          'package.json has no license field.', 'Add an SPDX `license` (e.g. "MIT"), or "UNLICENSED" with `"private": true` for proprietary code.');
        continue;
      }

      // Deprecated object / array forms.
      if (typeof license === 'object' || Array.isArray(pkg.licenses)) {
        emit('LIC-NONSTANDARD-001', 'Deprecated license format', 'Low', file.path,
          'The package uses the deprecated license object/array form. Modern tooling expects a single SPDX identifier string.',
          'Deprecated `license` object or `licenses` array.', 'Replace with a single SPDX expression string in the `license` field.');
        continue;
      }

      if (typeof license === 'string') {
        if (license === 'UNLICENSED') {
          if (!isPrivate) {
            emit('LIC-UNLICENSED-NOT-PRIVATE-001', 'UNLICENSED package is not marked private', 'Low', file.path,
              'The package declares `license: "UNLICENSED"` (proprietary) but is not `"private": true`, so it could be accidentally published to a registry.',
              'license = "UNLICENSED"; private is not true.', 'Set `"private": true` to prevent accidental publication.');
          }
          continue;
        }
        if (/^SEE LICENSE/i.test(license)) continue; // points to a LICENSE file — acceptable
        const isExpression = /[()]| OR | AND | WITH /i.test(license);
        if (COPYLEFT.test(license)) {
          emit('LIC-COPYLEFT-DECLARED-001', `Project declares a strong-copyleft license: ${license}`, 'Informational', file.path,
            'The project declares a strong-copyleft (GPL/AGPL) license. This is a factual note for awareness of your distribution obligations — not legal advice.',
            `license = "${license}"`, 'Confirm this license matches your distribution model; document third-party obligations.');
        } else if (!isExpression && !SPDX.has(license)) {
          emit('LIC-NONSTANDARD-001', `Non-standard license identifier: ${license}`, 'Informational', file.path,
            `The license "${license}" is not a recognised SPDX identifier, so automated license tooling may not interpret it correctly.`,
            `license = "${license}"`, 'Use a valid SPDX identifier (see https://spdx.org/licenses/), or "SEE LICENSE IN <file>".');
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(pkgs.length * CHECK_CATEGORIES, 1),
      executedChecks: executed,
      findings,
      artifacts,
    };
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    remediation: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'License',
      subcategory: 'Declared license',
      title,
      description,
      status: severity === 'Informational' ? 'WARNING' : 'FAIL',
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Highly likely',
      reproducibility: 'Always',
      cwe: [],
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'dependency',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'dependency-record', ref: artifactId, redacted: false }],
      remediation: { summary: remediation, effort: 'S', riskReduction: 'Low' },
      verificationMethod: 'Re-scan after correcting the license metadata.',
      standards: [{ framework: 'SPDX', version: 'n/a', id: 'license-identifiers' }],
      traceability: { requirements: [], tests: [] },
    };
  }
}
