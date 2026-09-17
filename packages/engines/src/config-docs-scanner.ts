/**
 * ConfigDocsScanner — configuration & documentation hygiene (Maintainability dimension).
 * Spec ref: §V.29 (configuration quality: env files, missing config; documentation quality: README, setup).
 *
 * Deterministic (§0.2.2): project-level presence/content checks. Findings are low-severity hygiene signals
 * (never score-distorting), matching the spec's guidance that these tie to maintainability, not correctness.
 */

import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CODE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const ENV_USAGE = /\bprocess\.env\.\w+|\bimport\.meta\.env\.\w+/;

function base(f: ProjectFile): string {
  return (f.path.split('/').pop() ?? '').toLowerCase();
}

export class ConfigDocsScanner implements Engine {
  readonly name = 'config-docs-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Maintainability' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.length > 0;
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], loc: Finding['location'], desc: string, evidence: string, fix: string) => {
      const art = addArtifact(`${rule}:${loc.file ?? 'project'}:${ordinal}`, evidence);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, loc, desc, art, fix));
    };

    const files = ctx.files;
    const hasReadme = files.some((f) => /^readme(\.[\w-]+)?$/i.test(base(f)));
    const hasLicense = files.some((f) => /^licen[sc]e(\.[\w-]+)?$/i.test(base(f)));
    const envExample = files.some((f) => /^\.env\.(example|sample|template|dist)$/i.test(base(f)));
    const envFiles = files.filter((f) => {
      const b = base(f);
      return b === '.env' || /^\.env\.(local|production|development|prod|dev)$/i.test(b);
    });

    if (!hasReadme) {
      emit('DOC-README-001', 'No README found', 'Informational', {},
        'The project has no README. Onboarding, setup, and usage are undocumented, hurting maintainability and DevEx.',
        'No README file found in the project root.', 'Add a README with setup, run, and contribution instructions.');
    }
    if (!hasLicense) {
      emit('DOC-LICENSE-001', 'No LICENSE found', 'Informational', {},
        'The project has no LICENSE file, leaving usage/redistribution terms undefined.',
        'No LICENSE file found in the project.', 'Add a LICENSE file that states the terms of use.');
    }
    for (const env of envFiles) {
      emit('CFG-ENV-COMMITTED-001', `Environment file present in the project: ${env.path}`, 'Medium', { file: env.path },
        `\`${env.path}\` is an environment file inside the project. If committed it can leak real secrets and configuration; env files should be gitignored and provided via a safe \`.env.example\`.`,
        `File: ${env.path}`, 'Ensure the env file is gitignored, rotate anything it contained, and commit a placeholder-only .env.example instead.');
    }

    // Undocumented required configuration: code reads env vars but there is no committed example.
    let usesEnv = false;
    if (!envExample) {
      for (const f of files.filter((x) => CODE_EXT.test(x.path) && !/\.(test|spec)\./.test(x.path))) {
        try {
          if (ENV_USAGE.test(await ctx.readText(f))) {
            usesEnv = true;
            break;
          }
        } catch {
          /* skip unreadable */
        }
      }
      if (usesEnv) {
        emit('CFG-NO-ENV-EXAMPLE-001', 'Environment variables used but not documented', 'Low', {},
          'The code reads environment variables, but there is no `.env.example` documenting the required configuration, so setup is error-prone.',
          'process.env / import.meta.env used; no .env.example present.', 'Add a `.env.example` listing every required variable with safe placeholder values.');
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: 4,
      executedChecks: 4,
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
      category: 'Maintainability',
      subcategory: 'Config/Docs',
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
      affectedComponent: location.file ?? 'project',
      location,
      detectionMethod: 'config',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: false }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'Medium' ? 'Medium' : 'Low' },
      verificationMethod: 'Re-scan after adding the missing file/documentation.',
      standards: [{ framework: 'ISO/IEC 25010', version: '2023', id: 'Maintainability' }],
      traceability: { requirements: [], tests: [] },
    };
  }
}
