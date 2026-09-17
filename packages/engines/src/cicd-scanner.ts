/**
 * CicdScanner — CI/CD pipeline security checks for GitHub Actions workflows (Security dimension).
 * Spec ref: §V.19 (CI/CD quality — pipeline-as-code security: poisoned-pipeline-execution, unpinned actions).
 *
 * Deterministic (§0.2.2): parses `.github/workflows/*.yml`. Flags unpinned actions, script injection from
 * untrusted event data, `pull_request_target`, secrets echoed in run steps, and missing least-privilege
 * permissions. Only workflow files under `.github/workflows/` are analysed.
 */

import { parseDocument } from 'yaml';
import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 5;
const WORKFLOW = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const DANGEROUS_CONTEXT =
  /\$\{\{[^}]*\b(github\.head_ref|github\.event\.[\w.]*(?:title|body|message|name|ref|label|author|email|url))/i;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const rec = (v: unknown): Record<string, unknown> => (isRecord(v) ? v : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function isWorkflow(f: ProjectFile): boolean {
  return WORKFLOW.test(f.path);
}

function hasTrigger(on: unknown, name: string): boolean {
  if (typeof on === 'string') return on === name;
  if (Array.isArray(on)) return on.some((x) => str(x) === name);
  if (isRecord(on)) return name in on;
  return false;
}

/** Classify a `uses:` reference by how it is pinned. */
function classifyUses(uses: string): 'sha' | 'branch' | 'tag' | 'none' | 'skip' {
  if (uses.startsWith('./') || uses.startsWith('docker://')) return 'skip';
  const at = uses.lastIndexOf('@');
  if (at === -1) return 'none';
  const ref = uses.slice(at + 1);
  if (/^[0-9a-f]{40}$/i.test(ref)) return 'sha';
  if (/^(main|master|head|develop|latest)$/i.test(ref)) return 'branch';
  return 'tag';
}

export class CicdScanner implements Engine {
  readonly name = 'cicd-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Security' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isWorkflow);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const workflows = ctx.files.filter(isWorkflow);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const emit = (rule: string, title: string, sev: Finding['severity'], status: Finding['status'], file: string, desc: string, evidence: string, fix: string, cwe: string[], owasp: string) => {
      const art = addArtifact(`${file}:${rule}:${ordinal}`, `File: ${file}\n${evidence}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, title, sev, status, { file }, desc, art, fix, cwe, owasp));
    };

    for (const file of workflows) {
      let doc: Record<string, unknown>;
      try {
        doc = rec(parseDocument(await ctx.readText(file)).toJS({ maxAliasCount: 100 }));
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;
      // YAML parses the `on:` key as boolean true in some cases; read both.
      const on = doc.on ?? (doc as Record<string, unknown>)['true'];

      // 1) pull_request_target trigger
      if (hasTrigger(on, 'pull_request_target')) {
        emit('CI-PR-TARGET-001', 'Workflow triggered by pull_request_target', 'Medium', 'FAIL', file.path,
          '`pull_request_target` runs with repository write permissions and secrets in the context of the base repo. Combined with checking out untrusted PR code it enables privilege escalation.',
          'on: pull_request_target', 'Prefer `pull_request`; if `pull_request_target` is required, never check out or execute PR-controlled code with it.', ['CWE-269'], 'Poisoned Pipeline Execution');
      }

      // 5) missing least-privilege permissions
      if (!('permissions' in doc)) {
        emit('CI-PERMISSIONS-000', 'No least-privilege permissions set', 'Informational', 'WARNING', file.path,
          'The workflow sets no top-level `permissions`, so the GITHUB_TOKEN may default to broad write access.',
          'workflow has no permissions: block', 'Add a least-privilege `permissions:` block (start from `contents: read`).', [], 'Least privilege');
      }

      const jobs = rec(doc.jobs);
      for (const [jobId, jobUnknown] of Object.entries(jobs)) {
        for (const stepUnknown of arr(rec(jobUnknown).steps)) {
          const step = rec(stepUnknown);
          const where = `job ${jobId}`;

          // 2) unpinned actions
          const uses = str(step.uses);
          if (uses) {
            const cls = classifyUses(uses);
            if (cls === 'none' || cls === 'branch') {
              emit('CI-ACTION-UNPINNED-001', `Action pinned to a mutable ref: ${uses}`, 'Medium', 'FAIL', file.path,
                `${where} uses \`${uses}\`, referenced by ${cls === 'none' ? 'no version' : 'a branch'}. A mutable ref can be repointed to malicious code between runs.`,
                `uses: ${uses}`, 'Pin the action to a full commit SHA (e.g. `owner/repo@<40-char-sha>`).', ['CWE-1357'], 'Supply chain');
            } else if (cls === 'tag') {
              emit('CI-ACTION-TAG-001', `Action pinned to a tag, not a SHA: ${uses}`, 'Informational', 'WARNING', file.path,
                `${where} uses \`${uses}\`. Tags are mutable; for supply-chain integrity pin to a commit SHA.`,
                `uses: ${uses}`, 'Pin to a full commit SHA and use Dependabot to bump it.', [], 'Supply chain');
            }
          }

          // 3) script injection from untrusted event data, 4) secret echoed
          const run = str(step.run);
          if (run) {
            if (DANGEROUS_CONTEXT.test(run)) {
              emit('CI-SCRIPT-INJECTION-001', 'Script injection from untrusted workflow context', 'High', 'FAIL', file.path,
                `${where} interpolates attacker-controllable event data (e.g. a PR/issue title) directly into a shell command. An attacker can inject shell commands that run with the workflow's token (CWE-94).`,
                redactedSnippet(run.split('\n').find((l) => DANGEROUS_CONTEXT.test(l)) ?? run), 'Pass the value via an `env:` variable and reference "$VAR" in the script; never inline `${{ github.event... }}`.', ['CWE-94'], 'Script Injection');
            }
            if (/echo\b[^\n]*\$\{\{\s*secrets\./i.test(run)) {
              emit('CI-SECRET-ECHO-001', 'Secret echoed in a run step', 'Medium', 'FAIL', file.path,
                `${where} echoes a secret in a run step, risking exposure in build logs (CWE-532).`,
                redactedSnippet(run.split('\n').find((l) => /echo\b[^\n]*\$\{\{\s*secrets\./i.test(l)) ?? run), 'Never echo secrets; pass them via env and avoid printing them.', ['CWE-532'], 'Secret exposure');
            }
          }
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(workflows.length * CHECK_CATEGORIES, 1),
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
    status: Finding['status'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    remediation: string,
    cwe: string[],
    owasp: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CICD',
      subcategory: 'GitHub Actions',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Highly likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'config',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: true }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-scan the workflow after hardening.',
      standards: [
        { framework: 'CI/CD Security', version: 'n/a', id: owasp },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
