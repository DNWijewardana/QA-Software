/**
 * ComplianceMapper — maps platform findings to a control-coverage matrix (§IV.3, §IX.1 Compliance Report).
 *
 * HONESTY (§I.5, §IV.3): this reports *technical evidence relevant to a control*, NOT *compliance with a
 * regulation* — the latter requires human/legal sign-off. Nothing here is a certification. A control is only
 * marked assessed when the automated check that provides its evidence actually ran; otherwise NOT_ASSESSED
 * (never silently "satisfied"). `SATISFIED` means "the automated check ran and found no violation", not "compliant".
 */

import { checkScoreInvariants } from './invariants.js';
import { coverageToConfidence } from './scoring.js';
import type { DimensionScore, Finding } from './types.js';

export type ControlStatus = 'SATISFIED' | 'GAPS' | 'NOT_ASSESSED';

export interface ControlMapping {
  framework: string;
  controlId: string;
  title: string;
  status: ControlStatus;
  /** rule IDs whose findings provide evidence for this control. */
  mappedRules: string[];
  /** finding IDs that represent gaps (violations) for this control. */
  gapFindings: string[];
  note: string;
}

export interface ComplianceMatrix {
  disclaimer: string;
  frameworks: string[];
  controls: ControlMapping[];
  summary: { total: number; assessed: number; satisfied: number; gaps: number; notAssessed: number };
}

interface CatalogControl {
  framework: string;
  controlId: string;
  title: string;
  /** rule IDs that, if violated, indicate a gap in this control. */
  rules: string[];
  /** the engine that must have run for this control to be considered assessed. */
  providedByEngine: string;
}

/**
 * Curated control catalog. Deliberately small and honest — each control is backed by a real, deterministic
 * platform check. SOC 2 entries are "controls inspired by" the Trust Services Criteria, not a SOC 2 audit.
 */
export const CONTROL_CATALOG: CatalogControl[] = [
  // --- Secrets management ---
  { framework: 'SOC 2 (illustrative)', controlId: 'CC6.1', title: 'Secrets are not hardcoded in source', rules: ['SEC-SECRET-001'], providedByEngine: 'secret-scanner' },
  { framework: 'OWASP Top 10 2025', controlId: 'A05', title: 'Security misconfiguration — no hardcoded secrets', rules: ['SEC-SECRET-001'], providedByEngine: 'secret-scanner' },
  // --- Supply chain / vulnerable components ---
  { framework: 'SOC 2 (illustrative)', controlId: 'CC7.1', title: 'Dependency hygiene (lockfile, pinned versions)', rules: ['SUP-LOCK-001', 'SUP-PIN-001'], providedByEngine: 'dependency-scanner' },
  { framework: 'OWASP Top 10 2025', controlId: 'A06', title: 'Vulnerable & outdated components', rules: ['SUP-LOCK-001', 'SUP-PIN-001'], providedByEngine: 'dependency-scanner' },
  // --- API authentication (OWASP API Security Top 10) ---
  { framework: 'OWASP API Security Top 10 2023', controlId: 'API2', title: 'API endpoints require authentication', rules: ['API-SPEC-NOAUTH-001', 'API-SPEC-OP-NOAUTH-001'], providedByEngine: 'openapi-scanner' },
  // --- Container image (CIS Docker) ---
  { framework: 'CIS Docker Benchmark', controlId: '4.1', title: 'Container runs as a non-root user', rules: ['IAC-DOCKER-USER-001'], providedByEngine: 'dockerfile-scanner' },
  { framework: 'CIS Docker Benchmark', controlId: '4.6', title: 'Image defines a HEALTHCHECK', rules: ['IAC-DOCKER-HEALTHCHECK-000'], providedByEngine: 'dockerfile-scanner' },
  { framework: 'CIS Docker Benchmark', controlId: '4.10', title: 'No secrets baked into the image', rules: ['IAC-DOCKER-SECRET-001'], providedByEngine: 'dockerfile-scanner' },
  { framework: 'CIS Docker Benchmark', controlId: '5.31', title: 'Docker socket not mounted into containers', rules: ['IAC-COMPOSE-DOCKERSOCK-001'], providedByEngine: 'compose-scanner' },
  // --- Kubernetes workloads (CIS K8s / Pod Security Standards) ---
  { framework: 'CIS Kubernetes Benchmark', controlId: '5.2.1', title: 'No privileged containers', rules: ['IAC-K8S-PRIV-001'], providedByEngine: 'kubernetes-scanner' },
  { framework: 'CIS Kubernetes Benchmark', controlId: '5.2.6', title: 'Containers run as non-root', rules: ['IAC-K8S-ROOT-001'], providedByEngine: 'kubernetes-scanner' },
  { framework: 'CIS Kubernetes Benchmark', controlId: '5.2.5', title: 'Privilege escalation disabled', rules: ['IAC-K8S-PRIVESC-001'], providedByEngine: 'kubernetes-scanner' },
  { framework: 'CIS Kubernetes Benchmark', controlId: '5.2.4', title: 'No host namespaces / hostPath volumes', rules: ['IAC-K8S-HOSTNS-001', 'IAC-K8S-HOSTPATH-001'], providedByEngine: 'kubernetes-scanner' },
];

const DISCLAIMER =
  'Technical evidence only — NOT a certification or a statement of regulatory compliance. ' +
  '"SATISFIED" means the automated check ran and found no violation; it does not assert compliance. ' +
  'Controls whose check did not run are NOT_ASSESSED, never assumed satisfied. Formal compliance requires human/legal sign-off.';

export interface ComplianceResult {
  matrix: ComplianceMatrix;
  score: DimensionScore;
}

/** Build the control-coverage matrix + a ComplianceReadiness dimension score. */
export function mapCompliance(findings: Finding[], ranEngines: ReadonlySet<string>): ComplianceResult {
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.ruleId) ?? [];
    list.push(f);
    byRule.set(f.ruleId, list);
  }

  const controls: ControlMapping[] = CONTROL_CATALOG.map((c) => {
    if (!ranEngines.has(c.providedByEngine)) {
      return {
        framework: c.framework,
        controlId: c.controlId,
        title: c.title,
        status: 'NOT_ASSESSED',
        mappedRules: c.rules,
        gapFindings: [],
        note: `Not assessed — the '${c.providedByEngine}' check did not run for this project.`,
      };
    }
    const gapFindings = c.rules
      .flatMap((r) => byRule.get(r) ?? [])
      .filter((f) => f.status === 'FAIL' || f.status === 'WARNING')
      .map((f) => f.id);
    const status: ControlStatus = gapFindings.length > 0 ? 'GAPS' : 'SATISFIED';
    return {
      framework: c.framework,
      controlId: c.controlId,
      title: c.title,
      status,
      mappedRules: c.rules,
      gapFindings,
      note:
        status === 'SATISFIED'
          ? 'The automated check ran and found no violation (technical evidence only).'
          : `${gapFindings.length} finding(s) represent gaps for this control.`,
    };
  });

  const total = controls.length;
  const notAssessed = controls.filter((c) => c.status === 'NOT_ASSESSED').length;
  const assessed = total - notAssessed;
  const satisfied = controls.filter((c) => c.status === 'SATISFIED').length;
  const gaps = controls.filter((c) => c.status === 'GAPS').length;

  const frameworks = [...new Set(controls.map((c) => c.framework))];
  const matrix: ComplianceMatrix = {
    disclaimer: DISCLAIMER,
    frameworks,
    controls,
    summary: { total, assessed, satisfied, gaps, notAssessed },
  };

  const coverage = total === 0 ? 0 : assessed / total;
  const scoreValue = assessed === 0 ? 0 : Math.round((satisfied / assessed) * 100);
  const confidence = coverageToConfidence(coverage, false);

  const why: string[] = [
    `${satisfied}/${assessed} assessed controls satisfied; ${gaps} with gaps.`,
    `${assessed}/${total} controls assessed (${notAssessed} not assessed because their check did not run).`,
  ];
  const unknowns = controls.filter((c) => c.status === 'NOT_ASSESSED').map((c) => `${c.framework} ${c.controlId} not assessed`);

  const score: DimensionScore = {
    dimension: 'ComplianceReadiness',
    score: scoreValue,
    confidence,
    coverage,
    weight: 0, // configurable; not part of the default weighted overall
    why,
    unknowns,
  };

  const violations = checkScoreInvariants(score);
  if (violations.length > 0) {
    throw new Error('Compliance score invariant violation: ' + violations.map((v) => v.message).join('; '));
  }

  return { matrix, score };
}
