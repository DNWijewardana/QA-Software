/**
 * Human-readable report generator (§IX.1, §IX.2). Honest language: states what was tested,
 * what was NOT, and the confidence. Never "your software looks good."
 */

import type { Finding, ScanResult, Severity } from '@qa/core';

const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

function bySeverity(a: Finding, b: Finding): number {
  return SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
}

export function renderHumanReport(r: ScanResult): string {
  const L: string[] = [];
  const p = (s = '') => L.push(s);

  p('# Quality Assessment Report');
  p();
  p(`- **Scan ID:** ${r.scan.id}`);
  p(`- **Mode:** ${r.scan.mode}`);
  p(`- **Started / Completed:** ${r.scan.startedAt} → ${r.scan.completedAt ?? '(running)'}`);
  p(`- **Ruleset:** ${r.scan.manifest.rulesetVersion}  ·  **Node:** ${r.scan.manifest.runtimeVersions.node}`);
  p();

  // Release decision first — the headline (§VII.9).
  p('## Release Decision');
  p(`**${r.releaseDecision.decision}** — ${r.releaseDecision.rationale}`);
  if (r.releaseDecision.conditions.length) {
    p();
    p('Conditions:');
    for (const c of r.releaseDecision.conditions) p(`- ${c}`);
  }
  p();
  p('Gates evaluated:');
  for (const g of r.releaseDecision.gatesEvaluated) p(`- ${g.gate}: **${g.result}**`);
  p();

  // Project profile with detection confidence (§III.3).
  p('## Project Profile');
  const langs = r.projectProfile.languages.map((l) => `${l.name} (${(l.confidence * 100).toFixed(0)}%)`).join(', ') || 'none detected';
  const fw = r.projectProfile.frameworks.map((f) => f.name).join(', ') || 'none detected';
  p(`- **Languages:** ${langs}`);
  p(`- **Frameworks:** ${fw}`);
  p(`- **Package managers:** ${r.projectProfile.packageManagers.join(', ') || 'none'}`);
  p(`- **Tests present:** ${r.projectProfile.hasTests ? 'yes' : 'no'}`);
  p(`- **Files analyzed:** ${r.projectProfile.fileCount}`);
  p(`- **Detection confidence:** ${(r.projectProfile.detectionConfidence * 100).toFixed(0)}%`);
  for (const n of r.projectProfile.notes) p(`  - note: ${n}`);
  p();

  // Overall — with the honesty caveats (§VII.6).
  p('## Overall');
  const ov = r.overall;
  p(`- **Overall score:** ${ov.score === null ? 'INSUFFICIENT EVIDENCE (not enough coverage to responsibly aggregate)' : `${ov.score}/100`}`);
  p(`- **Confidence:** ${ov.confidence}`);
  p(`- **Evidence coverage:** ${(ov.evidenceCoverage * 100).toFixed(0)}%`);
  p(`- **Critical blockers:** ${ov.criticalBlockers}  ·  **High-risk findings:** ${ov.highRiskFindings}`);
  p(`- **Manual verification required:** ${ov.manualVerificationRequired}`);
  if (ov.untestedAreas.length) p(`- **Low-coverage / untested dimensions:** ${ov.untestedAreas.join(', ')}`);
  p();

  // Per-dimension scores, each explaining WHY (§VII.6).
  p('## Dimension Scores (each explains "why")');
  for (const s of r.scores) {
    p(`### ${s.dimension}: ${s.score}/100 — Confidence: ${s.confidence} — Coverage: ${(s.coverage * 100).toFixed(0)}%`);
    for (const w of s.why) p(`- why: ${w}`);
    for (const u of s.unknowns) p(`- unknown: ${u}`);
    p();
  }

  // Findings, most severe first.
  p('## Findings');
  if (r.findings.length === 0) {
    p('No findings in the executed checks. (This is NOT proof of absence — see Limitations.)');
  } else {
    const sorted = [...r.findings].sort(bySeverity);
    for (const f of sorted) {
      const loc = f.location.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : f.location.endpoint ?? f.location.url ?? '';
      p(`- **[${f.severity}] ${f.title}** (${f.id}, ${f.status}, ${f.confidence})`);
      p(`  - where: ${loc}`);
      p(`  - ${f.description}`);
      if (f.evidence[0]?.snippet) p(`  - evidence (redacted): \`${f.evidence[0]!.snippet.replace(/\n/g, ' ')}\``);
      if (f.remediation) p(`  - fix: ${f.remediation.summary}`);
      if (f.cwe.length) p(`  - CWE: ${f.cwe.join(', ')}`);
    }
  }
  p();

  // Supply chain / SBOM (§V.17, §IX.1 Supply-Chain Report).
  if (r.sbom) {
    p('## Supply Chain (SBOM)');
    p(`- **Format:** ${r.sbom.format} ${r.sbom.specVersion}  ·  **Source:** ${r.sbom.source}`);
    p(`- **Components inventoried:** ${r.sbom.components.length}`);
    const notTested = r.sbom.components.filter((c) => c.vulnerabilityStatus === 'NOT_TESTED').length;
    if (notTested > 0) {
      p(`- **Vulnerability status:** ${notTested}/${r.sbom.components.length} components NOT checked against a CVE/OSV database (offline). Reported as NOT_TESTED — not "clean".`);
    }
    for (const n of r.sbom.notes) p(`  - note: ${n}`);
    p();
  }

  // Compliance control-coverage matrix (§IV.3, §IX.1). Technical evidence only — not a certification.
  if (r.compliance) {
    const c = r.compliance;
    p('## Compliance (control-coverage matrix)');
    p(`> ${c.disclaimer}`);
    p();
    p(`- **Frameworks:** ${c.frameworks.join(', ')}`);
    p(`- **Controls:** ${c.summary.assessed}/${c.summary.total} assessed · ${c.summary.satisfied} satisfied · ${c.summary.gaps} with gaps · ${c.summary.notAssessed} not assessed`);
    p();
    for (const ctrl of c.controls) {
      const mark = ctrl.status === 'SATISFIED' ? '✓' : ctrl.status === 'GAPS' ? '✗' : '–';
      p(`- ${mark} **${ctrl.framework} ${ctrl.controlId}** — ${ctrl.title}: **${ctrl.status}**`);
      if (ctrl.gapFindings.length) p(`  - gaps: ${ctrl.gapFindings.join(', ')}`);
      else p(`  - ${ctrl.note}`);
    }
    p();
  }

  // SEO — reported SEPARATELY from software quality (§V.24).
  if (r.seo) {
    p('## SEO (reported separately from software quality)');
    p(`> ${r.seo.note}`);
    p();
    p(`- **Pages analyzed:** ${r.seo.summary.pages}  ·  **Issues:** ${r.seo.summary.issues}`);
    for (const f of r.seo.findings) {
      const loc = f.location.file ?? '(project)';
      p(`- **[${f.severity}] ${f.title}** (${f.ruleId}) — ${loc}`);
    }
    p();
  }

  // Manual review queue (§IX.5) — subjective items honestly separated.
  if (r.manualReviewQueue.length) {
    p('## Manual Review Required (human judgment)');
    for (const m of r.manualReviewQueue) p(`- ${m.item} — ${m.reason}`);
    p();
  }

  // Suppressed findings (§VII.17) — recorded and auditable; excluded from scores/gates but never hidden.
  if (r.suppressedFindings && r.suppressedFindings.length) {
    p('## Suppressed Findings (auditable — excluded from scores/gates)');
    for (const s of r.suppressedFindings) {
      const loc = s.finding.location?.file ? ` (${s.finding.location.file}${s.finding.location.line ? `:${s.finding.location.line}` : ''})` : '';
      const exp = s.suppression.expiresAt ? `, expires ${s.suppression.expiresAt}` : '';
      p(`- [${s.finding.severity}] ${s.finding.ruleId} — ${s.finding.title}${loc} · suppressed by ${s.suppression.createdBy}${exp}: ${s.suppression.reason}`);
    }
    p();
  }

  // Limitations — never hidden (§XIII rule 10).
  p('## Limitations (never hidden)');
  for (const lim of r.limitations) p(`- ${lim}`);
  p();

  return L.join('\n');
}
