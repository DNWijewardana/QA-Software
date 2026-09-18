/**
 * Self-contained HTML report exporter (§IX.3). Produces a single styled, accessible HTML document from a
 * ScanResult — shareable and printable ("Print to PDF").
 *
 * SECURITY: findings/evidence originate from UNTRUSTED scanned code, so every dynamic value is HTML-escaped
 * before it is written into the document (prevents stored-XSS when the report is opened in a browser).
 */

import type { Finding, ScanResult, Severity } from '@qa/core';
import { xmlEscape } from './xml.js';

const esc = xmlEscape;
const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
const pct = (n: number) => `${Math.round(n * 100)}%`;

function meter(label: string, value: number): string {
  const band = value >= 80 ? 'good' : value >= 50 ? 'warn' : 'bad';
  return `<div class="meter ${band}" role="meter" aria-valuenow="${value}" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(label)} score ${value} of 100"><span style="width:${value}%"></span></div>`;
}

function findingsTable(findings: Finding[]): string {
  if (findings.length === 0) return '<p class="muted">No findings in the executed checks. (Not proof of absence — see Limitations.)</p>';
  const rows = [...findings]
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .map((f) => {
      const loc = f.location.file
        ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
        : f.location.endpoint ?? f.location.url ?? '—';
      const snippet = f.evidence[0]?.snippet ? `<div class="mono snippet">${esc(f.evidence[0]!.snippet.replace(/\n/g, ' '))}</div>` : '';
      const fix = f.remediation ? `<div class="fix">Fix: ${esc(f.remediation.summary)}</div>` : '';
      return `<tr>
        <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td><strong>${esc(f.title)}</strong><div class="muted">${esc(f.description)}</div>${snippet}${fix}</td>
        <td class="mono">${esc(loc)}</td>
        <td>${esc(f.status)} <span class="muted">(${esc(f.confidence)})</span></td>
        <td class="mono">${esc(f.cwe.join(', ') || '—')}</td>
      </tr>`;
    })
    .join('\n');
  return `<div class="table-wrap"><table>
    <thead><tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Location</th><th scope="col">Status</th><th scope="col">CWE</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

export function toHtml(r: ScanResult): string {
  const ov = r.overall;
  const decision = r.releaseDecision.decision;

  const kpis = `<div class="kpis">
    <div class="kpi"><div class="kv">${ov.score === null ? 'N/A' : `${ov.score}/100`}</div><div class="kl">Overall score</div></div>
    <div class="kpi"><div class="kv">${pct(ov.evidenceCoverage)}</div><div class="kl">Evidence coverage</div></div>
    <div class="kpi"><div class="kv">${ov.criticalBlockers}</div><div class="kl">Critical blockers</div></div>
    <div class="kpi"><div class="kv">${ov.highRiskFindings}</div><div class="kl">High-risk findings</div></div>
    <div class="kpi"><div class="kv">${ov.manualVerificationRequired}</div><div class="kl">Manual verification</div></div>
  </div>`;

  const dims = r.scores.map((s) => `<li>
      <div class="dim-head"><span><strong>${esc(s.dimension)}</strong></span><span class="muted">${s.score}/100 · ${esc(s.confidence)} · ${pct(s.coverage)} coverage</span></div>
      ${meter(s.dimension, s.score)}
      ${s.why.length ? `<div class="muted small">${esc(s.why.join(' '))}</div>` : ''}
    </li>`).join('\n');

  const compliance = r.compliance ? `<section><h2>Compliance (control-coverage matrix)</h2>
    <p class="muted">${esc(r.compliance.disclaimer)}</p>
    <p><strong>${r.compliance.summary.assessed}/${r.compliance.summary.total}</strong> assessed · ${r.compliance.summary.satisfied} satisfied · ${r.compliance.summary.gaps} with gaps · ${r.compliance.summary.notAssessed} not assessed</p>
    <div class="table-wrap"><table><thead><tr><th scope="col">Status</th><th scope="col">Framework</th><th scope="col">Control</th><th scope="col">Title</th></tr></thead><tbody>
    ${r.compliance.controls.map((c) => `<tr><td><span class="ctrl ${esc(c.status)}">${esc(c.status.replace('_', ' '))}</span></td><td>${esc(c.framework)}</td><td class="mono">${esc(c.controlId)}</td><td>${esc(c.title)}</td></tr>`).join('\n')}
    </tbody></table></div></section>` : '';

  const sbom = r.sbom ? `<section><h2>Supply chain (SBOM)</h2>
    <p class="muted">${esc(r.sbom.format)} ${esc(r.sbom.specVersion)} · source: ${esc(r.sbom.source)} · ${r.sbom.components.length} component(s). Vulnerability status is NOT_TESTED offline — not "clean".</p>
    <div class="table-wrap"><table><thead><tr><th scope="col">Component</th><th scope="col">Version</th><th scope="col">Scope</th><th scope="col">Vuln status</th></tr></thead><tbody>
    ${r.sbom.components.map((c) => `<tr><td>${esc(c.name)}</td><td class="mono">${esc(c.version)}</td><td>${esc(c.scope)}</td><td>${esc(c.vulnerabilityStatus)}</td></tr>`).join('\n')}
    </tbody></table></div></section>` : '';

  const seo = r.seo ? `<section><h2>SEO <span class="muted small">(separate from software quality)</span></h2>
    <p class="muted">${esc(r.seo.note)}</p>
    <ul>${r.seo.findings.map((f) => `<li><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)} <span class="mono muted">${esc(f.ruleId)}</span></li>`).join('\n')}</ul></section>` : '';

  const manual = r.manualReviewQueue.length ? `<section><h2>Manual review required</h2><ul>${r.manualReviewQueue.map((m) => `<li><strong>${esc(m.item)}</strong> — ${esc(m.reason)}</li>`).join('\n')}</ul></section>` : '';
  const limitations = `<section><h2>Limitations (never hidden)</h2><ul>${r.limitations.map((l) => `<li>${esc(l)}</li>`).join('\n')}</ul></section>`;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quality Assessment Report — ${esc(r.scan.id)}</title>
<style>
  :root { --bg:#f7f8fa; --surface:#fff; --surface2:#eef1f5; --border:#cdd3dc; --text:#14181f; --muted:#4a5361; --go:#1c6b2f; --nogo:#a11020; --cond:#7a5b00; }
  @media (prefers-color-scheme: dark){ :root{ --bg:#0e1116; --surface:#171b22; --surface2:#1f242d; --border:#333b47; --text:#e8ebf0; --muted:#a4adbb; --go:#7fd394; --nogo:#ff8a8a; --cond:#e6c766; } }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;line-height:1.5}
  main{max-width:1000px;margin:0 auto;padding:1.5rem 1rem 4rem}
  h1{font-size:1.3rem} h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}
  .muted{color:var(--muted)} .small{font-size:.85rem} .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em}
  .decision{display:inline-block;font-weight:700;padding:.4rem .9rem;border:2px solid currentColor;border-radius:8px}
  .decision.GO{color:var(--go)} .decision.NO_GO{color:var(--nogo)} .decision.GO_WITH_CONDITIONS{color:var(--cond)} .decision.INSUFFICIENT_EVIDENCE{color:var(--muted)}
  .kpis{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0} .kpi{border:1px solid var(--border);border-radius:8px;background:var(--surface2);padding:.6rem .9rem;min-width:120px}
  .kv{font-size:1.4rem;font-weight:700} .kl{font-size:.8rem;color:var(--muted)}
  ul.dims{list-style:none;padding:0;display:grid;gap:.9rem} .dim-head{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap}
  .meter{height:10px;background:var(--surface2);border:1px solid var(--border);border-radius:999px;overflow:hidden} .meter span{display:block;height:100%}
  .meter.good span{background:var(--go)} .meter.warn span{background:var(--cond)} .meter.bad span{background:var(--nogo)}
  .table-wrap{overflow-x:auto} table{border-collapse:collapse;width:100%;background:var(--surface)} th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--border);vertical-align:top} th{border-bottom:2px solid var(--border)}
  .sev{font-size:.75rem;font-weight:700;padding:.1rem .45rem;border:1px solid currentColor;border-radius:4px;white-space:nowrap}
  .sev.Critical{color:#a11020} .sev.High{color:#a63a00} .sev.Medium{color:#7a5b00} .sev.Low{color:#29506b} .sev.Informational{color:var(--muted)}
  .ctrl{font-weight:600} .ctrl.SATISFIED{color:var(--go)} .ctrl.GAPS{color:var(--nogo)} .ctrl.NOT_ASSESSED{color:var(--muted)}
  .snippet{margin-top:.3rem;color:var(--muted)} .fix{margin-top:.3rem}
  @media print{ body{background:#fff} .kpi,table{break-inside:avoid} }
</style></head>
<body><main>
  <h1>Quality Assessment Report</h1>
  <p class="muted">Scan <span class="mono">${esc(r.scan.id)}</span> · Mode ${esc(r.scan.mode)} · Ruleset ${esc(r.scan.manifest.rulesetVersion)} · ${esc(r.scan.startedAt)}</p>

  <h2>Release Decision</h2>
  <p><span class="decision ${esc(decision)}">${esc(decision.replace(/_/g, ' '))}</span></p>
  <p class="muted">${esc(r.releaseDecision.rationale)}</p>
  ${r.releaseDecision.conditions.length ? `<ul>${r.releaseDecision.conditions.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` : ''}

  <h2>Overall</h2>${kpis}<p class="muted">Confidence: ${esc(ov.confidence)}</p>

  <h2>Quality dimensions</h2><ul class="dims">${dims}</ul>

  <h2>Findings</h2>${findingsTable(r.findings)}
  ${compliance}${sbom}${seo}${manual}${limitations}
</main></body></html>`;
}
