'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanPlan, ScanPolicyInput, SuppressionInput, TargetRoot } from '@/app/lib/types';

interface SupRow {
  ruleId: string;
  pathPattern: string;
  reason: string;
}

type Mode = 'local' | 'git';

export function SubmitForm({ targets }: { targets: TargetRoot[] }) {
  const router = useRouter();
  const options = useMemo(
    () => targets.flatMap((t) => t.projects.map((p) => ({ label: p.name, value: p.path }))),
    [targets],
  );
  // Default to the local dropdown when configured projects exist; otherwise start on the git-URL input.
  const [mode, setMode] = useState<Mode>(options.length > 0 ? 'local' : 'git');
  const [selected, setSelected] = useState(options[0]?.value ?? '');
  const [gitUrl, setGitUrl] = useState('');
  const [tier, setTier] = useState('');
  const [maxHigh, setMaxHigh] = useState('');
  const [secWeight, setSecWeight] = useState('');
  const [supRows, setSupRows] = useState<SupRow[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<ScanPlan | null>(null);
  const [planning, setPlanning] = useState(false);

  /** Build an optional policy from the advanced inputs; undefined when nothing valid was entered. */
  function buildPolicy(): ScanPolicyInput | undefined {
    const policy: ScanPolicyInput = {};
    const mh = Number(maxHigh);
    if (maxHigh.trim() !== '' && Number.isFinite(mh) && mh >= 0) policy.gates = { maxHigh: Math.floor(mh) };
    const sw = Number(secWeight);
    if (secWeight.trim() !== '' && Number.isFinite(sw) && sw >= 0) policy.weights = { Security: sw };
    return policy.gates || policy.weights ? policy : undefined;
  }

  /** Build suppressions from the editor rows; a row needs a reason and a ruleId and/or path. */
  function buildSuppressions(): SuppressionInput[] | undefined {
    const now = new Date().toISOString();
    const valid = supRows
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.reason.trim() && (r.ruleId.trim() || r.pathPattern.trim()))
      .map(({ r, i }) => ({
        id: `web-${i + 1}`,
        ...(r.ruleId.trim() ? { ruleId: r.ruleId.trim() } : {}),
        ...(r.pathPattern.trim() ? { pathPattern: r.pathPattern.trim() } : {}),
        reason: r.reason.trim(),
        createdBy: 'web',
        createdAt: now,
      }));
    return valid.length ? valid : undefined;
  }

  async function onPreviewPlan() {
    if (mode !== 'local' || !selected) return;
    setPlanning(true);
    setError(null);
    setPlan(null);
    try {
      const res = await fetch('/api/plan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ projectDir: selected, ...(tier ? { tier } : {}) }),
      });
      const body = (await res.json()) as ScanPlan & { message?: string; error?: string };
      if (!res.ok || !Array.isArray(body.engines)) {
        setError(body.message ?? body.error ?? `Plan preview failed (${res.status})`);
        return;
      }
      setPlan(body);
    } catch {
      setError('Could not reach the platform API for the plan preview.');
    } finally {
      setPlanning(false);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const source = mode === 'git' ? { sourceUrl: gitUrl.trim() } : { projectDir: selected };
    if (mode === 'git' ? !source.sourceUrl : !source.projectDir) return;
    const policy = buildPolicy();
    const suppressions = buildSuppressions();
    const payload: Record<string, unknown> = { ...source };
    if (policy) payload.policy = policy;
    if (tier) payload.tier = tier;
    if (suppressions) payload.suppressions = suppressions;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const body = (await res.json()) as { scanId?: string; message?: string; error?: string };
      if (!res.ok || !body.scanId) {
        setError(body.message ?? body.error ?? `Request failed (${res.status})`);
        setSubmitting(false);
        return;
      }
      router.push(`/scans/${body.scanId}`);
    } catch {
      setError('Could not reach the platform API.');
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} aria-describedby="submit-help">
      <p id="submit-help" className="muted">
        Runs a SAFE_STATIC scan (reads files only; nothing is executed). Scan a project the API exposes, or
        a public git repository by URL (it is shallow-cloned, scanned, then deleted).
      </p>

      <fieldset className="field">
        <legend>Source</legend>
        <label>
          <input
            type="radio"
            name="mode"
            value="local"
            checked={mode === 'local'}
            disabled={options.length === 0}
            onChange={() => setMode('local')}
          />{' '}
          Configured project{options.length === 0 ? ' (none available)' : ''}
        </label>
        <label>
          <input type="radio" name="mode" value="git" checked={mode === 'git'} onChange={() => setMode('git')} /> Public git URL
        </label>
      </fieldset>

      {mode === 'local' ? (
        <div className="field">
          <label htmlFor="target">Project to scan</label>
          <select id="target" value={selected} onChange={(e) => setSelected(e.target.value)}>
            {options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
      ) : (
        <div className="field">
          <label htmlFor="giturl">Public git URL (https)</label>
          <input
            id="giturl"
            type="url"
            inputMode="url"
            placeholder="https://github.com/owner/repo.git"
            value={gitUrl}
            onChange={(e) => setGitUrl(e.target.value)}
            aria-describedby="giturl-help"
          />
          <p id="giturl-help" className="muted">
            Public HTTPS repositories only. Credentials in the URL and private/loopback hosts are rejected.
          </p>
        </div>
      )}

      <div className="field" style={{ maxWidth: 320 }}>
        <label htmlFor="tier">Scan profile</label>
        <select id="tier" value={tier} onChange={(e) => setTier(e.target.value)} aria-describedby="tier-help">
          <option value="">Standard (default — full static analysis)</option>
          <option value="quick">Quick (fast hygiene subset)</option>
          <option value="deep">Deep (everything applicable)</option>
        </select>
        <p id="tier-help" className="muted">
          Quick runs a reduced engine set for speed (coverage is intentionally limited). Standard and Deep run
          the full static analysis (§IX.9).
        </p>
      </div>

      <details className="advanced">
        <summary>Advanced options (policy)</summary>
        <p className="muted" style={{ marginTop: '0.5rem' }}>
          Optional per-scan policy (§VII.11). Leave blank for platform defaults. A policy can never un-block a
          Critical finding.
        </p>
        <div className="field" style={{ maxWidth: 320 }}>
          <label htmlFor="max-high">High-findings budget (max High before GO_WITH_CONDITIONS)</label>
          <input
            id="max-high"
            type="number"
            min={0}
            step={1}
            inputMode="numeric"
            placeholder="default 0"
            value={maxHigh}
            onChange={(e) => setMaxHigh(e.target.value)}
          />
        </div>
        <div className="field" style={{ maxWidth: 320 }}>
          <label htmlFor="sec-weight">Security dimension weight (relative)</label>
          <input
            id="sec-weight"
            type="number"
            min={0}
            step={0.05}
            inputMode="decimal"
            placeholder="default 0.2"
            value={secWeight}
            onChange={(e) => setSecWeight(e.target.value)}
          />
        </div>

        <fieldset className="field">
          <legend>False-positive suppressions (§VII.17)</legend>
          <p className="muted">
            Scoped and auditable: each needs a reason and a rule id and/or a path. A suppression can never hide
            a Critical finding.
          </p>
          {supRows.map((row, i) => (
            <div key={i} className="row" style={{ gap: '0.5rem', alignItems: 'flex-end', marginBottom: '0.4rem' }}>
              <input
                aria-label={`Suppression ${i + 1} rule id`}
                placeholder="rule id (e.g. RS-UNSAFE-001)"
                value={row.ruleId}
                onChange={(e) => setSupRows((rs) => rs.map((r, j) => (j === i ? { ...r, ruleId: e.target.value } : r)))}
              />
              <input
                aria-label={`Suppression ${i + 1} path`}
                placeholder="path (optional, e.g. src/legacy/**)"
                value={row.pathPattern}
                onChange={(e) => setSupRows((rs) => rs.map((r, j) => (j === i ? { ...r, pathPattern: e.target.value } : r)))}
              />
              <input
                aria-label={`Suppression ${i + 1} reason`}
                placeholder="reason (required)"
                value={row.reason}
                onChange={(e) => setSupRows((rs) => rs.map((r, j) => (j === i ? { ...r, reason: e.target.value } : r)))}
              />
              <button type="button" className="secondary" onClick={() => setSupRows((rs) => rs.filter((_, j) => j !== i))} aria-label={`Remove suppression ${i + 1}`}>
                Remove
              </button>
            </div>
          ))}
          <button type="button" className="secondary" onClick={() => setSupRows((rs) => [...rs, { ruleId: '', pathPattern: '', reason: '' }])}>
            Add suppression
          </button>
        </fieldset>
      </details>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}

      {plan ? (
        <section aria-labelledby="plan-heading" className="panel" style={{ marginTop: '0.75rem' }} aria-live="polite">
          <h3 id="plan-heading">Scan plan (preview — nothing executed yet)</h3>
          <p className="muted">
            Profile: {plan.tier} · Files: {plan.fileCount} · Languages:{' '}
            {plan.languages.map((l) => l.name).join(', ') || 'none detected'} · Engines that will run:{' '}
            {plan.applicableEngines} of {plan.engines.length}
          </p>
          <ul>
            {plan.engines.filter((e) => e.applicable).map((e) => (
              <li key={e.name}>
                {e.name} <span className="muted">({e.dimension})</span>
              </li>
            ))}
          </ul>
          <p className="muted">{plan.note}</p>
        </section>
      ) : null}

      <div className="row" style={{ gap: '0.75rem' }}>
        <button
          type="submit"
          disabled={submitting || (mode === 'local' ? !selected : !gitUrl.trim())}
          aria-busy={submitting}
        >
          {submitting ? 'Submitting…' : 'Start scan'}
        </button>
        {mode === 'local' ? (
          <button type="button" className="secondary" onClick={() => void onPreviewPlan()} disabled={planning || !selected} aria-busy={planning}>
            {planning ? 'Previewing…' : 'Preview plan'}
          </button>
        ) : null}
      </div>
    </form>
  );
}
