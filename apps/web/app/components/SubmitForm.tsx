'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanPolicyInput, TargetRoot } from '@/app/lib/types';

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
  const [maxHigh, setMaxHigh] = useState('');
  const [secWeight, setSecWeight] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /** Build an optional policy from the advanced inputs; undefined when nothing valid was entered. */
  function buildPolicy(): ScanPolicyInput | undefined {
    const policy: ScanPolicyInput = {};
    const mh = Number(maxHigh);
    if (maxHigh.trim() !== '' && Number.isFinite(mh) && mh >= 0) policy.gates = { maxHigh: Math.floor(mh) };
    const sw = Number(secWeight);
    if (secWeight.trim() !== '' && Number.isFinite(sw) && sw >= 0) policy.weights = { Security: sw };
    return policy.gates || policy.weights ? policy : undefined;
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const source = mode === 'git' ? { sourceUrl: gitUrl.trim() } : { projectDir: selected };
    if (mode === 'git' ? !source.sourceUrl : !source.projectDir) return;
    const policy = buildPolicy();
    const payload = policy ? { ...source, policy } : source;
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
      </details>

      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}
      <button
        type="submit"
        disabled={submitting || (mode === 'local' ? !selected : !gitUrl.trim())}
        aria-busy={submitting}
      >
        {submitting ? 'Submitting…' : 'Start scan'}
      </button>
    </form>
  );
}
