'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { TargetRoot } from '@/app/lib/types';

export function SubmitForm({ targets }: { targets: TargetRoot[] }) {
  const router = useRouter();
  const options = useMemo(
    () => targets.flatMap((t) => t.projects.map((p) => ({ label: p.name, value: p.path }))),
    [targets],
  );
  const [selected, setSelected] = useState(options[0]?.value ?? '');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ projectDir: selected }),
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

  if (options.length === 0) {
    return (
      <div className="notice" role="status">
        No scannable projects were returned by the API. Ensure the API is running and that its allowed
        roots contain at least one project directory.
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} aria-describedby="submit-help">
      <p id="submit-help" className="muted">
        Runs a SAFE_STATIC scan (reads files only; nothing is executed). The API restricts targets to its
        configured allowed roots.
      </p>
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
      {error ? (
        <div className="notice error" role="alert">
          {error}
        </div>
      ) : null}
      <button type="submit" disabled={submitting} aria-busy={submitting}>
        {submitting ? 'Submitting…' : 'Start scan'}
      </button>
    </form>
  );
}
