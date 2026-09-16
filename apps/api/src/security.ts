/**
 * Path-safety guard (§VIII.5 least-privilege / filesystem isolation). A scan target must resolve
 * under an explicitly allowed root — this prevents a request from pointing the scanner at arbitrary
 * host paths (e.g. `/etc`, `C:\Windows`) or traversing out with `..`.
 *
 * This is a REAL control (not a fake one): in SAFE_STATIC local mode we still refuse to read outside
 * the sandboxed roots. In production, uploads land in a per-job sandbox and this guard is even stricter.
 */

import path from 'node:path';

export interface PathCheckResult {
  ok: boolean;
  resolved: string;
  reason?: string;
}

export function resolveWithinAllowedRoots(requested: string, allowedRoots: string[]): PathCheckResult {
  const resolved = path.resolve(requested);
  for (const root of allowedRoots) {
    const absRoot = path.resolve(root);
    const rel = path.relative(absRoot, resolved);
    const isInside = rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    if (isInside) return { ok: true, resolved };
  }
  return {
    ok: false,
    resolved,
    reason: `Target path is not under an allowed root. Allowed: ${allowedRoots.join(', ')}`,
  };
}
