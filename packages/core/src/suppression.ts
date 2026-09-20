/**
 * False-positive / suppression management (§VII.17, §52). Users can suppress a finding by rule and/or path,
 * with a reason, author, and optional expiry. Deterministic and pure (§0.2): no I/O, no clock (the caller
 * passes `now`).
 *
 * HARD RULES from the spec, enforced here:
 *  - **Never a global "ignore all"** (§VII.17): a suppression MUST be scoped — it needs a ruleId and/or a
 *    non-wildcard path; a bare `*`/`**` path is rejected.
 *  - **Auditable, scoped, timestamped, attributable, reviewable**: every suppression carries id/reason/
 *    createdBy/createdAt and an optional expiresAt; suppressed findings are RECORDED (not deleted) so an
 *    auditor sees exactly what was hidden, by whom, and why.
 *  - **A suppression can NEVER hide a Critical finding** (§VII.8, Rule 14/22): a suppression that matches a
 *    Critical is refused — the finding stays active and still blocks the release. Mirrors the policy engine.
 */

import type { Finding } from './types.js';

export interface Suppression {
  id: string;
  /** Restrict to this rule (optional). */
  ruleId?: string;
  /** Restrict to files matching this glob/prefix (optional). `*`/`?` globs and directory prefixes supported. */
  pathPattern?: string;
  /** Why this finding is suppressed (false positive / accepted risk / …). Required and non-empty. */
  reason: string;
  /** Who created the suppression (attribution). Required and non-empty. */
  createdBy: string;
  /** ISO-8601 creation time. */
  createdAt: string;
  /** Optional ISO-8601 expiry; after this instant the suppression no longer applies. */
  expiresAt?: string;
}

export interface SuppressedFinding {
  finding: Finding;
  suppression: { id: string; reason: string; createdBy: string; expiresAt?: string };
}

const GLOBAL_PATTERNS = new Set(['*', '**', '**/*', '**/**', '/', './', '.']);

/** Validate a single suppression; returns a list of human-readable errors (empty = valid). */
export function validateSuppression(s: Suppression): string[] {
  const errors: string[] = [];
  if (!s.id || !s.id.trim()) errors.push('suppression.id is required');
  if (!s.reason || !s.reason.trim()) errors.push(`suppression ${s.id}: reason is required`);
  if (!s.createdBy || !s.createdBy.trim()) errors.push(`suppression ${s.id}: createdBy is required`);
  const hasRule = !!(s.ruleId && s.ruleId.trim());
  const hasPath = !!(s.pathPattern && s.pathPattern.trim());
  if (!hasRule && !hasPath) errors.push(`suppression ${s.id}: must be scoped by ruleId and/or pathPattern (no global ignore-all)`);
  if (hasPath && !hasRule && GLOBAL_PATTERNS.has(s.pathPattern!.trim())) {
    errors.push(`suppression ${s.id}: a bare wildcard path ('${s.pathPattern}') without a ruleId is a global ignore-all and is not allowed`);
  }
  return errors;
}

/** Partition a suppression list into valid ones and a flat list of validation errors. */
export function resolveSuppressions(list: Suppression[]): { valid: Suppression[]; errors: string[] } {
  const valid: Suppression[] = [];
  const errors: string[] = [];
  for (const s of list) {
    const e = validateSuppression(s);
    if (e.length) errors.push(...e);
    else valid.push(s);
  }
  return { valid, errors };
}

function globToRegExp(glob: string): RegExp {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const re = esc.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${re}$`);
}

function pathMatches(pattern: string, file: string | undefined): boolean {
  if (file === undefined) return false;
  if (/[*?]/.test(pattern)) return globToRegExp(pattern).test(file);
  // No glob chars → exact file or directory-prefix match.
  if (file === pattern) return true;
  const dir = pattern.endsWith('/') ? pattern : `${pattern}/`;
  return file.startsWith(dir);
}

function isExpired(s: Suppression, now: string): boolean {
  return s.expiresAt !== undefined && s.expiresAt <= now;
}

/** True if a suppression scopes to this finding (rule + path both, when present) and is not expired. */
function suppressionMatches(s: Suppression, f: Finding, now: string): boolean {
  if (isExpired(s, now)) return false;
  if (s.ruleId && s.ruleId !== f.ruleId) return false;
  if (s.pathPattern && !pathMatches(s.pathPattern, f.location?.file)) return false;
  return true;
}

/**
 * Apply suppressions to a finding list. Matched non-Critical findings move to `suppressed` (recorded for
 * audit); everything else stays `active`. Critical findings are NEVER suppressed — a matching suppression is
 * refused and the finding stays active (recorded in `refusedCritical`).
 */
export function applySuppressions(
  findings: Finding[],
  suppressions: Suppression[],
  now: string,
): { active: Finding[]; suppressed: SuppressedFinding[]; refusedCritical: number } {
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  let refusedCritical = 0;

  for (const f of findings) {
    const match = suppressions.find((s) => suppressionMatches(s, f, now));
    if (!match) {
      active.push(f);
      continue;
    }
    if (f.severity === 'Critical') {
      // A suppression can never hide a Critical (§VII.8, Rule 14/22).
      refusedCritical++;
      active.push(f);
      continue;
    }
    suppressed.push({
      finding: f,
      suppression: { id: match.id, reason: match.reason, createdBy: match.createdBy, expiresAt: match.expiresAt },
    });
  }
  return { active, suppressed, refusedCritical };
}
