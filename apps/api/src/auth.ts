/**
 * Authentication & RBAC for the platform API (§VIII.8).
 *
 * API-key auth: each request carries `Authorization: Bearer <key>` (or `x-api-key: <key>`). A key maps to a
 * principal { orgId, role }. Roles gate actions (RBAC). Org isolation is enforced by the server: a principal
 * may only read/act on records belonging to its own org (§VIII.8 — tenant isolation is a first-class control).
 *
 * Auth is opt-in: when a non-empty key list is configured, it is ENFORCED; with no keys the API runs open
 * (single-tenant dev mode). Keys are compared with a constant-time check to avoid timing leaks.
 */

import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

export const ROLES = ['Owner', 'Admin', 'QAManager', 'SecurityAnalyst', 'Developer', 'Viewer', 'Auditor', 'ComplianceOfficer'] as const;
export type Role = (typeof ROLES)[number];

export interface ApiKeyConfig {
  key: string;
  orgId: string;
  role: Role;
  /** non-secret identifier for logs/audit (never log the key itself). */
  keyId: string;
}

export interface Principal {
  orgId: string;
  role: Role;
  keyId: string;
}

/** Roles permitted to submit a scan (a write action). Read is allowed for any authenticated role. */
const SUBMIT_ROLES = new Set<Role>(['Owner', 'Admin', 'QAManager', 'SecurityAnalyst', 'Developer']);

export function canSubmitScan(role: Role): boolean {
  return SUBMIT_ROLES.has(role);
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function extractKey(req: IncomingMessage): string | null {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  const xk = req.headers['x-api-key'];
  if (typeof xk === 'string' && xk.trim()) return xk.trim();
  return null;
}

/** Resolve the request to a principal, or null if the key is missing/invalid. */
export function authenticate(req: IncomingMessage, keys: ApiKeyConfig[]): Principal | null {
  const presented = extractKey(req);
  if (!presented) return null;
  for (const k of keys) {
    if (constantTimeEqual(presented, k.key)) {
      return { orgId: k.orgId, role: k.role, keyId: k.keyId };
    }
  }
  return null;
}

/** Parse QA_API_KEYS (JSON array of {key,orgId,role,keyId}) into a validated key list. */
export function parseApiKeys(raw: string | undefined): ApiKeyConfig[] {
  if (!raw || raw.trim() === '') return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('QA_API_KEYS is not valid JSON');
  }
  if (!Array.isArray(parsed)) throw new Error('QA_API_KEYS must be a JSON array');
  return parsed.map((entry, i) => {
    const e = entry as Record<string, unknown>;
    const key = typeof e.key === 'string' ? e.key : '';
    const orgId = typeof e.orgId === 'string' ? e.orgId : '';
    const role = typeof e.role === 'string' && (ROLES as readonly string[]).includes(e.role) ? (e.role as Role) : 'Viewer';
    const keyId = typeof e.keyId === 'string' ? e.keyId : `key-${i}`;
    if (!key || !orgId) throw new Error(`QA_API_KEYS[${i}] requires "key" and "orgId"`);
    return { key, orgId, role, keyId };
  });
}
