/**
 * Source ingestion (§0.3.1 authorized-target, §VIII.1 SAFE_STATIC): resolve a scan *target* — either a
 * local directory or a remote git URL — into a local directory the pipeline can read.
 *
 * SECURITY:
 *  - The git URL is passed to `git` as an ARGUMENT (spawn with an arg array, `shell:false`), never
 *    interpolated into a shell command — no command injection.
 *  - `assertAllowedRemote` is the policy for UNTRUSTED callers (the API): HTTPS only, no embedded
 *    credentials, and a best-effort block of loopback/private hosts (SSRF mitigation — best-effort because
 *    DNS can still resolve a public name to a private address).
 *  - Clone is shallow (`--depth 1 --single-branch --no-tags`), non-interactive (`GIT_TERMINAL_PROMPT=0`),
 *    and time-bounded, so a hostile or huge repo cannot hang or exhaust the host.
 *  - Nothing from the repo is executed; it is only read. Submodules are NOT initialised.
 */

import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface SourceOrigin {
  type: 'local' | 'git';
  /** Human-readable reference: the resolved local path, or the (credential-free) git URL. */
  ref: string;
}

export interface PreparedSource {
  /** A local directory the scan pipeline can read. */
  dir: string;
  origin: SourceOrigin;
  /** Remove any temporary clone. Safe to call always; a no-op for local sources. */
  cleanup: () => Promise<void>;
}

export interface CloneOptions {
  /** Hard wall-clock limit for the clone; the git process is killed on expiry. Default 120s. */
  timeoutMs?: number;
  /** History depth. Default 1 (shallow) — we only need the working tree. */
  depth?: number;
}

/** Does this target look like a remote git URL (as opposed to a local path)? */
export function isRemoteTarget(s: string): boolean {
  if (/^(https?|git|ssh|file):\/\//i.test(s)) return true;
  if (/^git@[^:]+:.+/.test(s)) return true; // scp-like: git@host:owner/repo.git
  return false;
}

function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  if (h === 'localhost' || h === '0.0.0.0' || h === '::1' || h === '::') return true;
  if (h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  // IPv6 loopback / unique-local / link-local (best-effort prefix match).
  if (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  // IPv4 literals.
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local (incl. cloud metadata 169.254.169.254)
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  return false;
}

/**
 * Enforce the remote-source policy for untrusted callers. Throws on violation.
 * Returns the normalised, credential-free URL that is safe to log and to hand to git.
 */
export function assertAllowedRemote(rawUrl: string): string {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error(`not a valid URL: ${rawUrl}`);
  }
  if (u.protocol !== 'https:') {
    throw new Error(`only https:// git URLs are allowed (got '${u.protocol}//'); clone privately and scan the local path instead`);
  }
  if (u.username || u.password) {
    throw new Error('embedded credentials are not allowed in the URL; scan a public repository or clone it privately first');
  }
  if (isPrivateHost(u.hostname)) {
    throw new Error(`refusing to fetch from a private/loopback host: ${u.hostname}`);
  }
  u.username = '';
  u.password = '';
  return u.toString();
}

/**
 * Clone `url` into the (non-existent) `destDir`. Low-level mechanism — the caller applies policy.
 * Rejects with git's stderr on failure. No shell is used.
 */
export function cloneRepo(url: string, destDir: string, opts: CloneOptions = {}): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const depth = opts.depth ?? 1;
  const args = ['clone', '--depth', String(depth), '--single-branch', '--no-tags', '--', url, destDir];
  return new Promise<void>((resolve, reject) => {
    const child = spawn('git', args, {
      shell: false,
      windowsHide: true,
      timeout: timeoutMs,
      killSignal: 'SIGTERM',
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '', GCM_INTERACTIVE: 'never' },
    });
    let stderr = '';
    child.stderr?.on('data', (d) => {
      if (stderr.length < 4096) stderr += String(d);
    });
    child.on('error', (err) => {
      reject(new Error(`failed to launch git (is it installed?): ${err.message}`));
    });
    child.on('close', (code, signal) => {
      if (code === 0) return resolve();
      if (signal) return reject(new Error(`git clone timed out or was killed (${signal}) after ${timeoutMs}ms`));
      reject(new Error(`git clone failed (exit ${code}): ${stderr.trim().split('\n').slice(-3).join(' ').trim()}`));
    });
  });
}

/**
 * Resolve a scan target into a readable local directory. Remote targets are cloned to a temp dir the
 * caller must release via `cleanup()`. `enforceRemotePolicy` (default true) applies `assertAllowedRemote`.
 */
export async function prepareSource(
  target: string,
  opts: { tmpRoot?: string; enforceRemotePolicy?: boolean } & CloneOptions = {},
): Promise<PreparedSource> {
  if (isRemoteTarget(target)) {
    const url = opts.enforceRemotePolicy === false ? target : assertAllowedRemote(target);
    const tmp = await fs.mkdtemp(path.join(opts.tmpRoot ?? os.tmpdir(), 'qa-src-'));
    const dir = path.join(tmp, 'repo');
    try {
      await cloneRepo(url, dir, opts);
    } catch (err) {
      await fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
      throw err;
    }
    return {
      dir,
      origin: { type: 'git', ref: url },
      cleanup: () => fs.rm(tmp, { recursive: true, force: true }).catch(() => {}),
    };
  }

  const dir = path.resolve(target);
  const stat = await fs.stat(dir).catch(() => null);
  if (!stat?.isDirectory()) {
    throw new Error(`not a directory: ${dir}`);
  }
  return { dir, origin: { type: 'local', ref: dir }, cleanup: async () => {} };
}
