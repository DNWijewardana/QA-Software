/**
 * Source-ingestion tests (§0.3.1, §VIII.1). Verifies:
 *  - the remote-source SECURITY policy (assertAllowedRemote) accepts public https and rejects everything else,
 *  - the clone mechanism actually works (hermetically, against a local git repo over file:// — no network),
 *  - prepareSource resolves a local directory and cleans up a cloned temp dir.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertAllowedRemote, cloneRepo, isRemoteTarget, prepareSource } from '@qa/orchestrator';

function git(cwd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const c = spawn('git', args, {
      cwd,
      shell: false,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    });
    let err = '';
    c.stderr?.on('data', (d) => (err += String(d)));
    c.on('error', reject);
    c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`git ${args.join(' ')}: ${err}`))));
  });
}

let tmp: string;
let repoDir: string;
let repoUrl: string;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-ingest-'));
  repoDir = path.join(tmp, 'origin');
  await fs.mkdir(repoDir, { recursive: true });
  await fs.writeFile(path.join(repoDir, 'app.js'), 'const x = 1;\n', 'utf8');
  // Local repo with a single commit — identity supplied via -c so it works on a bare CI machine.
  await git(repoDir, ['init', '-q', '-b', 'main']);
  await git(repoDir, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'add', 'app.js']);
  await git(repoDir, ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init']);
  repoUrl = pathToFileURL(repoDir).href;
});
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('remote-source policy (assertAllowedRemote)', () => {
  it('accepts a public https URL and strips no-op credentials', () => {
    expect(assertAllowedRemote('https://github.com/owner/repo.git')).toBe('https://github.com/owner/repo.git');
  });

  it('rejects non-https schemes', () => {
    expect(() => assertAllowedRemote('http://github.com/o/r.git')).toThrow(/only https/i);
    expect(() => assertAllowedRemote('git://github.com/o/r.git')).toThrow();
    expect(() => assertAllowedRemote('ssh://git@github.com/o/r.git')).toThrow();
    expect(() => assertAllowedRemote('file:///etc/passwd')).toThrow();
  });

  it('rejects embedded credentials', () => {
    expect(() => assertAllowedRemote('https://user:pass@github.com/o/r.git')).toThrow(/credential/i);
  });

  it('rejects loopback/private/metadata hosts (SSRF mitigation)', () => {
    for (const h of ['localhost', '127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.0.1', '169.254.169.254', '[::1]']) {
      expect(() => assertAllowedRemote(`https://${h}/o/r.git`), h).toThrow(/private|loopback/i);
    }
  });
});

describe('isRemoteTarget', () => {
  it('distinguishes URLs from local paths', () => {
    expect(isRemoteTarget('https://github.com/o/r.git')).toBe(true);
    expect(isRemoteTarget('git@github.com:o/r.git')).toBe(true);
    expect(isRemoteTarget('file:///tmp/repo')).toBe(true);
    expect(isRemoteTarget('./fixtures/vulnerable-sample')).toBe(false);
    expect(isRemoteTarget('C:/projects/site')).toBe(false);
  });
});

describe('cloneRepo (hermetic, file://)', () => {
  it('clones a repository into a fresh directory', async () => {
    const dest = path.join(tmp, 'clone');
    await cloneRepo(repoUrl, dest);
    expect((await fs.readFile(path.join(dest, 'app.js'), 'utf8')).trim()).toBe('const x = 1;');
  });
});

describe('prepareSource', () => {
  it('resolves a local directory with a no-op cleanup', async () => {
    const s = await prepareSource(repoDir);
    expect(s.origin.type).toBe('local');
    expect(s.dir).toBe(path.resolve(repoDir));
    await s.cleanup(); // must not remove the real directory
    expect((await fs.stat(repoDir)).isDirectory()).toBe(true);
  });

  it('throws on a non-existent local directory', async () => {
    await expect(prepareSource(path.join(tmp, 'does-not-exist'))).rejects.toThrow(/not a directory/i);
  });

  it('clones a remote target and cleans up the temp dir (policy bypassed for file://)', async () => {
    const s = await prepareSource(repoUrl, { enforceRemotePolicy: false });
    expect(s.origin.type).toBe('git');
    expect((await fs.stat(s.dir)).isDirectory()).toBe(true);
    const cloneParent = path.dirname(s.dir);
    await s.cleanup();
    await expect(fs.stat(cloneParent)).rejects.toThrow(); // temp removed
  });
});
