/**
 * CLI baseline regression-gate test (§VII.10, §V.19). Drives the real CLI: generates a baseline scan, then
 * scans a WORSE target with --baseline --fail-on-regression (expects a non-zero CI gate) and a
 * NON-worse target (expects success). Verifies the differential CI gate end-to-end.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../', import.meta.url));
const cli = 'apps/cli/src/index.ts';
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

/** Run the CLI via a quoted shell command (Windows-safe with spaces in paths). Returns exit code + stdout. */
function runCli(args: string[]): { status: number; stdout: string } {
  const cmd = ['npx', 'tsx', cli, ...args.map((a) => (a.startsWith('--') || !a.includes(' ') ? a : `"${a}"`))].join(' ');
  const r = spawnSync(cmd, { cwd: repoRoot, shell: true, encoding: 'utf8' });
  return { status: r.status ?? -1, stdout: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

describe('CLI baseline regression gate (§VII.10)', () => {
  it('fails on a regression and passes when there is none', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cli-base-'));
    const baseOut = path.join(tmp, 'base');

    // 1) Generate a baseline scan of the architecture fixture (no Critical → not NO_GO).
    const gen = runCli(['fixtures/bad-architecture', '--out', baseOut, '--json-only']);
    expect(gen.status).toBe(0);
    const scanDirs = await fs.readdir(baseOut);
    const baselinePath = path.join(baseOut, scanDirs[0]!, 'result.json');

    // 2) Scan a WORSE target (vulnerable-sample seeds a Critical) against the baseline → regression → exit 1.
    const worse = runCli(['fixtures/vulnerable-sample', '--out', path.join(tmp, 'worse'), '--baseline', baselinePath, '--fail-on-regression']);
    expect(worse.status).toBe(1);
    expect(worse.stdout).toContain('Regression detected');

    // 3) Scan the SAME target against the baseline → no regression, not NO_GO → exit 0.
    const same = runCli(['fixtures/bad-architecture', '--out', path.join(tmp, 'same'), '--baseline', baselinePath, '--fail-on-regression', '--json-only']);
    expect(same.status).toBe(0);
  }, 60_000);
});
