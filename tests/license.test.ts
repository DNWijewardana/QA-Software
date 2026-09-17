/**
 * LicenseScanner test (§V.30). Builds temp projects with various package.json license metadata and checks
 * the factual license findings (no legal conclusions). Valid SPDX (incl. expressions) and private+UNLICENSED
 * produce no findings.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '@qa/orchestrator';
import type { ScanResult } from '@qa/core';

async function scanPkg(pkg: Record<string, unknown>): Promise<ScanResult> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-lic-'));
  await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg), 'utf8');
  const result = await runScan({ scanId: 's', projectDir: dir, evidenceDir: path.join(dir, 'ev') });
  await fs.rm(dir, { recursive: true, force: true });
  return result;
}
const licRules = (r: ScanResult) => new Set(r.findings.filter((f) => f.ruleId.startsWith('LIC-')).map((f) => f.ruleId));

describe('LicenseScanner (§V.30)', () => {
  it('flags a missing license', async () => {
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0' }))).toContain('LIC-MISSING-001');
  });

  it('flags UNLICENSED that is not private', async () => {
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: 'UNLICENSED' }))).toContain('LIC-UNLICENSED-NOT-PRIVATE-001');
  });

  it('notes a declared strong-copyleft license', async () => {
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: 'GPL-3.0-only' }))).toContain('LIC-COPYLEFT-DECLARED-001');
  });

  it('flags a non-SPDX license identifier', async () => {
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: 'Proprietary' }))).toContain('LIC-NONSTANDARD-001');
  });

  it('accepts valid SPDX, SPDX expressions, and private+UNLICENSED without findings', async () => {
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: 'MIT' })).size).toBe(0);
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: '(MIT OR Apache-2.0)' })).size).toBe(0);
    expect(licRules(await scanPkg({ name: 'x', version: '1.0.0', license: 'UNLICENSED', private: true })).size).toBe(0);
  });
});
