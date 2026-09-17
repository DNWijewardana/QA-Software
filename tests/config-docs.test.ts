/**
 * ConfigDocsScanner test (§V.29). Builds temp projects (so committed .env files aren't needed) and checks
 * README/LICENSE presence, committed env files, and undocumented required configuration.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

async function scanProject(files: Record<string, string>) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-cfg-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.writeFile(path.join(dir, name), content, 'utf8');
  }
  const result = await runScan({ scanId: 's', projectDir: dir, evidenceDir: path.join(dir, 'ev') });
  await fs.rm(dir, { recursive: true, force: true });
  return result;
}

describe('ConfigDocsScanner (§V.29)', () => {
  it('flags missing README/LICENSE, a committed .env, and undocumented env config', async () => {
    const result = await scanProject({
      'app.js': 'const url = process.env.API_URL;\nmodule.exports = { url };\n',
      '.env': 'API_URL=https://api.example.com\n',
    });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules).toContain('DOC-README-001');
    expect(rules).toContain('DOC-LICENSE-001');
    expect(rules).toContain('CFG-ENV-COMMITTED-001');
    expect(rules).toContain('CFG-NO-ENV-EXAMPLE-001');
    expect(result.scores.some((s) => s.dimension === 'Maintainability')).toBe(true);
  });

  it('produces no config/docs findings for a well-formed project', async () => {
    const result = await scanProject({
      'README.md': '# My Project\nSetup and run instructions.\n',
      LICENSE: 'MIT License\n',
      '.env.example': 'API_URL=https://example.com\n',
      'app.js': 'const url = process.env.API_URL;\nmodule.exports = { url };\n',
    });
    const cfgDoc = result.findings.filter((f) => f.ruleId.startsWith('DOC-') || f.ruleId.startsWith('CFG-'));
    expect(cfgDoc).toHaveLength(0);
  });
});
