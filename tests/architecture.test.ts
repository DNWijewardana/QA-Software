/**
 * ArchitectureScanner test (§V.10). Confirms import-cycle detection (CWE-1047), deep-relative-import
 * detection on the committed fixture, god-module detection on a runtime temp project, and no false
 * positives on a clean, acyclic, shallow project.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/bad-architecture', import.meta.url));
const tmps: string[] = [];
afterAll(async () => {
  await Promise.all(tmps.map((t) => fs.rm(t, { recursive: true, force: true })));
});

async function mkTmp(prefix: string): Promise<string> {
  const t = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tmps.push(t);
  return t;
}

describe('ArchitectureScanner (§V.10)', () => {
  it('detects an import cycle and a deep relative import', async () => {
    const ev = await mkTmp('qa-arch-');
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_arch', evidenceDir: path.join(ev, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = result.findings.map((f) => f.ruleId);
    expect(rules).toContain('ARCH-CIRCULAR-DEP-001');
    expect(rules).toContain('ARCH-DEEP-RELATIVE-IMPORT-001');

    const cycle = result.findings.find((f) => f.ruleId === 'ARCH-CIRCULAR-DEP-001');
    expect(cycle?.severity).toBe('Medium');
    expect(cycle?.cwe).toContain('CWE-1047');
    // The a→b→c→a cycle is a single distinct cycle → reported once.
    expect(rules.filter((r) => r === 'ARCH-CIRCULAR-DEP-001')).toHaveLength(1);
    // Architecture findings score under Maintainability (§V.10).
    expect(result.scores.some((s) => s.dimension === 'Maintainability')).toBe(true);
  });

  it('flags a god module (excessive internal fan-out)', async () => {
    const dir = await mkTmp('qa-arch-god-');
    const src = path.join(dir, 'src');
    await fs.mkdir(src, { recursive: true });
    const imports: string[] = [];
    for (let i = 0; i < 16; i++) {
      await fs.writeFile(path.join(src, `m${i}.ts`), `export const m${i} = ${i};\n`, 'utf8');
      imports.push(`import { m${i} } from './m${i}.js';`);
    }
    await fs.writeFile(path.join(src, 'god.ts'), `${imports.join('\n')}\nexport const all = [${Array.from({ length: 16 }, (_, i) => `m${i}`).join(', ')}];\n`, 'utf8');
    const result = await runScan({ projectDir: dir, scanId: 'scan_arch_god', evidenceDir: path.join(dir, 'ev') });
    const god = result.findings.find((f) => f.ruleId === 'ARCH-GOD-MODULE-001');
    expect(god).toBeDefined();
    expect(god?.affectedComponent).toContain('god.ts');
  });

  it('produces no architecture findings for a clean, acyclic, shallow project', async () => {
    const dir = await mkTmp('qa-arch-ok-');
    const src = path.join(dir, 'src');
    await fs.mkdir(src, { recursive: true });
    await fs.writeFile(path.join(src, 'index.ts'), `import { util } from './util.js';\nexport const run = () => util();\n`, 'utf8');
    await fs.writeFile(path.join(src, 'util.ts'), `export const util = () => 42;\n`, 'utf8');
    const result = await runScan({ projectDir: dir, scanId: 'scan_arch_ok', evidenceDir: path.join(dir, 'ev') });
    expect(result.findings.some((f) => f.ruleId.startsWith('ARCH-'))).toBe(false);
  });
});
