/**
 * ComposeScanner test (§V.18). Scans the intentionally-insecure docker-compose fixture and confirms each
 * seeded misconfiguration is detected, the secret is redacted, the privileged service + socket mount force
 * NO_GO, and the Docker-socket compliance control (CIS Docker 5.31) is a GAP. Isolated fixture.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '@qa/orchestrator';
import { validateScanResult } from '@qa/contracts';

const fixtureDir = fileURLToPath(new URL('../fixtures/insecure-compose', import.meta.url));
let tmp: string;
afterAll(async () => {
  if (tmp) await fs.rm(tmp, { recursive: true, force: true });
});

describe('ComposeScanner (docker-compose)', () => {
  it('detects every seeded compose misconfiguration and blocks release', async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'qa-compose-'));
    const result = await runScan({ projectDir: fixtureDir, scanId: 'scan_compose', evidenceDir: path.join(tmp, 'ev') });
    expect(() => validateScanResult(result)).not.toThrow();

    const rules = new Set(result.findings.map((f) => f.ruleId));
    for (const expected of [
      'IAC-COMPOSE-PRIV-001',
      'IAC-COMPOSE-DOCKERSOCK-001',
      'IAC-COMPOSE-HOSTMOUNT-001',
      'IAC-COMPOSE-HOSTNET-001',
      'IAC-COMPOSE-CAP-001',
      'IAC-COMPOSE-IMGTAG-001',
      'IAC-COMPOSE-SECRET-001',
      'IAC-COMPOSE-NNP-001',
    ]) {
      expect(rules, `missing ${expected}`).toContain(expected);
    }

    const sock = result.findings.find((f) => f.ruleId === 'IAC-COMPOSE-DOCKERSOCK-001');
    expect(sock?.severity).toBe('Critical');
    expect(result.releaseDecision.decision).toBe('NO_GO');

    // The Docker-socket compliance control is assessed and shows a gap.
    const ctrl = result.compliance?.controls.find((c) => c.controlId === '5.31');
    expect(ctrl?.status).toBe('GAPS');
  });

  it('never leaks the raw secret into evidence (§VIII.10)', async () => {
    const evDir = path.join(tmp, 'ev');
    for (const file of await fs.readdir(evDir)) {
      const content = await fs.readFile(path.join(evDir, file), 'utf8');
      expect(content).not.toContain('supersecret123');
    }
  });
});
