/**
 * DockerfileScanner — container build misconfiguration checks (CloudIaCPosture dimension).
 * Spec ref: §V.18 (Container/cloud/DevOps quality; IaC scanning, CIS Benchmarks), §IV.2 (CIS).
 *
 * Deterministic (§0.2.2): parses Dockerfile instructions and flags CIS-aligned misconfigurations.
 * Evidence snippets are redacted (§VIII.10). This covers Dockerfiles; Terraform/K8s/Helm scanners
 * plug in later behind the same Engine interface.
 */

import type { Finding } from '@qa/core';
import { redact, redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ScanContext, ProjectFile } from './types.js';
import { findingId, sha256 } from './util.js';

/** One logical instruction (line continuations joined), with the 1-based start line. */
interface Instruction {
  keyword: string; // uppercased, e.g. FROM, RUN, USER
  args: string;
  line: number;
  raw: string;
}

function isDockerfile(f: ProjectFile): boolean {
  const base = f.path.split('/').pop() ?? '';
  return base === 'Dockerfile' || base.endsWith('.Dockerfile') || base.startsWith('Dockerfile.');
}

/** Parse a Dockerfile into logical instructions, joining `\`-continued lines. */
function parse(content: string): Instruction[] {
  const rawLines = content.split(/\r?\n/);
  const out: Instruction[] = [];
  let i = 0;
  while (i < rawLines.length) {
    const startLine = i + 1;
    let text = rawLines[i] ?? '';
    // Skip blank lines and comments.
    const trimmed = text.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      i++;
      continue;
    }
    // Join continuations.
    const rawParts = [text];
    while (/\\\s*$/.test(text) && i + 1 < rawLines.length) {
      i++;
      text = rawLines[i] ?? '';
      rawParts.push(text);
    }
    i++;
    const joined = rawParts.map((p) => p.replace(/\\\s*$/, ' ')).join(' ').trim();
    const m = /^(\S+)\s*(.*)$/.exec(joined);
    if (!m) continue;
    out.push({ keyword: m[1]!.toUpperCase(), args: m[2]!.trim(), line: startLine, raw: rawParts.join('\n') });
  }
  return out;
}

const SECRET_KEY = /\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API[_-]?KEY|TOKEN|ACCESS[_-]?KEY|PRIVATE[_-]?KEY))\b\s*=/i;

export class DockerfileScanner implements Engine {
  readonly name = 'dockerfile-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'CloudIaCPosture' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isDockerfile);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const dockerfiles = ctx.files.filter(isDockerfile);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): { id: string; classes: Record<string, number> } => {
      const red = redact(content);
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content: red.text, contentHash: sha256(red.text), redactedClasses: red.redactedClasses });
      return { id, classes: red.redactedClasses };
    };

    for (const file of dockerfiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const instructions = parse(content);
      const stageNames = new Set<string>();
      for (const ins of instructions) {
        if (ins.keyword === 'FROM') {
          const asMatch = /\bAS\s+(\S+)\s*$/i.exec(ins.args);
          if (asMatch) stageNames.add(asMatch[1]!.toLowerCase());
        }
      }

      executed += 7; // seven check categories run per Dockerfile

      // 1) Base image tag: latest / untagged / stage-ref exempt.
      for (const ins of instructions.filter((x) => x.keyword === 'FROM')) {
        const imageRef = ins.args.split(/\s+/)[0] ?? '';
        const image = imageRef.split(/\s+/)[0]!;
        const nameNoAs = image;
        const lower = nameNoAs.toLowerCase();
        if (lower === 'scratch' || stageNames.has(lower)) continue;
        const hasDigest = nameNoAs.includes('@');
        const tag = nameNoAs.includes(':') ? nameNoAs.split(':').pop() : undefined;
        if (!hasDigest && (tag === undefined || tag === 'latest')) {
          const art = addArtifact(`${file.path}:${ins.line}:tag`, `${file.path}:${ins.line}\n${redactedSnippet(ins.raw)}`);
          findings.push(this.mk(findingId('IAC-DOCKER-TAG-001', ordinal++), 'IAC-DOCKER-TAG-001', `Unpinned base image: ${nameNoAs}`, 'Medium', 'FAIL', { file: file.path, line: ins.line },
            `Base image \`${nameNoAs}\` is ${tag === 'latest' ? 'tagged :latest' : 'untagged'} and not digest-pinned. Builds are non-reproducible and may silently pull a changed or compromised image.`,
            art.id, 'Pin the base image to a specific version and ideally a digest (e.g. `node:18.20.4-alpine@sha256:...`).', ['CWE-1104'], 'CIS Docker 4.x'));
        }
      }

      // 2) Runs as root (no non-root USER as the effective final user).
      const users = instructions.filter((x) => x.keyword === 'USER');
      const lastUser = users.length ? (users[users.length - 1]!.args.split(/\s+/)[0] ?? '') : '';
      const runsAsRoot = users.length === 0 || lastUser === 'root' || lastUser === '0';
      if (runsAsRoot) {
        const anchorLine = instructions.find((x) => x.keyword === 'FROM')?.line ?? 1;
        const art = addArtifact(`${file.path}:user`, `${file.path}: ${users.length === 0 ? 'no USER instruction' : `final USER is ${lastUser}`}`);
        findings.push(this.mk(findingId('IAC-DOCKER-USER-001', ordinal++), 'IAC-DOCKER-USER-001', 'Container runs as root', 'High', 'FAIL', { file: file.path, line: anchorLine },
          `The image ${users.length === 0 ? 'declares no USER' : `resets to \`${lastUser}\``}, so the container runs as root. A root container escalates the blast radius of any compromise.`,
          art.id, 'Create and switch to a non-root user (`RUN adduser ...` then `USER app`).', ['CWE-250'], 'CIS Docker 4.1'));
      }

      // 3) Remote-piped-to-shell in a RUN.
      for (const ins of instructions.filter((x) => x.keyword === 'RUN')) {
        if (/(curl|wget)\b[^\n|]*\|\s*(sh|bash)\b/i.test(ins.args)) {
          const art = addArtifact(`${file.path}:${ins.line}:curlbash`, `${file.path}:${ins.line}\n${redactedSnippet(ins.args)}`);
          findings.push(this.mk(findingId('IAC-DOCKER-CURLBASH-001', ordinal++), 'IAC-DOCKER-CURLBASH-001', 'Remote script piped into a shell during build', 'High', 'FAIL', { file: file.path, line: ins.line },
            'A RUN step downloads a remote script and pipes it straight into a shell. There is no integrity check, so a compromised or MITM-ed URL executes arbitrary code in the build.',
            art.id, 'Download to a file, verify a checksum/signature, then execute; or install from a pinned package.', ['CWE-494'], 'CIS Docker 4.x'));
        }
      }

      // 4) ADD (esp. remote) where COPY is safer.
      for (const ins of instructions.filter((x) => x.keyword === 'ADD')) {
        const remote = /https?:\/\//i.test(ins.args);
        const art = addArtifact(`${file.path}:${ins.line}:add`, `${file.path}:${ins.line}\n${redactedSnippet(ins.args)}`);
        findings.push(this.mk(findingId('IAC-DOCKER-ADD-001', ordinal++), 'IAC-DOCKER-ADD-001', remote ? 'ADD fetches a remote URL' : "Use of ADD where COPY is preferred", remote ? 'Medium' : 'Low', 'WARNING', { file: file.path, line: ins.line },
          remote ? 'ADD with a remote URL fetches unverified content and auto-extracts archives — an injection and supply-chain risk. Prefer COPY, or fetch-and-verify explicitly.' : 'ADD has implicit behavior (URL fetch, archive extraction). Prefer COPY for local files to keep behavior explicit.',
          art.id, 'Replace ADD with COPY for local files; for remote content, download and verify a checksum in a RUN step.', ['CWE-494'], 'CIS Docker 4.9'));
      }

      // 5) Hardcoded secret in ENV/ARG.
      for (const ins of instructions.filter((x) => x.keyword === 'ENV' || x.keyword === 'ARG')) {
        if (SECRET_KEY.test(ins.args) && /=\s*\S/.test(ins.args)) {
          const art = addArtifact(`${file.path}:${ins.line}:secret`, `${file.path}:${ins.line}\n${redactedSnippet(ins.raw)}`);
          findings.push(this.mk(findingId('IAC-DOCKER-SECRET-001', ordinal++), 'IAC-DOCKER-SECRET-001', 'Hardcoded secret in ENV/ARG', 'High', 'FAIL', { file: file.path, line: ins.line },
            'A secret-looking value is baked into an image layer via ENV/ARG. It persists in the image history and is recoverable by anyone who can pull the image. The value has been redacted in evidence.',
            art.id, 'Inject secrets at runtime (orchestrator secrets / --secret mounts), never bake them into the image.', ['CWE-798'], 'CIS Docker 4.10'));
        }
      }

      // 6) Missing HEALTHCHECK (informational — reliability/observability).
      if (!instructions.some((x) => x.keyword === 'HEALTHCHECK')) {
        const art = addArtifact(`${file.path}:healthcheck`, `${file.path}: no HEALTHCHECK instruction`);
        findings.push(this.mk(findingId('IAC-DOCKER-HEALTHCHECK-000', ordinal++), 'IAC-DOCKER-HEALTHCHECK-000', 'No HEALTHCHECK defined', 'Informational', 'WARNING', { file: file.path },
          'The image defines no HEALTHCHECK, so orchestrators cannot detect an unhealthy-but-running container.',
          art.id, 'Add a HEALTHCHECK instruction (or define readiness/liveness probes in the orchestrator).', [], 'CIS Docker 4.6'));
      }

      // 7) apt-get install without cleaning the lists in the same layer.
      for (const ins of instructions.filter((x) => x.keyword === 'RUN')) {
        if (/\bapt(-get)?\s+install\b/i.test(ins.args) && !/rm\s+-rf\s+\/var\/lib\/apt\/lists/i.test(ins.args)) {
          const art = addArtifact(`${file.path}:${ins.line}:apt`, `${file.path}:${ins.line}\n${redactedSnippet(ins.args)}`);
          findings.push(this.mk(findingId('IAC-DOCKER-APTCLEAN-001', ordinal++), 'IAC-DOCKER-APTCLEAN-001', 'apt install without cache cleanup', 'Low', 'WARNING', { file: file.path, line: ins.line },
            'An apt install in this layer does not remove `/var/lib/apt/lists/*`, bloating the image and the attack surface.',
            art.id, 'Append `&& rm -rf /var/lib/apt/lists/*` to the same RUN (and use `--no-install-recommends`).', [], 'CIS Docker 4.x'));
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(dockerfiles.length * 7, 1),
      executedChecks: executed,
      findings,
      artifacts,
    };
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    status: Finding['status'],
    location: Finding['location'],
    description: string,
    artifactId: string,
    remediation: string,
    cwe: string[],
    cisId: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CloudIaC',
      subcategory: 'Dockerfile',
      title,
      description,
      status,
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Highly likely',
      reproducibility: 'Always',
      cwe,
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'config',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: true }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'Informational' || severity === 'Low' ? 'Low' : 'Medium' },
      verificationMethod: 'Re-scan the Dockerfile after remediation.',
      standards: [
        { framework: 'CIS Docker Benchmark', version: 'latest', id: cisId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
