/**
 * ComposeScanner — docker-compose service misconfiguration checks (CloudIaCPosture dimension).
 * Spec ref: §V.18 (Container/cloud/DevOps quality; compose/K8s; CIS Docker Benchmark).
 *
 * Deterministic (§0.2.2): parses a compose file's `services` and flags high-impact risks — privileged
 * services, Docker socket mounts (container escape), host networking, sensitive host bind mounts,
 * dangerous capabilities, unpinned images, hardcoded secrets (redacted), and missing no-new-privileges.
 */

import { parseDocument } from 'yaml';
import type { Finding } from '@qa/core';
import { redact, redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, imageUnpinned, sha256 } from './util.js';

const CHECK_CATEGORIES = 8;
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'NET_RAW', 'SYS_TIME']);
const SENSITIVE_HOST_PATHS = new Set(['/', '/etc', '/root', '/var/run', '/var/lib/docker', '/usr', '/boot']);
const SECRET_KEY = /(PASSWORD|PASSWD|SECRET|API[_-]?KEY|TOKEN|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)/i;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const rec = (v: unknown): Record<string, unknown> => (isRecord(v) ? v : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const bool = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);

function isComposeFile(f: ProjectFile): boolean {
  const base = (f.path.split('/').pop() ?? '').toLowerCase();
  return /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base);
}

/** Extract "source" paths from short (`src:dst[:mode]`) and long ({source,target}) volume syntax. */
function volumeSources(volumes: unknown[]): string[] {
  const out: string[] = [];
  for (const v of volumes) {
    const s = str(v);
    if (s) {
      // Named volume ("name:/path") vs bind ("/host:/path"). Take the part before the first ':'.
      out.push(s.split(':')[0] ?? s);
    } else if (isRecord(v)) {
      const src = str(v.source);
      if (src) out.push(src);
    }
  }
  return out;
}

/** environment may be a map {K: v} or a list ["K=v"]. Return [key, value] pairs. */
function envEntries(env: unknown): Array<[string, string]> {
  if (isRecord(env)) return Object.entries(env).map(([k, v]) => [k, v == null ? '' : String(v)]);
  return arr(env)
    .map((e) => str(e))
    .filter((e): e is string => Boolean(e))
    .map((e) => {
      const eq = e.indexOf('=');
      return eq === -1 ? ([e, ''] as [string, string]) : ([e.slice(0, eq), e.slice(eq + 1)] as [string, string]);
    });
}

export class ComposeScanner implements Engine {
  readonly name = 'compose-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'CloudIaCPosture' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isComposeFile);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;
    let services = 0;

    const addArtifact = (key: string, content: string): string => {
      const red = redact(content);
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content: red.text, contentHash: sha256(red.text), redactedClasses: red.redactedClasses });
      return id;
    };

    for (const file of ctx.files.filter(isComposeFile)) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      let doc: unknown;
      try {
        doc = parseDocument(content).toJS({ maxAliasCount: 100 });
      } catch {
        continue;
      }
      const svcMap = rec(rec(doc).services);
      for (const [svcName, svcUnknown] of Object.entries(svcMap)) {
        const svc = rec(svcUnknown);
        services++;
        const resource = `service ${svcName}`;
        const evd = (field: string, value: string) => addArtifact(`${file.path}:${svcName}:${field}`, `File: ${file.path}\n${resource}\n${field}: ${value}`);
        const push = (rule: string, title: string, severity: Finding['severity'], status: Finding['status'], desc: string, art: string, fix: string, cwe: string[]) =>
          findings.push(this.mk(findingId(rule, ordinal++), rule, title, severity, status, { file: file.path }, resource, desc, art, fix, cwe));

        // 1) privileged
        if (bool(svc.privileged) === true) {
          push('IAC-COMPOSE-PRIV-001', `Privileged service: ${svcName}`, 'Critical', 'FAIL',
            `${resource} runs privileged, granting near-host-root access — effectively a container escape.`,
            evd('privileged', 'true'), 'Remove `privileged: true`; grant only the specific capabilities required.', ['CWE-250']);
        }

        // 2) Docker socket mount + 3) sensitive host bind mounts
        const sources = volumeSources(arr(svc.volumes));
        if (sources.some((s) => s === '/var/run/docker.sock')) {
          push('IAC-COMPOSE-DOCKERSOCK-001', `Docker socket mounted into ${svcName}`, 'Critical', 'FAIL',
            `${resource} mounts \`/var/run/docker.sock\`. Access to the Docker socket is equivalent to root on the host — a full container escape.`,
            evd('volumes', '/var/run/docker.sock'), 'Do not mount the Docker socket; use a scoped API proxy or rootless tooling if container control is required.', ['CWE-250']);
        }
        const sensitive = sources.filter((s) => SENSITIVE_HOST_PATHS.has(s));
        if (sensitive.length > 0) {
          push('IAC-COMPOSE-HOSTMOUNT-001', `Sensitive host path mounted into ${svcName}`, 'High', 'FAIL',
            `${resource} bind-mounts sensitive host path(s) (${sensitive.join(', ')}), exposing the host filesystem to the container.`,
            evd('volumes', sensitive.join(', ')), 'Mount only the specific directories required, read-only where possible.', ['CWE-668']);
        }

        // 4) host network mode
        if (str(svc.network_mode) === 'host') {
          push('IAC-COMPOSE-HOSTNET-001', `Host network mode: ${svcName}`, 'High', 'FAIL',
            `${resource} uses \`network_mode: host\`, removing network isolation between the container and the host.`,
            evd('network_mode', 'host'), 'Use a user-defined bridge network and publish only the required ports.', ['CWE-668']);
        }

        // 5) dangerous capabilities
        const caps = arr(svc.cap_add).map((c) => str(c)?.toUpperCase()).filter((c): c is string => Boolean(c));
        const dangerous = caps.filter((c) => DANGEROUS_CAPS.has(c));
        if (dangerous.length > 0) {
          push('IAC-COMPOSE-CAP-001', `Dangerous capabilities added to ${svcName}: ${dangerous.join(', ')}`, 'High', 'FAIL',
            `${resource} adds high-risk capabilities (${dangerous.join(', ')}) that can be used to escape the container or tamper with the host.`,
            evd('cap_add', dangerous.join(', ')), 'Drop capabilities and add back only the minimal set required.', ['CWE-250']);
        }

        // 6) unpinned image
        const image = str(svc.image);
        if (image) {
          const unpinned = imageUnpinned(image);
          if (unpinned) {
            push('IAC-COMPOSE-IMGTAG-001', `Unpinned image in ${svcName}: ${image}`, 'Medium', 'FAIL',
              `${resource} uses ${unpinned === 'latest' ? 'the :latest tag' : 'an untagged image'} (\`${image}\`), which is not reproducible.`,
              evd('image', image), 'Pin the image to a specific version and ideally a digest.', ['CWE-1104']);
          }
        }

        // 7) hardcoded secrets in environment
        for (const [k, v] of envEntries(svc.environment)) {
          if (SECRET_KEY.test(k) && v.trim() !== '' && !v.startsWith('${')) {
            push('IAC-COMPOSE-SECRET-001', `Hardcoded secret in ${svcName} environment`, 'High', 'FAIL',
              `${resource} sets a secret-looking environment variable (\`${k}\`) to an inline value. The value has been redacted in evidence.`,
              evd(`environment.${k}`, redactedSnippet(`${k}=${v}`)), 'Reference secrets via `${VAR}` from an untracked .env / secrets manager, never inline.', ['CWE-798']);
            break; // one finding per service is enough to flag the pattern
          }
        }

        // 8) missing no-new-privileges
        const secOpt = arr(svc.security_opt).map((s) => str(s) ?? '').join(' ');
        if (!/no-new-privileges\s*[:=]\s*true/i.test(secOpt)) {
          push('IAC-COMPOSE-NNP-001', `no-new-privileges not set for ${svcName}`, 'Medium', 'FAIL',
            `${resource} does not set \`security_opt: ["no-new-privileges:true"]\`, allowing processes to gain privileges via setuid binaries.`,
            evd('security_opt', 'missing no-new-privileges'), 'Add `security_opt: ["no-new-privileges:true"]` to the service.', ['CWE-250']);
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(services * CHECK_CATEGORIES, 1),
      executedChecks: services * CHECK_CATEGORIES,
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
    affectedComponent: string,
    description: string,
    artifactId: string,
    remediation: string,
    cwe: string[],
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CloudIaC',
      subcategory: 'DockerCompose',
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
      affectedComponent,
      location,
      detectionMethod: 'config',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'configuration', ref: artifactId, redacted: true }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'Critical' || severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-scan the compose file after remediation.',
      standards: [{ framework: 'CIS Docker Benchmark', version: 'latest', id: '5.x' }, ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : [])],
      traceability: { requirements: [], tests: [] },
    };
  }
}
