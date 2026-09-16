/**
 * KubernetesScanner — workload manifest security checks (CloudIaCPosture dimension).
 * Spec ref: §V.18 (Kubernetes workloads, pod security standards, network policies, CIS Benchmarks).
 *
 * Deterministic (§0.2.2): parses YAML manifests and evaluates each workload's pod spec against
 * CIS Kubernetes Benchmark / Pod Security Standards. Non-k8s YAML (no kind/apiVersion) is ignored,
 * so this never flags unrelated YAML (e.g. CI workflows).
 */

import { parseAllDocuments } from 'yaml';
import type { Finding } from '@qa/core';
import { redact } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, imageUnpinned, sha256 } from './util.js';

const CHECK_CATEGORIES = 11;
const DANGEROUS_CAPS = new Set(['ALL', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'NET_RAW', 'SYS_TIME']);
const WORKLOAD_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob']);

// ---- typed accessors over parsed YAML (unknown) --------------------------------------------------
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const rec = (v: unknown): Record<string, unknown> => (isRecord(v) ? v : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const bool = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

interface Workload {
  kind: string;
  name: string;
  podSpec: Record<string, unknown>;
}

function extractWorkload(doc: unknown): Workload | null {
  const d = rec(doc);
  const kind = str(d.kind);
  const apiVersion = str(d.apiVersion);
  if (!kind || !apiVersion || !WORKLOAD_KINDS.has(kind)) return null;
  const name = str(rec(d.metadata).name) ?? '(unnamed)';
  const spec = rec(d.spec);
  let podSpec: Record<string, unknown>;
  if (kind === 'Pod') podSpec = spec;
  else if (kind === 'CronJob') podSpec = rec(rec(rec(rec(spec.jobTemplate).spec).template).spec);
  else podSpec = rec(rec(spec.template).spec);
  if (arr(podSpec.containers).length === 0) return null;
  return { kind, name, podSpec };
}

function runsAsNonRoot(sc: Record<string, unknown>, podSC: Record<string, unknown>): boolean {
  if (bool(sc.runAsNonRoot) === true || bool(podSC.runAsNonRoot) === true) return true;
  const cUser = num(sc.runAsUser);
  const pUser = num(podSC.runAsUser);
  return (cUser !== undefined && cUser > 0) || (pUser !== undefined && pUser > 0);
}

export class KubernetesScanner implements Engine {
  readonly name = 'kubernetes-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'CloudIaCPosture' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isYaml);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;
    let workloadDocs = 0;

    const addArtifact = (key: string, content: string): string => {
      const red = redact(content);
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'configuration', content: red.text, contentHash: sha256(red.text), redactedClasses: red.redactedClasses });
      return id;
    };

    for (const file of ctx.files.filter(isYaml)) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      let docs: unknown[];
      try {
        docs = parseAllDocuments(content).map((d) => d.toJS({ maxAliasCount: 100 }));
      } catch {
        continue; // not valid YAML — ignore (not our concern here)
      }

      for (const doc of docs) {
        const wl = extractWorkload(doc);
        if (!wl) continue;
        workloadDocs++;
        const podSpec = wl.podSpec;
        const podSC = rec(podSpec.securityContext);
        const resource = `${wl.kind}/${wl.name}`;
        const evd = (field: string, value: string) => addArtifact(`${file.path}:${resource}:${field}`, `File: ${file.path}\nResource: ${resource}\n${field}: ${value}`);
        const push = (rule: string, title: string, severity: Finding['severity'], status: Finding['status'], desc: string, art: string, fix: string, cwe: string[], cis: string) =>
          findings.push(this.mk(findingId(rule, ordinal++), rule, title, severity, status, { file: file.path }, resource, desc, art, fix, cwe, cis));

        // ---- pod-level checks ----
        for (const ns of ['hostNetwork', 'hostPID', 'hostIPC'] as const) {
          if (bool(podSpec[ns]) === true) {
            push('IAC-K8S-HOSTNS-001', `${ns} enabled`, 'High', 'FAIL',
              `${resource} sets \`${ns}: true\`, sharing the host namespace and breaking pod isolation.`,
              evd(ns, 'true'), `Remove \`${ns}: true\` unless absolutely required and compensated by other controls.`, ['CWE-668'], 'CIS K8s 5.2.4');
          }
        }
        if (arr(podSpec.volumes).some((v) => isRecord(rec(v).hostPath))) {
          push('IAC-K8S-HOSTPATH-001', 'hostPath volume mounted', 'Medium', 'FAIL',
            `${resource} mounts a hostPath volume, exposing the node filesystem to the container.`,
            evd('volumes', 'hostPath'), 'Avoid hostPath; use PVCs, configMaps, or emptyDir as appropriate.', ['CWE-668'], 'CIS K8s 5.2.4');
        }
        if (bool(podSpec.automountServiceAccountToken) !== false) {
          push('IAC-K8S-SATOKEN-001', 'ServiceAccount token auto-mounted', 'Low', 'WARNING',
            `${resource} does not set \`automountServiceAccountToken: false\`; the API token is mounted even if unused, widening the blast radius of a compromise.`,
            evd('automountServiceAccountToken', 'not false'), 'Set `automountServiceAccountToken: false` unless the workload calls the Kubernetes API.', ['CWE-250'], 'CIS K8s 5.1.6');
        }

        // ---- container-level checks ----
        const containers = [...arr(podSpec.containers), ...arr(podSpec.initContainers)];
        let anyMissingProbe = false;
        for (const cUnknown of containers) {
          const c = rec(cUnknown);
          const cname = str(c.name) ?? '(unnamed)';
          const sc = rec(c.securityContext);
          const where = `${resource} container=${cname}`;

          if (bool(sc.privileged) === true) {
            push('IAC-K8S-PRIV-001', 'Privileged container', 'Critical', 'FAIL',
              `${where} runs privileged, granting near-host-root access — effectively a container escape.`,
              evd(`${cname}.privileged`, 'true'), 'Remove `privileged: true`; grant only the specific capabilities required.', ['CWE-250'], 'CIS K8s 5.2.1');
          }
          if (bool(sc.allowPrivilegeEscalation) !== false) {
            push('IAC-K8S-PRIVESC-001', 'Privilege escalation not disabled', 'Medium', 'FAIL',
              `${where} does not set \`allowPrivilegeEscalation: false\`, allowing a process to gain more privileges than its parent.`,
              evd(`${cname}.allowPrivilegeEscalation`, 'not false'), 'Set `allowPrivilegeEscalation: false` in the container securityContext.', ['CWE-250'], 'CIS K8s 5.2.5');
          }
          if (!runsAsNonRoot(sc, podSC)) {
            push('IAC-K8S-ROOT-001', 'Container may run as root', 'High', 'FAIL',
              `${where} does not enforce a non-root user (no runAsNonRoot/runAsUser>0 at pod or container level).`,
              evd(`${cname}.runAsNonRoot`, 'unset'), 'Set `securityContext.runAsNonRoot: true` (and a numeric runAsUser).', ['CWE-250'], 'CIS K8s 5.2.6');
          }
          const caps = arr(rec(sc.capabilities).add).map((x) => str(x)?.toUpperCase()).filter((x): x is string => Boolean(x));
          const dangerous = caps.filter((c2) => DANGEROUS_CAPS.has(c2));
          if (dangerous.length > 0) {
            push('IAC-K8S-CAP-001', `Dangerous Linux capabilities added: ${dangerous.join(', ')}`, 'High', 'FAIL',
              `${where} adds high-risk capabilities (${dangerous.join(', ')}) that can be used to escape the container or tamper with the host.`,
              evd(`${cname}.capabilities`, dangerous.join(', ')), 'Drop ALL capabilities and add back only the minimal set required.', ['CWE-250'], 'CIS K8s 5.2.8');
          }
          if (bool(sc.readOnlyRootFilesystem) !== true) {
            push('IAC-K8S-ROFS-001', 'Root filesystem is writable', 'Low', 'WARNING',
              `${where} does not set \`readOnlyRootFilesystem: true\`; a compromised process can modify the container filesystem.`,
              evd(`${cname}.readOnlyRootFilesystem`, 'not true'), 'Set `readOnlyRootFilesystem: true` and mount writable paths explicitly.', [], 'CIS K8s 5.2.11');
          }
          const limits = rec(rec(c.resources).limits);
          if (limits.cpu === undefined || limits.memory === undefined) {
            push('IAC-K8S-LIMITS-001', 'Missing CPU/memory limits', 'Medium', 'FAIL',
              `${where} does not define both CPU and memory limits, so it can exhaust node resources (DoS / noisy neighbour).`,
              evd(`${cname}.resources.limits`, 'incomplete'), 'Set `resources.limits.cpu` and `resources.limits.memory` (and matching requests).', ['CWE-770'], 'CIS K8s 5.x');
          }
          const image = str(c.image);
          if (image) {
            const unpinned = imageUnpinned(image);
            if (unpinned) {
              push('IAC-K8S-IMGTAG-001', `Unpinned image: ${image}`, 'Medium', 'FAIL',
                `${where} uses ${unpinned === 'latest' ? 'the :latest tag' : 'an untagged image'} (\`${image}\`), which is not reproducible and may pull a changed image.`,
                evd(`${cname}.image`, image), 'Pin the image to a specific version and ideally a digest.', ['CWE-1104'], 'CIS K8s 5.x');
            }
          }
          if (!isRecord(c.livenessProbe) || !isRecord(c.readinessProbe)) anyMissingProbe = true;
        }
        if (anyMissingProbe) {
          push('IAC-K8S-PROBES-000', 'Missing liveness/readiness probes', 'Informational', 'WARNING',
            `${resource} has a container without both liveness and readiness probes, so Kubernetes cannot reliably detect an unhealthy pod.`,
            evd('probes', 'incomplete'), 'Define livenessProbe and readinessProbe for each long-running container.', [], 'CIS K8s 5.x');
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(workloadDocs * CHECK_CATEGORIES, 1),
      executedChecks: workloadDocs * CHECK_CATEGORIES,
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
    cisId: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'CloudIaC',
      subcategory: 'Kubernetes',
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
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'Critical' || severity === 'High' ? 'High' : severity === 'Medium' ? 'Medium' : 'Low' },
      verificationMethod: 'Re-scan the manifest after remediation.',
      standards: [
        { framework: 'CIS Kubernetes Benchmark', version: 'latest', id: cisId },
        { framework: 'Pod Security Standards', version: 'restricted', id: ruleId },
        ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : []),
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}

function isYaml(f: ProjectFile): boolean {
  return /\.ya?ml$/i.test(f.path);
}
