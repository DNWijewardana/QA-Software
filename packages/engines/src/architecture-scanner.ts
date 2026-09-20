/**
 * ArchitectureScanner — static architecture-quality checks over the JS/TS module import graph (§V.10).
 * Scores under the Maintainability dimension (the spec folds architecture quality under maintainability).
 *
 * Deterministic (§0.2.2): builds a project-wide import graph from `import`/`export … from`/`require()`/
 * dynamic `import()` of RELATIVE specifiers (bare package specifiers are external and ignored), resolving
 * TS-style `.js` specifiers back to their `.ts` source. Then:
 *  - ARCH-CIRCULAR-DEP-001  — import cycles (CWE-1047), Medium.
 *  - ARCH-GOD-MODULE-001    — a module with excessive outgoing internal dependencies (low cohesion), Low.
 *  - ARCH-DEEP-RELATIVE-IMPORT-001 — a relative import climbing ≥4 levels (weak module boundaries), Info.
 *
 * High-signal by construction: only relative imports that RESOLVE to a file in the project become graph
 * edges, so external packages and unresolved paths never create phantom cycles.
 */

import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

/** A module with more than this many outgoing INTERNAL dependencies is flagged as a god module (low cohesion). */
const FANOUT_THRESHOLD = 15;
/** A relative import climbing this many levels or more is a module-boundary smell. */
const DEEP_RELATIVE_LEVELS = 4;
/** Cap reported cycles to keep the report bounded on pathological graphs. */
const MAX_CYCLES = 50;

const JS_TS = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;
const EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

function isJsTs(f: ProjectFile): boolean {
  return JS_TS.test(f.path) && !/\.d\.ts$/i.test(f.path);
}

function stripComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1'); // keep the char before // (avoids eating `http://`-style only after a non-colon)
}

const IMPORT_RES = [
  /\b(?:import|export)\b[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g, // import/export … from '…'
  /\bimport\s*['"]([^'"]+)['"]/g, // side-effect import '…'
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // require('…')
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // dynamic import('…')
];

/** Extract the specifier strings referenced by a source file (relative + bare; caller filters). */
function extractSpecifiers(code: string): string[] {
  const out: string[] = [];
  const stripped = stripComments(code);
  for (const re of IMPORT_RES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(stripped)) !== null) out.push(m[1]!);
  }
  return out;
}

/** posix-normalize a path (resolve `.`/`..` segments) without touching the filesystem. */
function normalize(p: string): string {
  const parts = p.split('/');
  const stack: string[] = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (stack.length && stack[stack.length - 1] !== '..') stack.pop();
      else stack.push('..');
    } else {
      stack.push(part);
    }
  }
  return stack.join('/');
}

function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

function stripKnownExt(p: string): string {
  const m = p.match(JS_TS);
  return m ? p.slice(0, p.length - m[0].length) : p;
}

/** How many parent levels a relative specifier climbs (number of leading `../`). */
function relativeDepth(spec: string): number {
  let depth = 0;
  for (const seg of spec.split('/')) {
    if (seg === '..') depth++;
    else if (seg !== '.') break;
  }
  return depth;
}

export class ArchitectureScanner implements Engine {
  readonly name = 'architecture-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Maintainability' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isJsTs);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const files = ctx.files.filter(isJsTs);
    const known = new Set(files.map((f) => f.path));
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    // Resolve a relative specifier from `fromPath` to a known project file path, or null.
    const resolve = (fromPath: string, spec: string): string | null => {
      if (!spec.startsWith('.')) return null; // bare/package specifier → external
      const base = normalize(`${dirname(fromPath)}/${spec}`);
      const stem = stripKnownExt(base);
      const candidates = [base, ...EXTS.map((e) => stem + e), ...EXTS.map((e) => `${stem}/index${e}`)];
      for (const c of candidates) if (known.has(c)) return c;
      return null;
    };

    const graph = new Map<string, Set<string>>();
    const deepFindings: Array<{ file: string; spec: string }> = [];

    for (const file of files) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      executed += 1;
      const specs = extractSpecifiers(content);
      const edges = new Set<string>();
      for (const spec of specs) {
        if (relativeDepth(spec) >= DEEP_RELATIVE_LEVELS) deepFindings.push({ file: file.path, spec });
        const target = resolve(file.path, spec);
        if (target && target !== file.path) edges.add(target);
      }
      graph.set(file.path, edges);
    }

    // --- ARCH-GOD-MODULE-001: excessive outgoing internal dependencies (low cohesion) ---
    for (const [node, edges] of graph) {
      if (edges.size > FANOUT_THRESHOLD) {
        const art = addArtifact(`${node}:god`, `File: ${node}\nInternal module dependencies: ${edges.size} (threshold ${FANOUT_THRESHOLD})`);
        findings.push(
          this.mk(
            findingId('ARCH-GOD-MODULE-001', ordinal++),
            'ARCH-GOD-MODULE-001',
            'God module: excessive internal dependencies',
            'Low',
            `This module imports ${edges.size} other internal modules (threshold ${FANOUT_THRESHOLD}), a low-cohesion "god module" that concentrates coupling and becomes a change/fault hotspot.`,
            'Split the module along cohesive responsibilities; introduce facades/boundaries so callers depend on narrow interfaces.',
            'CWE-1048',
            { file: node },
            art,
            `${edges.size} internal dependencies (threshold ${FANOUT_THRESHOLD})`,
          ),
        );
      }
    }

    // --- ARCH-CIRCULAR-DEP-001: import cycles (CWE-1047) ---
    for (const cycle of this.findCycles(graph)) {
      const label = cycle.join(' → ') + ` → ${cycle[0]}`;
      const art = addArtifact(`cycle:${cycle.join('|')}`, `Import cycle:\n${label}`);
      findings.push(
        this.mk(
          findingId('ARCH-CIRCULAR-DEP-001', ordinal++),
          'ARCH-CIRCULAR-DEP-001',
          'Circular dependency between modules',
          'Medium',
          `These modules form an import cycle (${label}). Circular dependencies (CWE-1047) cause fragile initialization order, hinder testing/reuse, and are a maintainability risk.`,
          'Break the cycle by extracting the shared piece into a third module, inverting one dependency, or introducing an interface.',
          'CWE-1047',
          { file: cycle[0]! },
          art,
          label,
        ),
      );
    }

    // --- ARCH-DEEP-RELATIVE-IMPORT-001: deep relative imports (weak boundaries) ---
    for (const d of deepFindings) {
      const art = addArtifact(`${d.file}:deep:${d.spec}`, `File: ${d.file}\nDeep relative import: ${d.spec}`);
      findings.push(
        this.mk(
          findingId('ARCH-DEEP-RELATIVE-IMPORT-001', ordinal++),
          'ARCH-DEEP-RELATIVE-IMPORT-001',
          'Deep relative import (weak module boundary)',
          'Informational',
          `The import "${d.spec}" climbs ${relativeDepth(d.spec)} directory levels, a sign of leaky module boundaries and poor layering.`,
          'Introduce a package/path alias or a public module entry point instead of reaching across many directory levels.',
          'CWE-1047',
          { file: d.file },
          art,
          d.spec,
        ),
      );
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(files.length, 1),
      executedChecks: executed,
      findings,
      artifacts,
    };
  }

  /** Find distinct import cycles (canonicalized, deduplicated, capped). */
  private findCycles(graph: Map<string, Set<string>>): string[][] {
    const cycles: string[][] = [];
    const seen = new Set<string>();
    const inStack = new Set<string>();
    const stack: string[] = [];

    const canonical = (nodes: string[]): string => {
      // Rotate so the lexicographically smallest node leads → stable dedup key regardless of entry point.
      let min = 0;
      for (let i = 1; i < nodes.length; i++) if (nodes[i]! < nodes[min]!) min = i;
      return [...nodes.slice(min), ...nodes.slice(0, min)].join('|');
    };

    const dfs = (node: string): void => {
      if (cycles.length >= MAX_CYCLES) return;
      inStack.add(node);
      stack.push(node);
      for (const next of graph.get(node) ?? []) {
        if (inStack.has(next)) {
          const idx = stack.indexOf(next);
          if (idx >= 0) {
            const cyc = stack.slice(idx);
            const key = canonical(cyc);
            if (!seen.has(key)) {
              seen.add(key);
              cycles.push(cyc);
            }
          }
        } else if (!seen.has(`v:${next}`)) {
          dfs(next);
        }
      }
      stack.pop();
      inStack.delete(node);
    };

    for (const node of graph.keys()) dfs(node);
    return cycles.slice(0, MAX_CYCLES);
  }

  private mk(
    id: string,
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    desc: string,
    fix: string,
    cwe: string,
    location: Finding['location'],
    artifactId: string,
    snippet: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Architecture',
      subcategory: 'Module structure',
      title,
      description: desc,
      status: severity === 'Informational' ? 'WARNING' : severity === 'Low' ? 'WARNING' : 'FAIL',
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity,
      risk: severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe: [cwe],
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: fix, effort: 'M', riskReduction: 'Medium' },
      verificationMethod: 'Re-scan after refactor; confirm the cycle/god-module/deep-import is gone.',
      standards: [
        { framework: 'ISO/IEC 25010', version: '2023', id: 'Maintainability' },
        { framework: 'CWE', version: '4.x', id: cwe },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
