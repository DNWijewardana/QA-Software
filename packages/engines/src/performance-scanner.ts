/**
 * PerformanceScanner — static performance / asset-budget checks (Performance dimension).
 * Spec ref: §V.12 (bundle size, image optimization, performance budgets per route).
 *
 * Static-only (no build or page load): flags oversized assets, over-budget shipped JS/CSS,
 * render-blocking scripts in <head>, and committed source maps. Budgets are conservative defaults.
 * This is NOT a substitute for runtime performance testing (load/latency/Core Web Vitals) — those
 * require a running target and are reported separately when a dynamic environment is authorized.
 */

import { parse, type HTMLElement } from 'node-html-parser';
import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const KB = 1024;
const BUDGETS = { image: 500 * KB, font: 500 * KB, media: 2048 * KB, css: 150 * KB, js: 300 * KB };
const IMG = /\.(png|jpe?g|gif|bmp|tiff?|ico|webp|avif|svg)$/i;
const FONT = /\.(woff2?|ttf|otf|eot)$/i;
const MEDIA = /\.(mp4|webm|mov|avi|mkv|mp3|wav|flac|ogg)$/i;
const ASSET_PATH = /(^|\/)(public|static|assets|dist|build)\//i;
const BUNDLED_JS = /\.(min|bundle)\.js$/i;

function isRelevant(f: ProjectFile): boolean {
  return (
    IMG.test(f.path) ||
    FONT.test(f.path) ||
    MEDIA.test(f.path) ||
    /\.css$/i.test(f.path) ||
    /\.x?html?$/i.test(f.path) ||
    /\.map$/i.test(f.path) ||
    (/\.js$/i.test(f.path) && (ASSET_PATH.test(f.path) || BUNDLED_JS.test(f.path)))
  );
}

function human(bytes: number): string {
  return bytes >= KB * KB ? `${(bytes / (KB * KB)).toFixed(1)} MB` : `${Math.round(bytes / KB)} KB`;
}

export class PerformanceScanner implements Engine {
  readonly name = 'performance-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Performance' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isRelevant);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const relevant = ctx.files.filter(isRelevant);
    let ordinal = 1;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'performance-measurement', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };
    const sizeSeverity = (bytes: number, budget: number): Finding['severity'] => (bytes > budget * 3 ? 'High' : 'Medium');

    const overBudget = (
      f: ProjectFile,
      budget: number,
      rule: string,
      kind: string,
      cwe: string[],
      fix: string,
    ) => {
      if (f.size <= budget) return;
      const art = addArtifact(`${f.path}:size`, `File: ${f.path}\nSize: ${f.size} bytes (${human(f.size)})\nBudget: ${human(budget)}`);
      findings.push(this.mk(findingId(rule, ordinal++), rule, `Oversized ${kind}: ${f.path} (${human(f.size)})`, sizeSeverity(f.size, budget), 'FAIL',
        { file: f.path }, `\`${f.path}\` is ${human(f.size)}, over the ${human(budget)} ${kind} budget. Large assets slow first load and hurt Core Web Vitals (LCP).`,
        art, fix, cwe));
    };

    // 1) asset / bundle size budgets
    for (const f of relevant) {
      if (IMG.test(f.path)) overBudget(f, BUDGETS.image, 'PERF-ASSET-IMG-001', 'image', [], 'Compress and resize; prefer WebP/AVIF and responsive sizes.');
      else if (FONT.test(f.path)) overBudget(f, BUDGETS.font, 'PERF-ASSET-FONT-001', 'font', [], 'Subset the font and use WOFF2.');
      else if (MEDIA.test(f.path)) overBudget(f, BUDGETS.media, 'PERF-ASSET-MEDIA-001', 'media file', [], 'Transcode/compress; stream instead of bundling.');
      else if (/\.css$/i.test(f.path)) overBudget(f, BUDGETS.css, 'PERF-CSS-SIZE-001', 'stylesheet', [], 'Split/minify CSS and remove unused rules.');
      else if (/\.js$/i.test(f.path)) overBudget(f, BUDGETS.js, 'PERF-JS-SIZE-001', 'JavaScript bundle', ['CWE-405'], 'Code-split, tree-shake, and lazy-load; enforce a per-route budget.');

      // 4) committed source maps
      if (/\.map$/i.test(f.path)) {
        const art = addArtifact(`${f.path}:map`, `File: ${f.path}`);
        findings.push(this.mk(findingId('PERF-SOURCEMAP-001', ordinal++), 'PERF-SOURCEMAP-001', `Source map committed: ${f.path}`, 'Informational', 'WARNING',
          { file: f.path }, 'A source map is present in the repository. Shipping source maps to production bloats deploys and can expose original source.',
          art, 'Generate source maps in CI and upload them to your error tracker, not the served bundle.', []));
      }
    }

    // 3) render-blocking scripts in <head>
    for (const f of relevant.filter((x) => /\.x?html?$/i.test(x.path))) {
      let content: string;
      try {
        content = await ctx.readText(f);
      } catch {
        continue;
      }
      let head: HTMLElement | null;
      try {
        head = parse(content, { comment: false }).querySelector('head');
      } catch {
        continue;
      }
      if (!head) continue;
      for (const s of head.querySelectorAll('script[src]')) {
        const asyncAttr = s.getAttribute('async') !== undefined;
        const deferAttr = s.getAttribute('defer') !== undefined;
        const type = (s.getAttribute('type') ?? '').toLowerCase();
        if (!asyncAttr && !deferAttr && type !== 'module') {
          const src = s.getAttribute('src') ?? '';
          const art = addArtifact(`${f.path}:renderblock:${src}`, `File: ${f.path}\nrender-blocking <script src="${src}"> in <head>`);
          findings.push(this.mk(findingId('PERF-RENDER-BLOCK-001', ordinal++), 'PERF-RENDER-BLOCK-001', `Render-blocking script in <head>: ${src}`, 'Medium', 'FAIL',
            { file: f.path }, `\`${src}\` is loaded synchronously in <head>, blocking first render until it downloads and executes.`,
            art, 'Add `defer` (or `async`), use `type="module"`, or move the script before </body>.', []));
        }
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(relevant.length, 1),
      executedChecks: relevant.length,
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
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Performance',
      subcategory: 'Static budget',
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
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'performance-measurement', ref: artifactId, redacted: false }],
      remediation: { summary: remediation, effort: 'M', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Re-measure asset size after optimization; confirm against the route budget.',
      standards: [{ framework: 'Web Performance', version: 'budgets', id: ruleId }, ...(cwe.length ? [{ framework: 'CWE', version: '4.x', id: cwe[0]! }] : [])],
      traceability: { requirements: [], tests: [] },
    };
  }
}
