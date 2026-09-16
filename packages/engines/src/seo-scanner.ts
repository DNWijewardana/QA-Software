/**
 * SEO analyzer (§V.24). Static HTML SEO checks — title, meta description, canonical, robots, headings,
 * Open Graph, viewport — plus project-level robots.txt / sitemap.xml presence.
 *
 * SEPARATION (§V.24): SEO quality is reported separately from software quality. This analyzer is NOT a
 * normal scoring Engine — the orchestrator calls it directly and places the result in `scan.seo`, keeping
 * SEO findings out of the quality dimensions, the overall score, and the release decision.
 */

import { parse, type HTMLElement } from 'node-html-parser';
import type { Finding, SeoReport } from '@qa/core';
import type { ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

function isHtml(f: ProjectFile): boolean {
  return /\.x?html?$/i.test(f.path);
}
function baseName(p: string): string {
  return (p.split('/').pop() ?? '').toLowerCase();
}

function mk(
  id: string,
  ruleId: string,
  title: string,
  severity: Finding['severity'],
  status: Finding['status'],
  location: Finding['location'],
  description: string,
  remediation: string,
): Finding {
  return {
    id,
    ruleId,
    category: 'SEO',
    subcategory: 'On-page',
    title,
    description,
    status,
    evidenceClass: 'AUTOMATICALLY_DETECTED',
    severity,
    risk: severity,
    confidence: 'Highly likely',
    reproducibility: 'Always',
    cwe: [],
    cve: [],
    affectedComponent: location.file,
    location,
    detectionMethod: 'static',
    toolUsed: 'seo-scanner@0.1.0',
    evidence: [],
    remediation: { summary: remediation, effort: 'S', riskReduction: 'Low' },
    verificationMethod: 'Re-crawl the page after the fix; validate with a search-console/rich-results tool.',
    standards: [{ framework: 'SEO best practices', version: 'n/a', id: ruleId }],
    traceability: { requirements: [], tests: [] },
  };
}

/** Analyse SEO across the project's HTML pages. Returns undefined when there are no HTML pages. */
export async function analyzeSeo(ctx: ScanContext): Promise<SeoReport | undefined> {
  const htmlFiles = ctx.files.filter(isHtml);
  if (htmlFiles.length === 0) return undefined;

  const findings: Finding[] = [];
  let ordinal = 1;
  const id = (rule: string) => findingId(rule, ordinal++);

  for (const file of htmlFiles) {
    let root: HTMLElement;
    try {
      root = parse(await ctx.readText(file), { comment: false });
    } catch {
      continue;
    }
    const loc: Finding['location'] = { file: file.path };
    const head = root.querySelector('head');
    const meta = (name: string): HTMLElement | undefined =>
      root.querySelectorAll('meta').find((m) => (m.getAttribute('name') ?? '').toLowerCase() === name);
    const metaProp = (prop: string): HTMLElement | undefined =>
      root.querySelectorAll('meta').find((m) => (m.getAttribute('property') ?? '').toLowerCase() === prop);

    if (!root.querySelector('title')?.text.trim()) {
      findings.push(mk(id('SEO-TITLE-001'), 'SEO-TITLE-001', 'Missing <title>', 'Medium', 'FAIL', loc,
        'The page has no non-empty <title>, the single strongest on-page ranking and SERP-display signal.',
        'Add a unique, descriptive <title> (~50–60 chars).'));
    }
    if (!meta('description')?.getAttribute('content')?.trim()) {
      findings.push(mk(id('SEO-META-DESC-001'), 'SEO-META-DESC-001', 'Missing meta description', 'Low', 'WARNING', loc,
        'No <meta name="description"> — search engines will synthesise a snippet, reducing click-through control.',
        'Add a compelling meta description (~150–160 chars).'));
    }
    if (!root.querySelectorAll('link').some((l) => (l.getAttribute('rel') ?? '').toLowerCase() === 'canonical')) {
      findings.push(mk(id('SEO-CANONICAL-001'), 'SEO-CANONICAL-001', 'Missing canonical link', 'Low', 'WARNING', loc,
        'No <link rel="canonical"> — duplicate-content signals may be split across URL variants.',
        'Add a canonical link pointing to the preferred URL.'));
    }
    const robots = (meta('robots')?.getAttribute('content') ?? '').toLowerCase();
    if (robots.includes('noindex')) {
      findings.push(mk(id('SEO-ROBOTS-NOINDEX-001'), 'SEO-ROBOTS-NOINDEX-001', 'Page set to noindex', 'Medium', 'WARNING', loc,
        'A robots meta tag contains `noindex`, so this page will be excluded from search results. Confirm this is intentional.',
        'Remove `noindex` if the page should be indexable.'));
    }
    const h1s = root.querySelectorAll('h1');
    if (h1s.length === 0) {
      findings.push(mk(id('SEO-H1-001'), 'SEO-H1-001', 'No <h1> heading', 'Low', 'WARNING', loc,
        'The page has no <h1>, weakening topical signals and document structure.', 'Add a single descriptive <h1>.'));
    } else if (h1s.length > 1) {
      findings.push(mk(id('SEO-H1-001'), 'SEO-H1-001', `Multiple <h1> headings (${h1s.length})`, 'Low', 'WARNING', loc,
        'Multiple <h1> elements dilute the primary topic signal.', 'Use one <h1> per page; demote the rest to <h2>.'));
    }
    if (!metaProp('og:title') || !metaProp('og:description') || !metaProp('og:image')) {
      findings.push(mk(id('SEO-OG-001'), 'SEO-OG-001', 'Incomplete Open Graph tags', 'Low', 'WARNING', loc,
        'Missing og:title/og:description/og:image — social shares will render poor previews.',
        'Add Open Graph meta tags for rich social previews.'));
    }
    if (head && !meta('viewport')) {
      findings.push(mk(id('SEO-VIEWPORT-001'), 'SEO-VIEWPORT-001', 'Missing viewport meta', 'Medium', 'FAIL', loc,
        'No <meta name="viewport"> — the page is not mobile-friendly, which affects mobile ranking.',
        'Add <meta name="viewport" content="width=device-width, initial-scale=1">.'));
    }
  }

  // Project-level signals.
  const rootLoc: Finding['location'] = {};
  if (!ctx.files.some((f) => baseName(f.path) === 'robots.txt')) {
    findings.push(mk(id('SEO-ROBOTSTXT-001'), 'SEO-ROBOTSTXT-001', 'No robots.txt', 'Informational', 'WARNING', rootLoc,
      'No robots.txt found — crawlers get no crawl directives or sitemap pointer.', 'Add a robots.txt with a Sitemap: directive.'));
  }
  if (!ctx.files.some((f) => baseName(f.path) === 'sitemap.xml')) {
    findings.push(mk(id('SEO-SITEMAP-001'), 'SEO-SITEMAP-001', 'No sitemap.xml', 'Informational', 'WARNING', rootLoc,
      'No sitemap.xml found — search engines have no explicit list of indexable URLs.', 'Generate and publish a sitemap.xml.'));
  }

  // Deterministic ordering for reproducibility.
  findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return {
    note: 'SEO quality is reported SEPARATELY from software quality (§V.24). These findings do not affect the quality dimension scores, the overall score, or the release decision.',
    findings,
    summary: { pages: htmlFiles.length, issues: findings.length },
  };
}
