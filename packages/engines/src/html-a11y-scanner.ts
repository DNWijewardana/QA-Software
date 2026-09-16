/**
 * HtmlAccessibilityScanner — static HTML accessibility checks (Accessibility dimension).
 * Spec ref: §V.5 (WCAG 2.2 principal framework). Each finding carries the WCAG criterion + level.
 *
 * HONESTY (§V.5): automated checks CANNOT prove full WCAG conformance. These are static, high-confidence
 * checks on the markup only; keyboard, focus-order, screen-reader, and contrast-in-context testing require
 * humans. The orchestrator adds a manual WCAG audit item to the manual-review queue when this engine runs.
 */

import { parse, type HTMLElement } from 'node-html-parser';
import type { Finding } from '@qa/core';
import { redactedSnippet } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 9;
const LABELLABLE_SKIP_TYPES = new Set(['hidden', 'submit', 'reset', 'button']);

interface Wcag {
  criterion: string;
  level: 'A' | 'AA' | 'AAA';
}

function isHtml(f: ProjectFile): boolean {
  return /\.x?html?$/i.test(f.path);
}

function accessibleName(el: HTMLElement): string {
  const text = el.text.trim();
  if (text) return text;
  const aria = el.getAttribute('aria-label')?.trim();
  if (aria) return aria;
  if (el.getAttribute('aria-labelledby')?.trim()) return 'labelledby';
  const title = el.getAttribute('title')?.trim();
  if (title) return title;
  const img = el.querySelector('img');
  const imgAlt = img?.getAttribute('alt')?.trim();
  if (imgAlt) return imgAlt;
  return '';
}

function wrappedInLabel(el: HTMLElement): boolean {
  let p = el.parentNode as HTMLElement | null;
  while (p) {
    if ((p.rawTagName ?? '').toLowerCase() === 'label') return true;
    p = p.parentNode as HTMLElement | null;
  }
  return false;
}

export class HtmlAccessibilityScanner implements Engine {
  readonly name = 'html-a11y-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Accessibility' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some(isHtml);
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const htmlFiles = ctx.files.filter(isHtml);
    let ordinal = 1;
    let executed = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of htmlFiles) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      let root: HTMLElement;
      try {
        root = parse(content, { comment: false });
      } catch {
        continue;
      }
      executed += CHECK_CATEGORIES;

      const push = (rule: string, title: string, severity: Finding['severity'], wcag: Wcag, desc: string, snippet: string, fix: string, key: string) => {
        const art = addArtifact(`${file.path}:${key}`, `File: ${file.path}\n${snippet}`);
        findings.push(this.mk(findingId(rule, ordinal++), rule, title, severity, { file: file.path }, wcag, desc, art, snippet, fix));
      };

      // 1) images without alt (missing attribute; alt="" is allowed for decorative images)
      for (const img of root.querySelectorAll('img')) {
        if (img.getAttribute('alt') === undefined) {
          push('A11Y-IMG-ALT-001', 'Image missing alt attribute', 'Medium', { criterion: '1.1.1', level: 'A' },
            'An <img> has no alt attribute, so assistive technology cannot describe it. Use alt="" for purely decorative images.',
            redactedSnippet(img.toString()), 'Add a descriptive alt (or alt="" if decorative).', `img:${img.getAttribute('src') ?? ordinal}`);
        }
      }

      // 2) <html> without lang
      const htmlEl = root.querySelector('html');
      if (htmlEl && !htmlEl.getAttribute('lang')?.trim()) {
        push('A11Y-HTML-LANG-001', 'Document language not set', 'Medium', { criterion: '3.1.1', level: 'A' },
          'The <html> element has no lang attribute, so screen readers cannot select the correct pronunciation rules.',
          '<html> (no lang)', 'Set <html lang="en"> (or the correct language).', 'html-lang');
      }

      // 3) missing document title
      if ((htmlEl || root.querySelector('head')) && !root.querySelector('title')?.text.trim()) {
        push('A11Y-TITLE-001', 'Missing document <title>', 'Medium', { criterion: '2.4.2', level: 'A' },
          'The page has no non-empty <title>, so users cannot identify it in tabs, history, or bookmarks.',
          '<head> without <title>', 'Add a concise, descriptive <title>.', 'doc-title');
      }

      // 4) form controls without an accessible label
      const labelForIds = new Set(
        root.querySelectorAll('label').map((l) => l.getAttribute('for')?.trim()).filter((x): x is string => Boolean(x)),
      );
      for (const ctrl of root.querySelectorAll('input, select, textarea')) {
        const type = (ctrl.getAttribute('type') ?? '').toLowerCase();
        if (ctrl.rawTagName?.toLowerCase() === 'input' && LABELLABLE_SKIP_TYPES.has(type)) continue;
        const id = ctrl.getAttribute('id')?.trim();
        const hasLabel =
          Boolean(ctrl.getAttribute('aria-label')?.trim()) ||
          Boolean(ctrl.getAttribute('aria-labelledby')?.trim()) ||
          Boolean(ctrl.getAttribute('title')?.trim()) ||
          (id !== undefined && labelForIds.has(id)) ||
          wrappedInLabel(ctrl);
        if (!hasLabel) {
          push('A11Y-INPUT-LABEL-001', `Form control has no accessible label: <${ctrl.rawTagName?.toLowerCase()}>`, 'High', { criterion: '1.3.1', level: 'A' },
            'A form control has no associated <label>, aria-label, aria-labelledby, or title, so its purpose is not announced.',
            redactedSnippet(ctrl.toString()), 'Associate a <label for> (or add aria-label) to the control.', `ctrl:${id ?? ctrl.getAttribute('name') ?? ordinal}`);
        }
      }

      // 5) buttons with no accessible name
      for (const btn of root.querySelectorAll('button')) {
        if (accessibleName(btn) === '') {
          push('A11Y-BUTTON-NAME-001', 'Button has no accessible name', 'High', { criterion: '4.1.2', level: 'A' },
            'A <button> has no text, aria-label, or title, so its action is not announced to assistive technology.',
            redactedSnippet(btn.toString()), 'Add visible text or an aria-label to the button.', `btn:${ordinal}`);
        }
      }

      // 6) links with no accessible name
      for (const a of root.querySelectorAll('a[href]')) {
        if (accessibleName(a) === '') {
          push('A11Y-LINK-NAME-001', 'Link has no accessible name', 'High', { criterion: '2.4.4', level: 'A' },
            'A link has no discernible text, so its destination is not announced.',
            redactedSnippet(a.toString()), 'Provide descriptive link text (or an aria-label).', `link:${a.getAttribute('href') ?? ordinal}`);
        }
      }

      // 7) positive tabindex
      for (const el of root.querySelectorAll('[tabindex]')) {
        const ti = Number(el.getAttribute('tabindex'));
        if (Number.isFinite(ti) && ti > 0) {
          push('A11Y-TABINDEX-001', `Positive tabindex (${ti}) disrupts focus order`, 'Low', { criterion: '2.4.3', level: 'A' },
            'A positive tabindex overrides the natural DOM focus order, which is fragile and confusing for keyboard users.',
            redactedSnippet(el.toString()), 'Use tabindex="0" or restructure the DOM so focus order is natural.', `tabindex:${ordinal}`);
        }
      }

      // 8) iframes without a title
      for (const frame of root.querySelectorAll('iframe')) {
        if (!frame.getAttribute('title')?.trim()) {
          push('A11Y-IFRAME-TITLE-001', 'iframe has no title', 'Medium', { criterion: '4.1.2', level: 'A' },
            'An <iframe> has no title attribute, so its embedded content is not identified to assistive technology.',
            redactedSnippet(frame.toString()), 'Add a descriptive title attribute to the iframe.', `iframe:${frame.getAttribute('src') ?? ordinal}`);
        }
      }

      // 9) viewport that blocks zoom
      const viewport = root.querySelectorAll('meta').find((m) => (m.getAttribute('name') ?? '').toLowerCase() === 'viewport');
      const vpContent = (viewport?.getAttribute('content') ?? '').toLowerCase();
      if (/user-scalable\s*=\s*no/.test(vpContent) || /maximum-scale\s*=\s*(1|1\.0)\b/.test(vpContent)) {
        push('A11Y-VIEWPORT-001', 'Viewport disables zoom', 'Medium', { criterion: '1.4.4', level: 'AA' },
          'The viewport meta tag disables pinch-zoom (user-scalable=no / maximum-scale=1), preventing low-vision users from enlarging text.',
          redactedSnippet(viewport?.toString() ?? ''), 'Remove user-scalable=no and maximum-scale restrictions.', 'viewport');
      }
    }

    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: Math.max(htmlFiles.length * CHECK_CATEGORIES, 1),
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
    location: Finding['location'],
    wcag: Wcag,
    description: string,
    artifactId: string,
    snippet: string,
    remediation: string,
  ): Finding {
    return {
      id,
      ruleId,
      category: 'Accessibility',
      subcategory: `WCAG ${wcag.criterion} (${wcag.level})`,
      title,
      description,
      status: severity === 'Low' ? 'WARNING' : 'FAIL',
      // Static markup checks are automatically detected, but conformance still needs manual verification.
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
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: remediation, effort: 'S', riskReduction: severity === 'High' ? 'High' : 'Medium' },
      verificationMethod: 'Manual keyboard + screen-reader verification of the affected element.',
      standards: [
        { framework: 'WCAG 2.2', version: '2.2', id: `${wcag.criterion} (${wcag.level})` },
        { framework: 'EN 301 549', version: 'latest', id: '9 (Web)' },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
