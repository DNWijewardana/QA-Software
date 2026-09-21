/**
 * RequirementsScanner — requirements-quality checks (§V.1). Scores under the Functional dimension
 * (requirements quality is a precursor to functional suitability, ISO/IEC 25010).
 *
 * Deterministic (§0.2.2): parses a requirements file (structured YAML/JSON array, or a Markdown list) and
 * checks each requirement for ambiguity, testability, missing acceptance criteria, atomicity, and missing
 * id/priority. High-signal, filename-scoped (`requirements.{md,yaml,yml,json}` or a `requirements/` dir) so it
 * NEVER fires on ordinary source or config.
 */

import { parse as parseYaml } from 'yaml';
import type { Finding } from '@qa/core';
import type { Engine, EngineArtifact, EngineResult, ProjectFile, ScanContext } from './types.js';
import { findingId, sha256 } from './util.js';

const CHECK_CATEGORIES = 6;

/** Weak/vague terms that make a requirement subjective or untestable. */
const AMBIGUOUS = /\b(should|may|might|could|approximately|about|some|several|many|few|etc|and\/or|as appropriate|if needed|as needed|user-friendly|fast|slow|quick(?:ly)?|easy|easily|robust|efficient|flexible|scalable|intuitive|seamless|reasonable|adequate|sufficient|minimal|optimal|state-of-the-art|TBD|TBC)\b/i;
/** Signals of a measurable/verifiable criterion. */
const MEASURABLE = /\d|\b(within|less than|greater than|at least|at most|no more than|equal to|percent|%|ms|milliseconds?|seconds?|minutes?|requests?\/s|rps|p9\d|latency|throughput|exactly|between)\b/i;

export function isRequirementsFile(path: string): boolean {
  return /(^|\/)requirements\.(md|ya?ml|json)$/i.test(path) || /(^|\/)requirements\//i.test(path);
}

/** A parsed requirement reduced to what traceability needs (id + text). */
export interface ParsedRequirement {
  id?: string;
  text: string;
}

/** Parse a requirements file (structured YAML/JSON or Markdown) into id+text pairs. Reused by traceability. */
export function parseRequirements(path: string, content: string): ParsedRequirement[] {
  const reqs = isStructured(path) ? parseStructured(content, /\.json$/i.test(path)) : parseMarkdown(content);
  return reqs.map((r) => ({ id: r.id, text: r.text }));
}
function isStructured(path: string): boolean {
  return /\.(ya?ml|json)$/i.test(path);
}

interface Req {
  id?: string;
  text: string;
  acceptance: string[];
  priority?: string;
  hasAcceptanceField: boolean; // whether the source models acceptance/priority as fields (structured)
  raw: string;
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}
function asArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x) => typeof x === 'string');
  const s = asString(v);
  return s ? [s] : [];
}

/** Parse a structured requirements doc: an array of objects, or an object with a `requirements` array. */
function parseStructured(content: string, isJson: boolean): Req[] {
  let doc: unknown;
  try {
    doc = isJson ? JSON.parse(content) : parseYaml(content);
  } catch {
    return [];
  }
  const list = Array.isArray(doc) ? doc : Array.isArray((doc as Record<string, unknown> | null)?.requirements) ? (doc as { requirements: unknown[] }).requirements : [];
  const reqs: Req[] = [];
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as Record<string, unknown>;
    const text = asString(rec.text) ?? asString(rec.requirement) ?? asString(rec.description) ?? asString(rec.title);
    if (!text) continue;
    reqs.push({
      id: asString(rec.id) ?? asString(rec.key),
      text,
      acceptance: asArray(rec.acceptanceCriteria ?? rec.acceptance ?? rec.criteria),
      priority: asString(rec.priority),
      hasAcceptanceField: true,
      raw: text,
    });
  }
  return reqs;
}

/** Parse a Markdown requirements doc: list items / `REQ-xxx:` lines become requirements (best-effort). */
function parseMarkdown(content: string): Req[] {
  const reqs: Req[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const m = /^[-*]\s+(.*)$/.exec(line) ?? /^(REQ[-_ ]?\w+.*)$/i.exec(line);
    if (!m) continue;
    const body = m[1]!.trim();
    if (!body || body.startsWith('#')) continue;
    const idMatch = /\b(REQ[-_]?\w+)\b/i.exec(body);
    const text = body.replace(/^\**\s*(REQ[-_]?\w+)\**\s*[:.)-]?\s*/i, '').trim() || body;
    reqs.push({ id: idMatch ? idMatch[1] : undefined, text, acceptance: [], priority: undefined, hasAcceptanceField: false, raw: body });
  }
  return reqs;
}

interface RuleHit {
  id: string;
  title: string;
  severity: Finding['severity'];
  desc: string;
  fix: string;
}

/** Evaluate one requirement → the rule hits it triggers. */
function evaluate(req: Req): RuleHit[] {
  const hits: RuleHit[] = [];
  const measurable = MEASURABLE.test(req.text) || req.acceptance.some((a) => MEASURABLE.test(a));

  if (AMBIGUOUS.test(req.text)) {
    hits.push({ id: 'REQ-AMBIGUOUS-001', title: 'Ambiguous / subjective requirement', severity: 'Medium',
      desc: 'The requirement uses vague or subjective language (e.g. "should", "fast", "user-friendly") that cannot be objectively verified.',
      fix: 'Rewrite with precise, measurable, testable language (use "shall" + a concrete acceptance criterion).' });
  }
  if (req.acceptance.length === 0 && !measurable) {
    hits.push({ id: 'REQ-NOT-TESTABLE-001', title: 'Requirement is not objectively testable', severity: 'Medium',
      desc: 'The requirement has no acceptance criteria and no measurable condition, so pass/fail cannot be determined.',
      fix: 'Add a measurable acceptance criterion (threshold, count, timing, or explicit expected result).' });
  }
  if (req.hasAcceptanceField && req.acceptance.length === 0) {
    hits.push({ id: 'REQ-NO-ACCEPTANCE-001', title: 'Missing acceptance criteria', severity: 'Low',
      desc: 'The requirement declares no acceptance criteria, so it cannot be traced to a verifying test.',
      fix: 'Add explicit acceptance criteria that a test can assert.' });
  }
  if ((req.text.match(/\b(shall|must|should)\b/gi) ?? []).length >= 2) {
    hits.push({ id: 'REQ-NOT-ATOMIC-001', title: 'Requirement is not atomic', severity: 'Low',
      desc: 'The requirement combines multiple obligations ("shall/must" appears more than once), which hinders precise testing and traceability.',
      fix: 'Split into separate atomic requirements, one obligation each.' });
  }
  if (!req.id) {
    hits.push({ id: 'REQ-MISSING-ID-001', title: 'Requirement has no identifier', severity: 'Informational',
      desc: 'The requirement has no stable identifier, preventing traceability to tests and defects (§VII.13).',
      fix: 'Assign a stable id (e.g. REQ-001).' });
  }
  if (req.hasAcceptanceField && !req.priority) {
    hits.push({ id: 'REQ-MISSING-PRIORITY-001', title: 'Requirement has no priority', severity: 'Informational',
      desc: 'The requirement declares no priority, so risk-based test planning cannot rank it.',
      fix: 'Assign a priority (e.g. High/Medium/Low).' });
  }
  return hits;
}

export class RequirementsScanner implements Engine {
  readonly name = 'requirements-scanner';
  readonly version = '0.1.0';
  readonly dimension = 'Functional' as const;

  appliesTo(ctx: ScanContext): boolean {
    return ctx.files.some((f) => isRequirementsFile(f.path));
  }

  async run(ctx: ScanContext): Promise<EngineResult> {
    const findings: Finding[] = [];
    const artifacts: EngineArtifact[] = [];
    const files = ctx.files.filter((f) => isRequirementsFile(f.path));
    let ordinal = 1;
    let reqCount = 0;

    const addArtifact = (key: string, content: string): string => {
      const id = `ev-${sha256(key).slice(0, 16)}`;
      artifacts.push({ id, type: 'source-code', content, contentHash: sha256(content), redactedClasses: {} });
      return id;
    };

    for (const file of files) {
      let content: string;
      try {
        content = await ctx.readText(file);
      } catch {
        continue;
      }
      const reqs = isStructured(file.path)
        ? parseStructured(content, /\.json$/i.test(file.path))
        : parseMarkdown(content);
      reqCount += reqs.length;
      for (const req of reqs) {
        for (const hit of evaluate(req)) {
          const label = req.id ?? req.text.slice(0, 40);
          const snippet = `${req.id ? `${req.id}: ` : ''}${req.text}`.slice(0, 200);
          const art = addArtifact(`${file.path}:${label}:${hit.id}`, `File: ${file.path}\nRequirement: ${snippet}`);
          findings.push(this.mk(findingId(hit.id, ordinal++), hit, { file: file.path }, art, snippet));
        }
      }
    }

    const applicable = Math.max(reqCount * CHECK_CATEGORIES, 1);
    return {
      engine: this.name,
      version: this.version,
      dimension: this.dimension,
      applicableChecks: applicable,
      executedChecks: reqCount * CHECK_CATEGORIES,
      findings,
      artifacts,
      degraded: reqCount === 0,
      degradedReason: reqCount === 0 ? 'A requirements file was present but no requirements could be parsed.' : undefined,
    };
  }

  private mk(id: string, hit: RuleHit, location: Finding['location'], artifactId: string, snippet: string): Finding {
    return {
      id,
      ruleId: hit.id,
      category: 'Requirements',
      subcategory: 'Requirements quality',
      title: hit.title,
      description: hit.desc,
      status: hit.severity === 'Informational' ? 'WARNING' : hit.severity === 'Low' ? 'WARNING' : 'FAIL',
      evidenceClass: 'AUTOMATICALLY_DETECTED',
      severity: hit.severity,
      risk: hit.severity,
      confidence: 'Likely',
      reproducibility: 'Always',
      cwe: [],
      cve: [],
      affectedComponent: location.file,
      location,
      detectionMethod: 'static',
      toolUsed: `${this.name}@${this.version}`,
      evidence: [{ type: 'source-code', ref: artifactId, redacted: true, snippet }],
      remediation: { summary: hit.fix, effort: 'S', riskReduction: 'Medium' },
      verificationMethod: 'Rewrite the requirement to be atomic, unambiguous, and testable; add acceptance criteria and re-scan.',
      standards: [
        { framework: 'ISO/IEC 25010', version: '2023', id: 'Functional-suitability' },
        { framework: 'ISO/IEC 29148', version: '2018', id: 'Requirements-quality' },
      ],
      traceability: { requirements: [], tests: [] },
    };
  }
}
