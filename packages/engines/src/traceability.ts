/**
 * Requirement→test traceability (§VII.13). Correlates requirements (from a requirements file) with the test
 * files that reference them, surfacing uncovered requirements and dangling references. Deterministic; pure
 * over the scan context. Reported as evidence — it does NOT feed the quality dimensions or the release
 * decision (a coverage gap is informational here; a project may enforce it via policy later).
 */

import type { TraceabilityMatrix } from '@qa/core';
import type { ScanContext, ProjectFile } from './types.js';
import { isRequirementsFile, parseRequirements } from './requirements-scanner.js';

const REQ_REF = /\bREQ[-_]?\w+\b/gi;

function isTestFile(f: ProjectFile): boolean {
  return (
    /\.(test|spec)\.[cm]?[jt]sx?$/i.test(f.path) ||
    /_test\.(py|go|rb|rs|java|cs|php)$/i.test(f.path) ||
    /(^|\/)(tests?|__tests__|spec)\//i.test(f.path)
  );
}

/** Build the requirement→test traceability matrix, or undefined when no requirements file is present. */
export async function analyzeTraceability(ctx: ScanContext): Promise<TraceabilityMatrix | undefined> {
  const reqFiles = ctx.files.filter((f) => isRequirementsFile(f.path));
  if (reqFiles.length === 0) return undefined;

  // Collect requirements (only id'd ones are traceable; count the rest).
  const withId: Array<{ id: string; text: string }> = [];
  let untraceable = 0;
  for (const f of reqFiles) {
    let content: string;
    try {
      content = await ctx.readText(f);
    } catch {
      continue;
    }
    for (const r of parseRequirements(f.path, content)) {
      if (r.id) withId.push({ id: r.id, text: r.text });
      else untraceable++;
    }
  }
  const reqIds = new Set(withId.map((r) => r.id));

  // Scan test files for requirement-id references (exact id substring), and for dangling REQ refs.
  const testFiles = ctx.files.filter(isTestFile).filter((f) => !isRequirementsFile(f.path));
  const testContents: Array<{ path: string; text: string }> = [];
  for (const f of testFiles) {
    try {
      testContents.push({ path: f.path, text: await ctx.readText(f) });
    } catch {
      /* skip unreadable */
    }
  }

  const requirements = withId.map((r) => {
    const tests = testContents.filter((t) => t.text.includes(r.id)).map((t) => t.path);
    return { id: r.id, text: r.text, tests, covered: tests.length > 0 };
  });

  const danglingReferences: Array<{ testFile: string; ids: string[] }> = [];
  for (const t of testContents) {
    const refs = new Set((t.text.match(REQ_REF) ?? []).map((s) => s.toUpperCase().replace('_', '-')));
    const dangling = [...refs].filter((id) => !reqIds.has(id) && ![...reqIds].some((r) => r.toUpperCase() === id));
    if (dangling.length) danglingReferences.push({ testFile: t.path, ids: dangling.sort() });
  }

  const covered = requirements.filter((r) => r.covered).length;
  return {
    note: 'Requirement→test traceability (§VII.13). A requirement is "covered" when a test file references its id. This is reported evidence and does not affect the quality dimensions or release decision.',
    requirements,
    untraceableRequirements: untraceable,
    danglingReferences,
    summary: {
      totalRequirements: requirements.length,
      covered,
      uncovered: requirements.length - covered,
      testFilesScanned: testContents.length,
    },
  };
}
