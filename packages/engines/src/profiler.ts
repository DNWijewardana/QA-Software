/**
 * Project Profiler — detects the technology stack and RECORDS DETECTION CONFIDENCE.
 * Spec ref: §III.2/§III.3 ("Never assume the technology stack. Detect it, and record confidence").
 */

import path from 'node:path';
import type { ProjectProfile } from '@qa/core';
import type { ProjectFile } from './types.js';

const EXT_LANG: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.py': 'Python',
  '.java': 'Java',
  '.go': 'Go',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.rs': 'Rust',
  '.cs': 'C#',
};

const FRAMEWORK_DEPS: Record<string, string> = {
  react: 'React',
  next: 'Next.js',
  vue: 'Vue',
  '@angular/core': 'Angular',
  express: 'Express',
  '@nestjs/core': 'NestJS',
  fastify: 'Fastify',
  django: 'Django',
  flask: 'Flask',
  fastapi: 'FastAPI',
};

const TEST_DEPS = ['jest', 'vitest', 'mocha', 'playwright', '@playwright/test', 'cypress', 'pytest', 'supertest'];

export interface ProfilerInput {
  files: ProjectFile[];
  readText: (file: ProjectFile) => Promise<string>;
}

export async function profileProject(input: ProfilerInput): Promise<ProjectProfile> {
  const { files, readText } = input;
  const notes: string[] = [];

  // Language detection by extension frequency.
  const langCounts = new Map<string, number>();
  for (const f of files) {
    const lang = EXT_LANG[path.extname(f.path).toLowerCase()];
    if (lang) langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
  }
  const totalLangFiles = [...langCounts.values()].reduce((a, b) => a + b, 0);
  const languages = [...langCounts.entries()]
    .map(([name, count]) => ({ name, confidence: totalLangFiles ? +(count / totalLangFiles).toFixed(2) : 0 }))
    .sort((a, b) => b.confidence - a.confidence);

  // Framework + package manager + tests via package.json (JS/TS) — extensible per ecosystem.
  const frameworks: Array<{ name: string; confidence: number }> = [];
  const packageManagers: string[] = [];
  let hasTests = false;

  const pkgFile = files.find((f) => f.path === 'package.json');
  if (pkgFile) {
    try {
      const pkg = JSON.parse(await readText(pkgFile)) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      for (const [dep, label] of Object.entries(FRAMEWORK_DEPS)) {
        if (deps[dep]) frameworks.push({ name: label, confidence: 0.9 });
      }
      hasTests = TEST_DEPS.some((d) => deps[d]);
    } catch {
      notes.push('package.json present but could not be parsed; framework detection limited.');
    }
  }

  if (files.some((f) => f.path === 'package-lock.json')) packageManagers.push('npm');
  if (files.some((f) => f.path === 'pnpm-lock.yaml')) packageManagers.push('pnpm');
  if (files.some((f) => f.path === 'yarn.lock')) packageManagers.push('yarn');
  if (files.some((f) => f.path === 'requirements.txt' || f.path === 'pyproject.toml')) packageManagers.push('pip');

  if (!hasTests && files.some((f) => /\.(test|spec)\.[jt]sx?$/.test(f.path))) hasTests = true;

  // Detection confidence: high when we have a strong primary language + a lockfile/manifest.
  let detectionConfidence = 0.3;
  if (languages[0] && languages[0].confidence > 0.5) detectionConfidence += 0.3;
  if (pkgFile || packageManagers.length > 0) detectionConfidence += 0.3;
  if (frameworks.length > 0) detectionConfidence += 0.1;
  detectionConfidence = Math.min(1, +detectionConfidence.toFixed(2));

  if (languages.length === 0) notes.push('No recognized source languages detected by extension.');

  return {
    languages,
    frameworks,
    packageManagers,
    hasTests,
    fileCount: files.length,
    detectionConfidence,
    notes,
  };
}
