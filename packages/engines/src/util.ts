import { createHash } from 'node:crypto';

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Deterministic finding id: RULE + zero-padded ordinal (stable across runs for the same order). */
export function findingId(ruleId: string, ordinal: number): string {
  return `${ruleId}-${String(ordinal).padStart(4, '0')}`;
}

const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.java', '.go', '.rb', '.php', '.rs', '.cs',
  '.json', '.env', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.txt', '.md', '.html', '.css', '.sh',
]);

export function isLikelyTextFile(relPath: string): boolean {
  const idx = relPath.lastIndexOf('.');
  if (idx < 0) return relPath.startsWith('.env') || relPath === 'Dockerfile';
  return TEXT_EXTENSIONS.has(relPath.slice(idx).toLowerCase()) || relPath.startsWith('.env');
}
