import { createHash, randomUUID } from 'node:crypto';

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function newScanId(): string {
  return `scan_${randomUUID()}`;
}
