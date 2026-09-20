// FIXTURE — intentionally bad architecture for the golden corpus (spec X.3). NOT for real use.
// a → b → c → a forms an import cycle (SEEDED: ARCH-CIRCULAR-DEP-001).
import { b } from './b.js';

export function a(): string {
  return `a:${b()}`;
}
