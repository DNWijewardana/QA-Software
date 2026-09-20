// FIXTURE — part of the a → b → c → a cycle.
import { c } from './c.js';

export function b(): string {
  return `b:${c()}`;
}
