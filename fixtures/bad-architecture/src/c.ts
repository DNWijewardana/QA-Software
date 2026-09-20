// FIXTURE — closes the a → b → c → a cycle by importing back into a.
import { a } from './a.js';

export function c(): string {
  // Referencing a() here is what closes the cycle.
  return typeof a === 'function' ? 'c' : 'c';
}
