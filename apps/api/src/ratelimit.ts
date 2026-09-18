/**
 * Fixed-window rate limiter (§VI.9). Per-key request budget within a rolling window. Deterministic and
 * in-memory; a Redis-backed limiter implements the same shape for the distributed deployment.
 */

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetMs: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  check(key: string, now = Date.now()): RateLimitResult {
    let b = this.buckets.get(key);
    if (!b || now >= b.resetAt) {
      b = { count: 0, resetAt: now + this.windowMs };
    }
    b.count += 1;
    this.buckets.set(key, b);
    const allowed = b.count <= this.limit;
    return {
      allowed,
      limit: this.limit,
      remaining: Math.max(0, this.limit - b.count),
      resetMs: b.resetAt - now,
    };
  }
}
