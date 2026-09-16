import { describe, it, expect } from 'vitest';
import { redact } from '@qa/core';

describe('redaction (§VIII.10 — never expose secrets)', () => {
  it('masks an AWS access key and never leaks the raw value', () => {
    const raw = 'const k = "AKIAIOSFODNN7EXAMPLE";';
    const out = redact(raw);
    expect(out.redacted).toBe(true);
    expect(out.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out.text).toContain('«REDACTED:aws-access-key»');
  });

  it('masks a generic credential assignment but keeps the key name', () => {
    const out = redact('password = "SuperSecretP@ssw0rd123"');
    expect(out.text).not.toContain('SuperSecretP@ssw0rd123');
    expect(out.text.toLowerCase()).toContain('password');
    expect(out.redactedClasses['generic-secret-assignment']).toBeGreaterThan(0);
  });

  it('leaves clean text untouched', () => {
    const out = redact('const port = 3000;');
    expect(out.redacted).toBe(false);
    expect(out.text).toBe('const port = 3000;');
  });
});
