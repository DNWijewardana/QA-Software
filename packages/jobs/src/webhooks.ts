/**
 * Webhooks / notifications (§VI.10, §111). Emit signed, idempotent events to an external sink when a scan
 * completes, fails, produces a Critical finding, or fails a quality gate. Delivery is best-effort with a
 * bounded retry; a webhook failure NEVER fails the scan (§VI.7 — the scan result is authoritative).
 *
 * Security (§111): payloads are signed with HMAC-SHA256 over the exact request body (header
 * `X-QA-Signature: sha256=<hex>`); each delivery carries a unique `X-QA-Delivery` id for idempotency.
 */

import { createHmac, randomUUID } from 'node:crypto';
import type { ScanResult } from '@qa/core';

export type WebhookEventType = 'scan.completed' | 'scan.failed' | 'critical.finding' | 'quality-gate.failed';

export interface WebhookEvent {
  id: string;
  type: WebhookEventType;
  scanId: string;
  orgId: string;
  at: string;
  data: Record<string, unknown>;
}

export interface WebhookEmitter {
  emit(events: WebhookEvent[]): Promise<void>;
}

/** HMAC-SHA256 signature of a webhook body: `sha256=<hex>`. Empty when no secret is configured. */
export function signPayload(secret: string | undefined, body: string): string {
  if (!secret) return '';
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

/** Derive the events for a completed scan result (deterministic; no I/O). */
export function deriveEvents(result: ScanResult, orgId: string): WebhookEvent[] {
  const base = { scanId: result.scan.id, orgId, at: new Date().toISOString() };
  const events: WebhookEvent[] = [
    {
      id: randomUUID(),
      type: 'scan.completed',
      ...base,
      data: {
        decision: result.releaseDecision.decision,
        overallScore: result.overall.score,
        criticalBlockers: result.overall.criticalBlockers,
        highRiskFindings: result.overall.highRiskFindings,
      },
    },
  ];
  if (result.overall.criticalBlockers > 0) {
    events.push({ id: randomUUID(), type: 'critical.finding', ...base, data: { criticalBlockers: result.overall.criticalBlockers } });
  }
  if (result.releaseDecision.decision === 'NO_GO' || result.releaseDecision.decision === 'GO_WITH_CONDITIONS') {
    events.push({ id: randomUUID(), type: 'quality-gate.failed', ...base, data: { decision: result.releaseDecision.decision, conditions: result.releaseDecision.conditions } });
  }
  return events;
}

/** A scan.failed event (emitted when a scan errors). */
export function failedEvent(scanId: string, orgId: string, message: string): WebhookEvent {
  return { id: randomUUID(), type: 'scan.failed', scanId, orgId, at: new Date().toISOString(), data: { error: message } };
}

export interface HttpWebhookOptions {
  url: string;
  secret?: string;
  /** event types to deliver; when omitted, all events are delivered. */
  events?: WebhookEventType[];
  timeoutMs?: number;
  /** total attempts per event (>=1). Default 3. */
  maxAttempts?: number;
}

/** Real HTTP emitter: POSTs each subscribed event as a signed JSON body, with a bounded retry. */
export class HttpWebhookEmitter implements WebhookEmitter {
  private readonly subscribed?: Set<WebhookEventType>;
  constructor(private readonly opts: HttpWebhookOptions) {
    this.subscribed = opts.events ? new Set(opts.events) : undefined;
  }

  async emit(events: WebhookEvent[]): Promise<void> {
    for (const event of events) {
      if (this.subscribed && !this.subscribed.has(event.type)) continue;
      await this.deliver(event);
    }
  }

  private async deliver(event: WebhookEvent): Promise<void> {
    const body = JSON.stringify(event);
    const signature = signPayload(this.opts.secret, body);
    const maxAttempts = Math.max(1, this.opts.maxAttempts ?? 3);
    const timeoutMs = this.opts.timeoutMs ?? 5000;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(this.opts.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-qa-event': event.type,
            'x-qa-delivery': event.id,
            ...(signature ? { 'x-qa-signature': signature } : {}),
          },
          body,
          signal: controller.signal,
        });
        if (res.ok) return;
      } catch {
        // network error / timeout → fall through to retry
      } finally {
        clearTimeout(timer);
      }
      // Delivery failed; a webhook failure must never fail the scan — just stop after the last attempt.
    }
  }
}
