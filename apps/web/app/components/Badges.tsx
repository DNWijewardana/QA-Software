/** Presentational badges. Severity/decision are conveyed by TEXT + color, never color alone (WCAG 1.4.1). */

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`sev ${severity}`}>
      <span className="visually-hidden">Severity: </span>
      {severity}
    </span>
  );
}

const DECISION_LABEL: Record<string, string> = {
  GO: 'GO',
  NO_GO: 'NO-GO',
  GO_WITH_CONDITIONS: 'GO WITH CONDITIONS',
  INSUFFICIENT_EVIDENCE: 'INSUFFICIENT EVIDENCE',
};

export function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span className={`decision ${decision}`}>
      <span className="visually-hidden">Release decision: </span>
      {DECISION_LABEL[decision] ?? decision}
    </span>
  );
}
