/**
 * SARIF 2.1.0 exporter (§IX.3 — SARIF for code-scanning integration).
 * Maps each Finding to a SARIF result with a rule, level, and physical location.
 * SARIF is consumed by GitHub code scanning, Azure DevOps, and many IDEs.
 */

import type { Finding, ScanResult, Severity } from '@qa/core';

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

function toLevel(sev: Severity, status: Finding['status']): SarifLevel {
  if (status === 'NOT_TESTED' || status === 'INSUFFICIENT_EVIDENCE') return 'none';
  switch (sev) {
    case 'Critical':
    case 'High':
      return 'error';
    case 'Medium':
    case 'Low':
      return 'warning';
    default:
      return 'note';
  }
}

/** security-severity is a GitHub convention (0-10) so alerts sort by risk. */
function securitySeverity(sev: Severity): string {
  const map: Record<Severity, string> = {
    Critical: '9.5',
    High: '8.0',
    Medium: '5.5',
    Low: '3.0',
    Informational: '0.0',
  };
  return map[sev];
}

export function toSarif(result: ScanResult): string {
  const rulesMap = new Map<string, { id: string; name: string; shortDescription: string }>();
  for (const f of result.findings) {
    if (!rulesMap.has(f.ruleId)) {
      rulesMap.set(f.ruleId, { id: f.ruleId, name: f.title, shortDescription: f.title });
    }
  }

  const rules = [...rulesMap.values()].map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.shortDescription },
  }));

  const results = result.findings.map((f) => {
    const region = f.location.line ? { startLine: f.location.line } : undefined;
    const uri = f.location.file ?? f.location.url ?? f.location.endpoint ?? 'unknown';
    return {
      ruleId: f.ruleId,
      level: toLevel(f.severity, f.status),
      message: { text: f.description },
      properties: {
        severity: f.severity,
        status: f.status,
        confidence: f.confidence,
        evidenceClass: f.evidenceClass,
        cwe: f.cwe,
        'security-severity': securitySeverity(f.severity),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            ...(region ? { region } : {}),
          },
        },
      ],
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'qa-engineering-platform',
            informationUri: 'https://example.invalid/qa-platform',
            version: '0.1.0',
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: result.releaseDecision.decision !== 'NO_GO',
            startTimeUtc: result.scan.startedAt,
            endTimeUtc: result.scan.completedAt ?? undefined,
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
