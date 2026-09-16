# 04 — Evidence Model

> Spec ref: PART VII.2 (evidence-first), VII.1 (finding record), VIII.9/VIII.10 (artifacts, redaction), I.4.

## 1. Principle: evidence or silence (spec §0.2.1)

No fact is asserted without linkable evidence. If evidence is missing, the result is
`INSUFFICIENT EVIDENCE` — never upgraded to a pass. A **serious finding without evidence can never be
`Confirmed`** (spec VII.2, XII.2).

## 2. Evidence types (spec VII.2)

`source-code` · `test-output` · `http-request/response` · `screenshot` · `browser-trace` ·
`console/network-error` · `performance-measurement` · `dependency-record` · `configuration` · `log` ·
`stack-trace`.

## 3. Evidence artifact structure

```
EvidenceArtifact {
  id: string                 // stable, referenced by findings
  type: EvidenceType
  storageRef: string         // object-storage key (blob lives outside the DB)
  contentHash: string        // integrity: sha256 of the (redacted) artifact
  redacted: boolean          // true if secrets/PII were masked before storage
  redactionMap?: {...}       // WHAT class of value was redacted (never the value itself)
  capturedAt: ISO-8601
  capturedBy: string         // engine + tool@version
  manifestRef: string        // links to the execution manifest that produced it
}
```

The `Finding.evidence[]` holds **references** (`{type, ref, redacted}`), not inline blobs — keeping the
canonical JSON contract (IX.4) small and the heavy artifacts in object storage.

## 4. Redaction is mandatory and happens BEFORE storage (spec VIII.10, Rule 11)

- Secret/PII detection runs on every artifact **before** it is persisted or shown.
- Detected secrets (API keys, tokens, passwords, private keys, cloud/DB creds) and PII are replaced with a
  typed placeholder, e.g. `«REDACTED:aws-access-key»`. The **raw value is never written to disk or to any report.**
- The redaction map records *what class* was removed and *where*, never the value — so reviewers know a
  secret was present without re-exposing it.
- This applies uniformly across findings, logs, HTTP request/response pairs, and traces.

## 5. Reproducibility: the execution manifest (spec VIII.6, §0.2.6)

Every scan emits a manifest so results are re-derivable:

```
ExecutionManifest {
  scanId, projectVersion, commit?, environment, mode,
  os, runtimeVersions{ node, ... }, packageVersions{...},
  engineVersions{ engineName: version, ... },
  rulesetVersion, config, configHash, startedAt, completedAt
}
```

Every `EvidenceArtifact` links to the manifest that produced it. Two runs with the same manifest against the
same input must yield the same findings (determinism, §0.2.2).

## 6. Evidence → Finding → verification chain (spec §0.2.7 traceability)

```
Requirement → Rule/Control → Test/Scan → EvidenceArtifact → Finding → Remediation → VerificationMethod
```

Each finding links **back** to a requirement/rule/standard and **forward** to a remediation + a concrete
verification method (e.g., "add boundary test quantity=0; expect 400"). This makes every finding auditable
and every fix checkable.

## 7. Evidence lifecycle (spec VIII.9)

Artifacts get TTL-based lifecycle policies; sensitive artifacts are securely deleted on expiry and never
retained indefinitely. Deletion is itself an audited event.
