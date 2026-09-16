# 03 — Data Model

> Spec ref: PART VI.8 (Storage), PART VII.1 (Finding schema), I.4 (vocabularies & invariants), VII.8 (guardrails).

## 1. Design principle: invariants live in the schema, not in code comments

The spec's critical guarantees (`NOT TESTED` ↛ `PASS`; scores cannot hide Critical findings) are **enforced
by the database**, not by convention (spec I.4, VII.8). Where PostgreSQL can express a rule as a CHECK
constraint, a foreign key, or a trigger, it does — so no application bug can violate it.

## 2. Enumerations (single source of truth = `packages/core`)

- **EvidenceClass:** `AUTOMATICALLY_VERIFIED · AUTOMATICALLY_DETECTED · INFERRED · SUSPECTED ·
  MANUALLY_REQUIRED · NOT_APPLICABLE · UNABLE_TO_TEST · INSUFFICIENT_EVIDENCE`
- **Status:** `PASS · FAIL · WARNING · NOT_TESTED · NOT_APPLICABLE · BLOCKED · INSUFFICIENT_EVIDENCE`
- **Confidence:** `Confirmed · Highly likely · Likely · Possible · Informational · Needs human verification`
- **Severity/Risk:** `Critical · High · Medium · Low · Informational`
- **Reproducibility:** `Always · Often · Sometimes · Rarely · Unknown`
- **ExecutionMode:** `SAFE_STATIC · SAFE_DYNAMIC · AUTHORIZED_SECURITY · DESTRUCTIVE · PRODUCTION`
- **JobState:** `QUEUED · PREPARING · PROFILING · STATIC_ANALYSIS · TESTING · SECURITY · PERFORMANCE ·
  AGGREGATING · REPORTING · COMPLETED · FAILED · CANCELLED · TIMEOUT · PARTIAL`

## 3. Core entities (spec VI.8)

```
Organization 1───* User            (RBAC role per membership)
Organization 1───* Project
Project      1───* Repository / Environment
Project      1───* Scan
Scan         1───1 Job              (async execution + manifest)
Scan         1───* Finding
Finding      1───* Evidence
Finding      *───* Requirement      (traceability, VII.13)
Finding      *───* TestCase         (traceability)
Scan         1───* DimensionScore
Scan         1───1 ReleaseDecision
Project      1───* Suppression      (scoped, expiring, auditable — VII.17)
Project      1───* Baseline         (diff/trend — VII.10)
Organization 1───* AuditEvent       (append-only, hash-chained — VIII.7)
Scan         1───* ManualReviewItem (subjective/human-required — IX.5)
```

Also stored (VI.8): policies, quality scores, SBOMs, compliance-control mappings, manual-review records.
Evidence **blobs** live in object storage; the `Evidence` row holds metadata + a storage ref + redaction flag.

## 4. Key tables (illustrative DDL — enforced invariants highlighted)

```sql
CREATE TYPE status AS ENUM ('PASS','FAIL','WARNING','NOT_TESTED','NOT_APPLICABLE','BLOCKED','INSUFFICIENT_EVIDENCE');
CREATE TYPE evidence_class AS ENUM ('AUTOMATICALLY_VERIFIED','AUTOMATICALLY_DETECTED','INFERRED','SUSPECTED',
  'MANUALLY_REQUIRED','NOT_APPLICABLE','UNABLE_TO_TEST','INSUFFICIENT_EVIDENCE');
CREATE TYPE severity AS ENUM ('Critical','High','Medium','Low','Informational');

CREATE TABLE finding (
  id                 TEXT PRIMARY KEY,                 -- e.g. SEC-AUTH-001-0007
  scan_id            UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  rule_id            TEXT NOT NULL,
  category           TEXT NOT NULL,
  subcategory        TEXT,
  title              TEXT NOT NULL,
  description        TEXT NOT NULL,
  status             status NOT NULL,
  evidence_class     evidence_class NOT NULL,
  severity           severity NOT NULL,
  risk               severity NOT NULL,
  confidence         TEXT NOT NULL,
  reproducibility    TEXT NOT NULL DEFAULT 'Unknown',
  cwe                TEXT[] NOT NULL DEFAULT '{}',
  cve                TEXT[] NOT NULL DEFAULT '{}',
  cvss_vector        TEXT,  cvss_score NUMERIC, cvss_version TEXT,
  epss               NUMERIC, kev BOOLEAN NOT NULL DEFAULT FALSE,
  affected_component TEXT,
  location_file      TEXT, location_url TEXT, location_endpoint TEXT, location_line INT,
  detection_method   TEXT NOT NULL,      -- static|dynamic|dependency|config|ai-assisted|manual
  tool_used          TEXT,
  remediation        JSONB,
  verification_method TEXT,
  root_cause         JSONB,
  owner              TEXT, target_fix_date DATE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- INVARIANT 1 (spec I.4): a PASS may never rest on "no evidence".
  CONSTRAINT pass_needs_evidence CHECK (
    status <> 'PASS' OR evidence_class IN
      ('AUTOMATICALLY_VERIFIED','AUTOMATICALLY_DETECTED')
  ),
  -- INVARIANT 2: NOT_TESTED must not masquerade as a verified class.
  CONSTRAINT not_tested_is_honest CHECK (
    status <> 'NOT_TESTED' OR evidence_class IN
      ('UNABLE_TO_TEST','INSUFFICIENT_EVIDENCE','MANUALLY_REQUIRED','NOT_APPLICABLE')
  ),
  -- INVARIANT 3 (spec VII.2): a "confirmed" confidence requires at least one evidence row (enforced by trigger).
);

-- Trigger enforces: confidence='Confirmed' OR severity in (Critical,High) with status=FAIL ⇒ ≥1 evidence row.
```

`DimensionScore` rows are immutable per scan and always carry `coverage`, `confidence`, `weight`, `why[]`,
`unknowns[]` (spec VII.6) — a score row with empty `why` is rejected.

## 5. Suppressions (spec VII.17)

`Suppression(scope, rule_id|path|dependency, reason, created_by, created_at, expires_at)`.
No row may have a null/empty `reason` or a null `expires_at` beyond a configurable max (no permanent global
ignore). A suppression **hides a finding from gates but never deletes it** — the finding remains, tagged suppressed.

## 6. Audit log (spec VIII.7)

`AuditEvent(id, org_id, actor, action, target, payload_hash, prev_hash, hash, created_at)` — append-only,
each row's `hash = H(prev_hash || row)`, making tampering detectable (hash chain). No updates or deletes allowed.

## 7. Retention (spec VIII.9, VI.8)

Evidence artifacts and uploaded source get lifecycle policies (TTL) — sensitive artifacts are **not** retained
forever; secure deletion on expiry. Uploaded source is treated as untrusted and encrypted at rest.
