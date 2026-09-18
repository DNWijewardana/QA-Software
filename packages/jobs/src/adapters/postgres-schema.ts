/**
 * PostgreSQL schema for the scan/job store (§VI.8, doc 03).
 *
 * The scan record is stored in one table. The heavy `result` JSON (the full canonical ScanResult) is
 * kept in a JSONB column here for the delivery layer; a later normalization pass can explode findings
 * into their own table with the CHECK-constraint invariants from doc 03. Progress + state are first-class
 * columns so status endpoints never need to parse the result blob.
 */

export const SCAN_TABLE_DDL = `
CREATE TABLE IF NOT EXISTS scan_job (
  scan_id       TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL DEFAULT 'default',
  project_id    TEXT NOT NULL,
  state         TEXT NOT NULL,
  stage         TEXT NOT NULL,
  completed_stages INTEGER NOT NULL DEFAULT 0,
  total_stages  INTEGER NOT NULL DEFAULT 6,
  pct           INTEGER NOT NULL DEFAULT 0,
  result        JSONB,
  error         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- INVARIANT (doc 03 / §I.4): a COMPLETED job must carry a result; a FAILED job must carry an error.
  CONSTRAINT completed_has_result CHECK (state <> 'COMPLETED' OR result IS NOT NULL),
  CONSTRAINT failed_has_error     CHECK (state <> 'FAILED' OR error IS NOT NULL),
  CONSTRAINT pct_in_range         CHECK (pct BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS scan_job_project_idx ON scan_job (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_job_org_idx ON scan_job (org_id, created_at DESC);
`;
