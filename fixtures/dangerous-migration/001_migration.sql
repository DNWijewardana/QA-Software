-- FIXTURE — intentionally dangerous SQL migration for the golden corpus (spec X.3). NOT for real use.

-- SEEDED: DROP TABLE (SQL-DROP-TABLE-001)
DROP TABLE users;

-- SEEDED: DROP COLUMN (SQL-DROP-COLUMN-001)
ALTER TABLE accounts DROP COLUMN legacy_flag;

-- SEEDED: TRUNCATE (SQL-TRUNCATE-001)
TRUNCATE audit_log;

-- SEEDED: DELETE without WHERE (SQL-DELETE-NO-WHERE-001)
DELETE FROM sessions;

-- SEEDED: UPDATE without WHERE (SQL-UPDATE-NO-WHERE-001)
UPDATE orders SET status = 'archived';

-- SEEDED: ADD COLUMN NOT NULL without DEFAULT (SQL-NOTNULL-NO-DEFAULT-001)
ALTER TABLE customers ADD COLUMN country TEXT NOT NULL;

-- SAFE statements below — these must NOT be flagged:
DELETE FROM sessions WHERE expired = true;
UPDATE orders SET status = 'x' WHERE id = 1;
ALTER TABLE customers ADD COLUMN note TEXT;
ALTER TABLE customers ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;
