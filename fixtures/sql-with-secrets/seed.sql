-- FIXTURE — intentionally contains a secret + PII in SQL seed data (spec X.3). NOT real data.
-- INSERTs are used so this file exercises the secret/PII engines, not the migration-safety engine.

-- SEEDED: hardcoded AWS access key (SEC-SECRET-001)
INSERT INTO app_secrets (name, value) VALUES ('aws', 'AKIAIOSFODNN7EXAMPLE');

-- SEEDED: personal email (PRIV-PII-EMAIL-001) and Luhn-valid card (PRIV-PII-CARD-001)
INSERT INTO customers (email, card) VALUES ('john.doe@gmail.com', '4111111111111111');
