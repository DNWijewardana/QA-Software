// FIXTURE — intentionally insecure. Seeded defects for the golden corpus (spec X.3).
// Do NOT copy into real code. Secret values below are well-known AWS documentation examples.

// SEEDED DEFECT: hardcoded AWS access key id (SEC-SECRET-001, CWE-798)
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

// SEEDED DEFECT: hardcoded generic credential assignment (SEC-SECRET-001, CWE-798)
const dbPassword = "SuperSecretP@ssw0rd123";

// SEEDED DEFECT: use of var (MNT-VAR-001)
var region = "us-east-1";

module.exports = { AWS_ACCESS_KEY_ID, dbPassword, region };
