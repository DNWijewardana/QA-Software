// FIXTURE — intentionally contains PII for the golden corpus (spec X.3). NOT real data.
// The card number is a well-known Luhn-valid test value; the SSN/email are fabricated.

const customer = {
  name: "John Doe",
  // SEEDED: Luhn-valid credit-card number in source (PRIV-PII-CARD-001, CWE-312)
  card: "4111111111111111",
  // SEEDED: SSN in source (PRIV-PII-SSN-001, CWE-359)
  ssn: "123-45-6789",
  // SEEDED: personal email in source (PRIV-PII-EMAIL-001)
  email: "john.doe@gmail.com",
};

module.exports = { customer };
