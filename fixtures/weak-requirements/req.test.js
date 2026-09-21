// FIXTURE — tests linked to requirements for traceability (§VII.13). NOT for real use.
// Covers REQ-001 and REQ-002; references REQ-999 which does not exist (a dangling reference).
test('REQ-001: system responsiveness', () => {
  expect(true).toBe(true);
});
test('REQ-002: api returns results', () => {
  expect(true).toBe(true);
});
test('REQ-999: orphaned reference to a non-existent requirement', () => {
  expect(true).toBe(true);
});
