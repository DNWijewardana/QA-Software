// FIXTURE — intentionally poor error handling for the golden corpus (spec X.3). NOT for real use.

function a() {
  // SEEDED: empty catch swallows the error (ERR-EMPTY-CATCH-001)
  try { risky(); } catch (e) {}
}

function b() {
  // SEEDED: catch only logs to console, does not handle/rethrow (ERR-CATCH-CONSOLE-001)
  try { risky(); } catch (e) { console.log(e); }
}

function handler(err, req, res) {
  // SEEDED: stack trace sent to the client (ERR-STACK-EXPOSED-001, CWE-209)
  res.status(500).send(err.stack);
}

function c() {
  // SEEDED: throwing a string instead of an Error (ERR-THROW-LITERAL-001)
  throw "boom";
}

module.exports = { a, b, handler, c };
