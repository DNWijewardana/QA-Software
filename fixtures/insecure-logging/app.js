// FIXTURE — intentionally leaky logging for the golden corpus (spec X.3). NOT for real use.

function handler(req, res) {
  // SEEDED: sensitive data written to logs (OBS-LOG-SENSITIVE-001, CWE-532)
  console.log("login attempt, password=" + req.body.password);

  // SEEDED: logging a whole request object (OBS-LOG-PII-OBJECT-001)
  console.log(req.body);

  // SEEDED: sensitive token logged via a logger (OBS-LOG-SENSITIVE-001)
  logger.error("auth failed for token " + req.headers.authorization);

  // (console.* usage above also triggers OBS-LOG-CONSOLE-001)
  res.end("ok");
}

module.exports = { handler };
