// FIXTURE — intentionally imperfect. Seeded maintainability defects for the golden corpus.

const { AWS_ACCESS_KEY_ID } = require("./config");

// SEEDED DEFECT: TODO marker (MNT-TODO-001)
// TODO: add authentication before exposing this handler

function handler(req, res) {
  // SEEDED DEFECT: use of var (MNT-VAR-001)
  var user = req.query.user;
  res.end("hello " + user + " key=" + AWS_ACCESS_KEY_ID);
}

module.exports = { handler };
