# Golden Test Corpus (fixtures)

> Spec ref: §X.2 / §X.3 — "Create intentionally vulnerable toy projects as fixtures; the platform must
> correctly detect known seeded defects." Detection effectiveness is measured against these (§X.4).

⚠️ **These projects are intentionally insecure and imperfect. They are NOT real applications and must never
be deployed or copied into real code.** Secret-looking values are well-known public documentation examples,
not live credentials.

## `vulnerable-sample/`

Seeded defects (each maps to a rule the platform must detect):

| Seeded defect | Location | Expected rule | Severity |
|---|---|---|---|
| Hardcoded AWS access key | `src/config.js` | `SEC-SECRET-001` | Critical |
| Hardcoded credential assignment (`dbPassword`) | `src/config.js` | `SEC-SECRET-001` | High |
| Use of `var` (×2) | `src/config.js`, `src/app.js` | `MNT-VAR-001` | Low |
| TODO / tech-debt markers (×2) | `src/app.js` | `MNT-TODO-001` | Informational |
| Missing dependency lockfile | `package.json` | `SUP-LOCK-001` | Medium |
| Unpinned/wildcard dependency (`left-pad: "*"`) | `package.json` | `SUP-PIN-001` | Medium |
| Dependency vuln scan not performed (offline) | `package.json` | `SUP-VULN-000` | Informational (NOT_TESTED) |

The dogfooding test `tests/dogfood.test.ts` scans this fixture and asserts the seeded defects are found,
the output validates against the canonical contract, and **no raw secret value leaks into any evidence file**.

## Adding fixtures

Each new engine (Phase 2+) ships with a fixture that seeds the defect it detects, so detection precision/recall
can be benchmarked and regressions in detection quality fail the build (§X.4).
