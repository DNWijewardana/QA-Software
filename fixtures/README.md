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

## `insecure-docker/`

An intentionally-insecure `Dockerfile` for the `DockerfileScanner` (spec V.18, CIS Docker Benchmark):

| Seeded defect | Expected rule | Severity |
|---|---|---|
| Unpinned base image (`node:latest`) | `IAC-DOCKER-TAG-001` | Medium |
| Container runs as root (no `USER`) | `IAC-DOCKER-USER-001` | High |
| Remote script piped to shell (`curl … \| sh`) | `IAC-DOCKER-CURLBASH-001` | High |
| `ADD` fetches a remote URL | `IAC-DOCKER-ADD-001` | Medium |
| Hardcoded secret in `ENV` | `IAC-DOCKER-SECRET-001` | High |
| `apt install` without cache cleanup | `IAC-DOCKER-APTCLEAN-001` | Low |
| No `HEALTHCHECK` | `IAC-DOCKER-HEALTHCHECK-000` | Informational |

`tests/dockerfile.test.ts` asserts each rule fires, the `CloudIaCPosture` dimension is scored, and the
seeded secret never leaks into evidence (it is captured but redacted).

## Adding fixtures

Each new engine (Phase 2+) ships with a fixture that seeds the defect it detects, so detection precision/recall
can be benchmarked and regressions in detection quality fail the build (§X.4).
