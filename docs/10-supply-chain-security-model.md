# 10 — Supply-Chain Security Model

> Spec ref: PART V.17 (dependency/supply-chain security), IX.1 (Supply-Chain Report), IV.2 (SBOM: CycloneDX/SPDX),
> V.30 (license/legal), and PART VIII (safe ingestion of untrusted source).
> This is a living design document (Phase 0 item #18). Every control described here exists in the repository
> today; anything not yet built is listed under **Deferred** rather than implied.

## 1. Scope & threat framing

The platform's own supply-chain exposure is two-sided:

1. **The code it *analyses*** is untrusted third-party source (uploaded, or cloned from a git URL). Ingesting it
   must not let that repository run code, exfiltrate data, or reach internal hosts (§3).
2. **The dependencies *declared inside* that code** are themselves a supply-chain risk to whoever ships it. The
   platform inventories them, reports pinning/lockfile hygiene, produces an SBOM, and is **honest** that offline
   vulnerability status is `NOT_TESTED` — never a false "clean" (§2).

The platform's *own* build dependencies (its npm workspaces) are governed by the same honesty rules and the
Testing Strategy (`docs/09`); this doc focuses on the two risks above.

## 2. Dependency inventory, SBOM & pinning (`DependencyScanner`, §V.17)

`packages/engines/src/dependency-scanner.ts` reads declared dependencies (e.g. `package.json`) and produces:

### 2.1 Findings (facts, feeding `SupplyChainHealth`)

| Rule | Meaning | Severity |
|---|---|---|
| `SUP-LOCK-001` | No dependency lockfile present — builds are not reproducible | Medium |
| `SUP-PIN-001` | A dependency version is unpinned / uses a wildcard (`*`, ranges) | Medium |
| `SUP-VULN-000` | Vulnerability scan **not performed** (offline: no CVE/OSV database) | Informational |

`SUP-VULN-000` is the non-negotiable in action: with no vulnerability database reachable, the platform reports
the status as `NOT_TESTED`, **not** `PASS`. A missing scan is a disclosed limitation, never an implied clean bill
of health (PART XIII; §XII.2 "absence of findings is not evidence of absence").

### 2.2 SBOM (§IV.2)

The scanner emits a **CycloneDX 1.5** SBOM (`format: 'CycloneDX'`, `specVersion: '1.5'`) carried on
`EngineResult.sbom → ScanResult.sbom`, validated by the Zod contract, and exportable via
`?format=cyclonedx` (API/web) or `sbom.cdx.json` (CLI). Each component lists name, version, scope, and an
explicit `vulnerabilityStatus` — which is `NOT_TESTED` offline, surfaced prominently in the web SBOM panel so a
reader is never misled into thinking the components were vetted.

## 3. Safe ingestion of untrusted source (`prepareSource` / `cloneRepo`, PART VIII)

`packages/orchestrator/src/ingest.ts` resolves a scan target that is either a local directory or a git URL.
Remote targets are the higher-risk path and are handled defensively:

- **No command injection.** The URL is passed to `git` as an *argument* via `spawn` with an argument array and
  `shell: false` (`['clone', '--depth', '1', '--single-branch', '--no-tags', '--', url, destDir]`). It is never
  interpolated into a shell string.
- **No code execution from the repo.** The clone is shallow (`--depth 1 --single-branch --no-tags`),
  non-interactive (`GIT_TERMINAL_PROMPT=0`), and time-bounded (default 120 s). Nothing in the working tree is
  executed and **submodules are not initialised** — analysis is purely static file reads.
- **SSRF mitigation (`assertAllowedRemote`, the policy for untrusted API callers).** It permits **HTTPS only**,
  rejects URLs with **embedded credentials**, and best-effort **blocks loopback / private / link-local hosts** —
  including the cloud metadata address `169.254.169.254`. This is explicitly documented as *best-effort* because
  DNS can still resolve a public name to a private address; a network-egress policy is the defence-in-depth
  complement (see Deferred).
- **Cleanup.** The temp clone directory is removed in a `finally` block after the scan, whether it succeeds or
  fails — verified end-to-end (0 leaked temp dirs) in `tests/ingest.test.ts` and `tests/jobs.test.ts`.

The API's `POST /projects/:id/scans` applies this policy before enqueue: a local path goes through the
allowed-roots guard, a remote URL through `assertAllowedRemote` (→ `400 forbidden_source` on violation). The
distributed worker enforces the same policy by default (`enforceRemotePolicy: true`).

## 4. License / legal hygiene (`LicenseScanner`, §V.30)

`packages/engines/src/license-scanner.ts` inspects declared license metadata and reports **facts only** — it
draws no legal conclusions and never asserts license compatibility (spec V.30):

| Rule | Meaning | Severity |
|---|---|---|
| `LIC-MISSING-001` | No `license` field declared | Informational |
| `LIC-NONSTANDARD-001` | Deprecated object/array form, or a non-SPDX identifier | Low / Info |
| `LIC-UNLICENSED-NOT-PRIVATE-001` | `UNLICENSED` without `private: true` (publishable by accident) | Low |
| `LIC-COPYLEFT-DECLARED-001` | A strong-copyleft GPL/AGPL license is declared | Informational |

Valid SPDX expressions (e.g. `(MIT OR Apache-2.0)`) and `private + UNLICENSED` produce nothing. Feeds
`SupplyChainHealth`.

## 5. Integrity of the platform's own audit trail (cross-reference)

Supply-chain trust also depends on the record of *what the platform did* being tamper-evident. That is provided by
the hash-chained audit log (`packages/jobs/src/audit.ts` + the durable `PostgresAuditStore`), described in
`docs/06`: append-only, each event's hash covers the previous, and `verify()` detects any mutation/deletion.
Production revokes UPDATE/DELETE on the `audit_event` table so the chain cannot be silently rewritten.

## 6. How this maps to standard frameworks

- **CycloneDX 1.5** — the SBOM format emitted (§2.2); referenced on findings as `{ framework: 'CycloneDX', id: 'SBOM' }`.
- **OWASP Top 10 2025 A06** — Vulnerable and Outdated Components — the dependency findings carry this standard tag.
- **SLSA (provenance)** — *aspirational*; see Deferred. The lockfile/pinning checks (§2.1) are prerequisites for
  reproducible builds but do not by themselves establish SLSA provenance.

## 7. Deferred (not yet built — stated, not implied)

- **Live vulnerability scanning** (CVE/OSV/GHSA lookup) — requires network access to a vulnerability database;
  until then `SUP-VULN-000` keeps the status honestly `NOT_TESTED`.
- **Transitive dependency resolution** — the current inventory reads *declared* dependencies; full transitive
  graph resolution (lockfile parsing across ecosystems) is future work.
- **Signature / provenance verification** (Sigstore/cosign, SLSA attestations, npm package signatures).
- **Network-egress sandboxing** for the clone/analysis step (defence-in-depth beyond `assertAllowedRemote`'s
  host checks) — belongs with the execution sandbox (§VIII.5), which is gated on the Definition of Ready.
- **Private-repo authentication** for ingestion (currently public HTTPS only, by policy).
